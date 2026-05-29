import os, json, hmac, hashlib, uuid, sqlite3
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from api.auth import (create_token, get_current_tenant, require_domain,
                      require_admin, hash_password, verify_password)

def utcnow():
    return datetime.now(timezone.utc).isoformat()

BASE        = os.environ.get("NEXUS_BASE", ".")
DOMAINS_DIR = os.path.join(BASE, "domains")
SECRET      = os.environ.get("NEXUS_SECRET", "nexus-dev-secret-uniform-2026")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = bool(DATABASE_URL)

if USE_PG:
    import psycopg2, psycopg2.extras
    print("DB: PostgreSQL")
else:
    print("DB: SQLite (fallback)")

class DomainRegistry:
    def __init__(self):
        self.domains     = {}
        self.connections = {}
        self._load_all()

    def _load_all(self):
        if not os.path.exists(DOMAINS_DIR):
            return
        for name in os.listdir(DOMAINS_DIR):
            cfg_path = os.path.join(DOMAINS_DIR, name, "config.json")
            if os.path.exists(cfg_path):
                with open(cfg_path) as f:
                    self.domains[name] = json.load(f)

    def get(self, domain_id):
        if domain_id not in self.domains:
            raise HTTPException(404, f"Domeniu necunoscut: {domain_id}")
        return self.domains[domain_id]

    def get_db(self, domain_id):
        self.get(domain_id)
        if domain_id not in self.connections:
            if USE_PG:
                conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
                conn.autocommit = True
                self.connections[domain_id] = ("pg", conn)
            else:
                db_path = os.path.join(DOMAINS_DIR, domain_id, f"{domain_id}.db")
                if not os.path.exists(db_path):
                    raise HTTPException(404, f"DB inexistenta: {domain_id}")
                conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.row_factory = sqlite3.Row
                self.connections[domain_id] = ("sqlite", conn)
        return self.connections[domain_id]

    def query(self, domain_id, sql, params=()):
        db_type, conn = self.get_db(domain_id)
        if db_type == "pg":
            sql_pg = sql.replace("?", "%s")
            cur = conn.cursor()
            cur.execute(sql_pg, params)
            try:    return [dict(r) for r in cur.fetchall()]
            except: return []
        else:
            cur = conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def query_one(self, domain_id, sql, params=()):
        rows = self.query(domain_id, sql, params)
        return rows[0] if rows else None

    def owner_key(self, domain_id):
        return self.domains.get(domain_id, {}).get("owner_key", "tenant_id")

    def init_pg_tables(self):
        if not USE_PG:
            return
        _, conn = list(self.connections.values())[0] if self.connections else (None, None)
        if not conn:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
        cur = conn.cursor()
        # Users table (global)
        cur.execute("""CREATE TABLE IF NOT EXISTS nexus_users (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            domain_id TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            active BOOLEAN DEFAULT TRUE,
            created_at TEXT
        )""")
        for domain_id in self.domains:
            tabel = domain_id + "_comenzi"
            cur.execute(f"""CREATE TABLE IF NOT EXISTS {tabel} (
                id TEXT PRIMARY KEY,
                domain_id TEXT,
                tenant_id TEXT,
                data TEXT,
                hash TEXT,
                status TEXT,
                valoare REAL DEFAULT 0,
                urgent INTEGER DEFAULT 0,
                created_at TEXT,
                updated_at TEXT
            )""")
            cur.execute(f"""CREATE TABLE IF NOT EXISTS {domain_id}_audit_log (
                id TEXT PRIMARY KEY,
                domain_id TEXT,
                comanda_id TEXT,
                action TEXT,
                tenant_id TEXT,
                timestamp TEXT,
                details TEXT
            )""")
            cur.execute(f"""CREATE TABLE IF NOT EXISTS {domain_id}_tenanti (
                tenant_id TEXT PRIMARY KEY,
                domain_id TEXT,
                status TEXT DEFAULT 'active',
                created_at TEXT
            )""")
            print(f"OK: PG tables {domain_id}")
        # Seed admin
        cur.execute("SELECT id FROM nexus_users WHERE tenant_id='admin' AND domain_id='admin'")
        if not cur.fetchone():
            from api.auth import hash_password as hp
            cur.execute(
                "INSERT INTO nexus_users VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (uuid.uuid4().hex, "admin", "admin",
                 hp(os.environ.get("ADMIN_PASSWORD", "nexus-admin-2026")),
                 "admin", True, utcnow())
            )
            print("OK: admin user seeded")

registry = DomainRegistry()

def detecteaza_tabel(domain_id):
    if USE_PG:
        return domain_id + "_comenzi"
    db_type, conn = registry.get_db(domain_id)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT IN ('audit_log','tenanti','linii_comanda','aprobari','facturi')"
    ).fetchall()
    return tables[0]["name"] if tables else "comenzi"

def safe_get(row, key, default=None):
    try:    return row[key]
    except: return default

def verifica_integritate(domain_id, row):
    try:
        data_str  = row["data"] if isinstance(row["data"], str) else json.dumps(row["data"])
        data_obj  = json.loads(data_str)
        nonce     = data_obj.get("_nonce", "")
        timestamp = data_obj.get("_timestamp", "")
        valoare   = safe_get(row, "valoare", 0) or 0
        owner_key = registry.owner_key(domain_id)
        owner_id  = safe_get(row, owner_key, "")
        pd = {"comanda_id": row["id"], owner_key: owner_id,
              "data": data_str, "timestamp": timestamp,
              "nonce": nonce, "valoare": valoare}
        canonical = json.dumps(pd, ensure_ascii=True, sort_keys=True, separators=(",",":"))
        expected  = hmac.new(SECRET.encode(), (row["id"] + canonical).encode(), hashlib.sha256).hexdigest()
        stored    = row.get("hash", "") if isinstance(row, dict) else safe_get(row, "hash", "")
        return hmac.compare_digest(expected, stored)
    except:
        return False

app = FastAPI(title="Nexus Platform API", version="1.1.0")
app.add_middleware(CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*", "Authorization"])

@app.on_event("startup")
def startup():
    if USE_PG:
        registry.init_pg_tables()

# ── AUTH ENDPOINTS ───────────────────────────────────────

@app.post("/auth/login")
def login(body: dict):
    tenant_id = body.get("tenant_id", "")
    domain_id = body.get("domain_id", "")
    password  = body.get("password", "")
    if not tenant_id or not domain_id or not password:
        raise HTTPException(400, "tenant_id, domain_id, password obligatorii")
    if USE_PG:
        _, conn = registry.get_db(list(registry.domains.keys())[0])
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM nexus_users WHERE tenant_id=%s AND domain_id=%s AND active=TRUE",
            (tenant_id, domain_id)
        )
        user = cur.fetchone()
    else:
        raise HTTPException(503, "Auth doar cu PostgreSQL")
    if not user:
        raise HTTPException(401, "Tenant inexistent sau inactiv")
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(401, "Parola incorecta")
    token = create_token({"tenant_id": tenant_id, "domain_id": domain_id, "role": user["role"]})
    return {"access_token": token, "token_type": "bearer",
            "tenant_id": tenant_id, "domain_id": domain_id, "role": user["role"]}

@app.post("/auth/register")
def register(body: dict, current: dict = Depends(get_current_tenant)):
    require_admin(current)
    tenant_id = body.get("tenant_id", "")
    domain_id = body.get("domain_id", "")
    password  = body.get("password", "")
    role      = body.get("role", "user")
    if not tenant_id or not domain_id or not password:
        raise HTTPException(400, "tenant_id, domain_id, password obligatorii")
    if USE_PG:
        _, conn = registry.get_db(list(registry.domains.keys())[0])
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO nexus_users VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (uuid.uuid4().hex, tenant_id, domain_id,
             hash_password(password), role, True, utcnow())
        )
    return {"ok": True, "tenant_id": tenant_id, "domain_id": domain_id, "role": role}

@app.get("/auth/me")
def me(current: dict = Depends(get_current_tenant)):
    return current

# ── PUBLIC ENDPOINTS ─────────────────────────────────────

@app.get("/")
def root():
    return {"platform": "Nexus Platform", "version": "1.1.0",
            "domenii": list(registry.domains.keys()),
            "db": "postgresql" if USE_PG else "sqlite",
            "status": "operational", "timestamp": utcnow()}

@app.get("/health")
def health():
    status = {}
    for domain_id in registry.domains:
        try:
            tabel = detecteaza_tabel(domain_id)
            row   = registry.query_one(domain_id, f"SELECT COUNT(*) as nr FROM {tabel}")
            status[domain_id] = {"status": "ok", "entitati": row["nr"] if row else 0}
        except Exception as e:
            status[domain_id] = {"status": "error", "detail": str(e)}
    return {"platform": "Nexus", "version": "1.1.0",
            "db": "postgresql" if USE_PG else "sqlite",
            "domenii": status, "timestamp": utcnow()}

@app.get("/api/domains")
def list_domains():
    result = []
    for domain_id, cfg in registry.domains.items():
        try:
            tabel = detecteaza_tabel(domain_id)
            row   = registry.query_one(domain_id, f"SELECT COUNT(*) as nr FROM {tabel}")
            nr    = row["nr"] if row else 0
            result.append({"domain_id": domain_id,
                "display_name": cfg.get("display_name", domain_id),
                "description":  cfg.get("description", ""),
                "color_primary":cfg.get("color_primary", "#6366f1"),
                "logo_letter":  cfg.get("logo_letter", domain_id[0].upper()),
                "entitati": nr, "tenants": len(cfg.get("tenants", []))})
        except:
            result.append({"domain_id": domain_id, "status": "error"})
    return {"domenii": result, "total": len(result)}

@app.get("/api/domains/{domain_id}/config")
def get_config(domain_id: str):
    return registry.get(domain_id)

# ── PROTECTED ENDPOINTS ──────────────────────────────────

@app.get("/api/domains/{domain_id}/tenants")
def get_tenants(domain_id: str, current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    try:
        tabel = domain_id + "_tenanti" if USE_PG else "tenanti"
        rows  = registry.query(domain_id, f"SELECT * FROM {tabel} ORDER BY tenant_id")
        return {"tenanti": rows, "total": len(rows)}
    except:
        cfg = registry.get(domain_id)
        return {"tenanti": cfg.get("tenants", []), "total": len(cfg.get("tenants", []))}

@app.get("/api/domains/{domain_id}/entities")
def get_entities(domain_id: str, tenant_id: Optional[str]=None,
                 status: Optional[str]=None, urgent: Optional[bool]=None,
                 limit: int=Query(50,ge=1,le=200), offset: int=Query(0,ge=0),
                 current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    if current["role"] != "admin" and not tenant_id:
        tenant_id = current["tenant_id"]
    tabel     = detecteaza_tabel(domain_id)
    owner_key = registry.owner_key(domain_id)
    query  = f"SELECT * FROM {tabel} WHERE 1=1"
    params = []
    if tenant_id:
        query += f" AND ({owner_key}=? OR furnizor=?)"
        params += [tenant_id, tenant_id]
    if status:
        query += " AND status=?"
        params.append(status)
    if urgent is not None:
        query += " AND urgent=?"
        params.append(1 if urgent else 0)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = registry.query(domain_id, query, params)
    result = []
    for r in rows:
        r["integritate"] = "OK" if verifica_integritate(domain_id, r) else "COMPROMIS"
        try:
            if isinstance(r.get("data"), str):
                r["data"] = json.loads(r["data"])
        except: pass
        result.append(r)
    return {"domain_id": domain_id, "entitati": result,
            "total": len(result), "limit": limit, "offset": offset}

@app.get("/api/domains/{domain_id}/entities/{entity_id}")
def get_entity(domain_id: str, entity_id: str, current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    tabel = detecteaza_tabel(domain_id)
    row   = registry.query_one(domain_id, f"SELECT * FROM {tabel} WHERE id=?", (entity_id,))
    if not row: raise HTTPException(404, f"Entitate {entity_id} negasita")
    row["integritate"] = "OK" if verifica_integritate(domain_id, row) else "COMPROMIS"
    try:
        if isinstance(row.get("data"), str):
            row["data"] = json.loads(row["data"])
    except: pass
    try:
        tabel_linii = domain_id + "_linii_comanda" if USE_PG else "linii_comanda"
        row["linii"] = registry.query(domain_id, f"SELECT * FROM {tabel_linii} WHERE comanda_id=?", (entity_id,))
    except: row["linii"] = []
    return row

@app.get("/api/domains/{domain_id}/audit")
def get_audit(domain_id: str, entity_id: Optional[str]=None,
              limit: int=Query(50,ge=1,le=200), current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    tabel = domain_id + "_audit_log" if USE_PG else "audit_log"
    if entity_id:
        rows = registry.query(domain_id, f"SELECT * FROM {tabel} WHERE comanda_id=? ORDER BY timestamp DESC LIMIT ?", (entity_id, limit))
    else:
        rows = registry.query(domain_id, f"SELECT * FROM {tabel} ORDER BY timestamp DESC LIMIT ?", (limit,))
    return {"audit": rows, "total": len(rows)}

@app.get("/api/domains/{domain_id}/stats")
def get_stats(domain_id: str, current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    tabel = detecteaza_tabel(domain_id)
    cfg   = registry.get(domain_id)
    nr_total  = (registry.query_one(domain_id, f"SELECT COUNT(*) as nr FROM {tabel}") or {}).get("nr", 0)
    val_total = (registry.query_one(domain_id, f"SELECT SUM(valoare) as s FROM {tabel}") or {}).get("s", 0) or 0
    try:    nr_urgent = (registry.query_one(domain_id, f"SELECT COUNT(*) as nr FROM {tabel} WHERE urgent=1") or {}).get("nr", 0)
    except: nr_urgent = 0
    tabel_audit = domain_id + "_audit_log" if USE_PG else "audit_log"
    nr_audit = (registry.query_one(domain_id, f"SELECT COUNT(*) as nr FROM {tabel_audit}") or {}).get("nr", 0)
    try:
        tabel_fact = domain_id + "_facturi" if USE_PG else "facturi"
        nr_facturi = (registry.query_one(domain_id, f"SELECT COUNT(*) as nr FROM {tabel_fact}") or {}).get("nr", 0)
        val_fact   = (registry.query_one(domain_id, f"SELECT SUM(total) as s FROM {tabel_fact}") or {}).get("s", 0) or 0
    except: nr_facturi = 0; val_fact = 0
    status_rows = registry.query(domain_id, f"SELECT status, COUNT(*) as nr FROM {tabel} GROUP BY status ORDER BY nr DESC")
    toate    = registry.query(domain_id, f"SELECT * FROM {tabel}")
    ok_count = sum(1 for r in toate if verifica_integritate(domain_id, r))
    return {"domain_id": domain_id, "display_name": cfg.get("display_name", domain_id),
            "entitati_total": nr_total, "valoare_totala": round(float(val_total), 2),
            "urgent_count": nr_urgent, "audit_events": nr_audit,
            "facturi_count": nr_facturi, "valoare_facturata": round(float(val_fact), 2),
            "integritate_ok": ok_count, "integritate_fail": nr_total - ok_count,
            "distributie_status": {r["status"]: r["nr"] for r in status_rows},
            "tenanti_count": len(cfg.get("tenants", [])), "timestamp": utcnow()}

@app.get("/api/domains/{domain_id}/facturi")
def get_facturi(domain_id: str, limit: int=Query(50,ge=1,le=200),
                current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    try:
        tabel = domain_id + "_facturi" if USE_PG else "facturi"
        rows  = registry.query(domain_id, f"SELECT * FROM {tabel} ORDER BY emisa_la DESC LIMIT ?", (limit,))
        return {"facturi": rows, "total": len(rows)}
    except: return {"facturi": [], "total": 0}

@app.get("/api/domains/{domain_id}/aprobari")
def get_aprobari(domain_id: str, entity_id: Optional[str]=None,
                 current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    try:
        tabel = domain_id + "_aprobari" if USE_PG else "aprobari"
        if entity_id:
            rows = registry.query(domain_id, f"SELECT * FROM {tabel} WHERE comanda_id=? ORDER BY timestamp", (entity_id,))
        else:
            rows = registry.query(domain_id, f"SELECT * FROM {tabel} ORDER BY timestamp DESC LIMIT 50")
        return {"aprobari": rows, "total": len(rows)}
    except: return {"aprobari": [], "total": 0}

@app.get("/api/stats/global")
def global_stats(current: dict = Depends(get_current_tenant)):
    require_admin(current)
    result = {}
    totals = {"entitati": 0, "valoare": 0.0, "facturi": 0}
    for domain_id in registry.domains:
        try:
            s = get_stats(domain_id, current)
            result[domain_id] = s
            totals["entitati"] += s["entitati_total"]
            totals["valoare"]  += s["valoare_totala"]
            totals["facturi"]  += s["facturi_count"]
        except Exception as e:
            result[domain_id] = {"error": str(e)}
    return {"domenii": result, "totals": totals,
            "db": "postgresql" if USE_PG else "sqlite", "timestamp": utcnow()}
