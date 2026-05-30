import os, json, hmac, hashlib, uuid, sqlite3, time
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from api.auth import (create_token, get_current_tenant, require_domain,
                      require_admin, hash_password, verify_password)
from api.tracing import trace_request, trace_error, trace_auth, flush


def utcnow():
    return datetime.now(timezone.utc).isoformat()

BASE         = os.environ.get("NEXUS_BASE", ".")
DOMAINS_DIR  = os.path.join(BASE, "domains")
SECRET       = os.environ.get("NEXUS_SECRET") or (_ for _ in ()).throw(EnvironmentError("NEXUS_SECRET lipsa din env"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG       = bool(DATABASE_URL)

# Rate limiter via PostgreSQL - shared intre toti workers

def check_rate_limit(key: str, max_requests: int = 5, window_seconds: int = 60) -> bool:
    if not USE_PG:
        return True
    now = time.time()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        cur = conn.cursor()
        cur.execute('SELECT count, window_start FROM rate_limit WHERE key=%s FOR UPDATE', (key,))
        row = cur.fetchone()
        if row:
            count, window_start = row
            if now - window_start > window_seconds:
                cur.execute('UPDATE rate_limit SET count=1, window_start=%s WHERE key=%s', (now, key))
                conn.commit()
                conn.close()
                return True
            if count >= max_requests:
                conn.rollback()
                conn.close()
                return False
            cur.execute('UPDATE rate_limit SET count=count+1 WHERE key=%s', (key,))
        else:
            cur.execute('INSERT INTO rate_limit (key, count, window_start) VALUES (%s, 1, %s)', (key, now))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f'[rate_limit] eroare: {e}')
        return True


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
            raise HTTPException(404, "Domeniu necunoscut: " + domain_id)
        return self.domains[domain_id]

    def get_db(self, domain_id):
        self.get(domain_id)
        if domain_id not in self.connections:
            if USE_PG:
                conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
                conn.autocommit = True
                self.connections[domain_id] = ("pg", conn)
            else:
                db_path = os.path.join(DOMAINS_DIR, domain_id, domain_id + ".db")
                if not os.path.exists(db_path):
                    raise HTTPException(404, "DB inexistenta: " + domain_id)
                conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.row_factory = sqlite3.Row
                self.connections[domain_id] = ("sqlite", conn)
        return self.connections[domain_id]

    def query(self, domain_id, sql, params=()):
        db_type, conn = self.get_db(domain_id)
        if db_type == "pg":
            cur = conn.cursor()
            cur.execute(sql.replace("?", "%s"), params)
            try:    return [dict(r) for r in cur.fetchall()]
            except: return []
        else:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def query_one(self, domain_id, sql, params=()):
        rows = self.query(domain_id, sql, params)
        return rows[0] if rows else None

    def owner_key(self, domain_id):
        return self.domains.get(domain_id, {}).get("owner_key", "tenant_id")

    def init_pg_tables(self):
        if not USE_PG: return
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS nexus_users (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, domain_id TEXT NOT NULL,
            password_hash TEXT NOT NULL, role TEXT DEFAULT 'user',
            active BOOLEAN DEFAULT TRUE, created_at TEXT)""")
        for domain_id in self.domains:
            cur.execute("CREATE TABLE IF NOT EXISTS " + domain_id + "_comenzi (id TEXT PRIMARY KEY, domain_id TEXT, tenant_id TEXT, data TEXT, hash TEXT, status TEXT, valoare REAL DEFAULT 0, urgent INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)")
            cur.execute("CREATE TABLE IF NOT EXISTS " + domain_id + "_audit_log (id TEXT PRIMARY KEY, domain_id TEXT, comanda_id TEXT, action TEXT, tenant_id TEXT, timestamp TEXT, details TEXT)")
            cur.execute("CREATE TABLE IF NOT EXISTS " + domain_id + "_tenanti (tenant_id TEXT PRIMARY KEY, domain_id TEXT, status TEXT DEFAULT 'active', created_at TEXT)")
        cur.execute("""CREATE TABLE IF NOT EXISTS rate_limit (
            key TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0,
            window_start REAL DEFAULT 0
        )""")
        cur.execute("SELECT id FROM nexus_users WHERE tenant_id='admin' AND domain_id='admin'")
        if not cur.fetchone():
            cur.execute("INSERT INTO nexus_users VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (uuid.uuid4().hex, "admin", "admin",
                 hash_password(os.environ.get("ADMIN_PASSWORD") or (_ for _ in ()).throw(EnvironmentError("ADMIN_PASSWORD lipsa din env"))),
                 "admin", True, utcnow()))
            print("OK: admin seeded")
        conn.close()

registry = DomainRegistry()

def detecteaza_tabel(domain_id):
    if USE_PG:
        return domain_id + "_comenzi"
    try:
        db_type, conn = registry.get_db(domain_id)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('audit_log','tenanti','linii_comanda','aprobari','facturi')").fetchall()
        return tables[0]["name"] if tables else domain_id + "_comenzi"
    except:
        return domain_id + "_comenzi"

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
              "data": data_str, "timestamp": timestamp, "nonce": nonce, "valoare": valoare}
        canonical = json.dumps(pd, ensure_ascii=True, sort_keys=True, separators=(",",":"))
        expected  = hmac.new(SECRET.encode(), (row["id"] + canonical).encode(), hashlib.sha256).hexdigest()
        stored    = row.get("hash", "") if isinstance(row, dict) else safe_get(row, "hash", "")
        return hmac.compare_digest(expected, stored)
    except: return False

app = FastAPI(title="Nexus Platform API", version="1.2.0")
app.add_middleware(CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*", "Authorization"])

@app.on_event("startup")
def startup():
    if USE_PG: registry.init_pg_tables()

@app.on_event("shutdown")
def shutdown():
    flush()

# ── AUTH ─────────────────────────────────────────────────

@app.post("/auth/login")
def login(request: Request, body: dict):
    t0 = time.time()
    # Rate limit: 5 requests/minut per IP
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login:{tenant_id}:{domain_id}"
    if not check_rate_limit(rate_key, max_requests=5, window_seconds=60):
        raise HTTPException(status_code=429, detail="Prea multe incercari. Incearca din nou in 60 secunde.")
    tenant_id = body.get("tenant_id", "")
    domain_id = body.get("domain_id", "")
    password  = body.get("password", "")
    if not tenant_id or not domain_id or not password:
        raise HTTPException(400, "tenant_id, domain_id, password obligatorii")
    if not USE_PG:
        raise HTTPException(503, "Auth doar cu PostgreSQL")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    cur  = conn.cursor()
    cur.execute("SELECT * FROM nexus_users WHERE tenant_id=%s AND domain_id=%s AND active=TRUE", (tenant_id, domain_id))
    user = cur.fetchone()
    conn.close()
    if not user or not verify_password(password, user["password_hash"]):
        trace_auth("login", tenant_id, domain_id, False, "bad credentials")
        raise HTTPException(401, "Credentiale invalide")
    token = create_token({"tenant_id": tenant_id, "domain_id": domain_id, "role": user["role"]})
    trace_auth("login", tenant_id, domain_id, True)
    return {"access_token": token, "token_type": "bearer",
            "tenant_id": tenant_id, "domain_id": domain_id, "role": user["role"],
            "duration_ms": round((time.time()-t0)*1000, 2)}

@app.post("/auth/register")
def register(body: dict, current: dict = Depends(get_current_tenant)):
    require_admin(current)
    tenant_id = body.get("tenant_id", "")
    domain_id = body.get("domain_id", "")
    password  = body.get("password", "")
    role      = body.get("role", "user")
    if not tenant_id or not domain_id or not password:
        raise HTTPException(400, "tenant_id, domain_id, password obligatorii")
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cur  = conn.cursor()
    cur.execute("INSERT INTO nexus_users VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (uuid.uuid4().hex, tenant_id, domain_id, hash_password(password), role, True, utcnow()))
    conn.close()
    trace_auth("register", tenant_id, domain_id, True, "role:" + role)
    return {"ok": True, "tenant_id": tenant_id, "domain_id": domain_id, "role": role}

@app.get("/auth/me")
def me(current: dict = Depends(get_current_tenant)):
    return current

# ── PUBLIC ───────────────────────────────────────────────

@app.get("/")
def root():
    return {"platform": "Nexus Platform", "version": "1.2.0",
            "domenii": list(registry.domains.keys()),
            "db": "postgresql" if USE_PG else "sqlite",
            "status": "operational", "timestamp": utcnow()}

@app.get("/health")
def health():
    status = {}
    for domain_id in registry.domains:
        try:
            tabel = detecteaza_tabel(domain_id)
            row   = registry.query_one(domain_id, "SELECT COUNT(*) as nr FROM " + tabel)
            status[domain_id] = {"status": "ok", "entitati": row["nr"] if row else 0}
        except Exception as e:
            status[domain_id] = {"status": "error", "detail": str(e)}
    return {"platform": "Nexus", "version": "1.2.0",
            "db": "postgresql" if USE_PG else "sqlite",
            "domenii": status, "timestamp": utcnow()}

@app.get("/api/domains")
def list_domains():
    result = []
    for domain_id, cfg in registry.domains.items():
        try:
            tabel = detecteaza_tabel(domain_id)
            row   = registry.query_one(domain_id, "SELECT COUNT(*) as nr FROM " + tabel)
            nr    = row["nr"] if row else 0
            result.append({"domain_id": domain_id,
                "display_name": cfg.get("display_name", domain_id),
                "description":  cfg.get("description", ""),
                "color_primary":cfg.get("color_primary", "#6366f1"),
                "logo_letter":  cfg.get("logo_letter", domain_id[0].upper()),
                "entitati": nr, "tenants": len(cfg.get("tenants", []))})
        except: result.append({"domain_id": domain_id, "status": "error"})
    return {"domenii": result, "total": len(result)}

@app.get("/api/domains/{domain_id}/config")
def get_config(domain_id: str):
    return registry.get(domain_id)

# ── PROTECTED ────────────────────────────────────────────

@app.get("/api/domains/{domain_id}/tenants")
def get_tenants(domain_id: str, current: dict = Depends(get_current_tenant)):
    t0 = time.time()
    require_domain(domain_id, current)
    try:
        tabel = domain_id + "_tenanti" if USE_PG else "tenanti"
        ph = "%s" if USE_PG else "?"
        # Admin vede toti tenantii, userul vede doar pe el
        if current["role"] == "admin":
            rows = registry.query(domain_id, "SELECT * FROM " + tabel + " ORDER BY tenant_id")
        else:
            rows = registry.query(domain_id, "SELECT * FROM " + tabel + " WHERE tenant_id=" + ph + " ORDER BY tenant_id", (current["tenant_id"],))
        result = {"tenanti": rows, "total": len(rows)}
    except:
        cfg = registry.get(domain_id)
        if current["role"] == "admin":
            tenanti = cfg.get("tenants", [])
        else:
            tenanti = [t for t in cfg.get("tenants", []) if t.get("tenant_id") == current["tenant_id"]]
        result = {"tenanti": tenanti, "total": len(tenanti)}
    trace_request("/tenants", domain_id, current["tenant_id"], {}, result, (time.time()-t0)*1000)
    return result

@app.get("/api/domains/{domain_id}/entities")
def get_entities(domain_id: str, tenant_id: Optional[str]=None,
                 status: Optional[str]=None, urgent: Optional[bool]=None,
                 limit: int=Query(50,ge=1,le=200), offset: int=Query(0,ge=0),
                 current: dict = Depends(get_current_tenant)):
    t0 = time.time()
    require_domain(domain_id, current)
    if current["role"] != "admin" and not tenant_id:
        tenant_id = current["tenant_id"]
    tabel     = detecteaza_tabel(domain_id)
    owner_key = registry.owner_key(domain_id)
    ph        = "%s" if USE_PG else "?"
    query  = "SELECT * FROM " + tabel + " WHERE 1=1"
    params = []
    if tenant_id:
        query += " AND " + owner_key + "=" + ph
        params += [tenant_id]
    if status:
        query += " AND status=" + ph
        params.append(status)
    if urgent is not None:
        query += " AND urgent=" + ph
        params.append(1 if urgent else 0)
    query += " ORDER BY created_at DESC LIMIT " + ph + " OFFSET " + ph
    params += [limit, offset]
    rows = registry.query(domain_id, query, params)
    result = []
    for r in rows:
        r["integritate"] = "OK" if verifica_integritate(domain_id, r) else "COMPROMIS"
        try:
            if isinstance(r.get("data"), str): r["data"] = json.loads(r["data"])
        except: pass
        result.append(r)
    out = {"domain_id": domain_id, "entitati": result, "total": len(result), "limit": limit, "offset": offset}
    trace_request("/entities", domain_id, current["tenant_id"],
                  {"tenant_id": tenant_id, "status": status}, {"total": len(result)}, (time.time()-t0)*1000)
    return out

@app.get("/api/domains/{domain_id}/entities/{entity_id}")
def get_entity(domain_id: str, entity_id: str, current: dict = Depends(get_current_tenant)):
    t0 = time.time()
    require_domain(domain_id, current)
    tabel = detecteaza_tabel(domain_id)
    row   = registry.query_one(domain_id, "SELECT * FROM " + tabel + " WHERE id=?", (entity_id,))
    if not row: raise HTTPException(404, "Entitate " + entity_id + " negasita")
    row["integritate"] = "OK" if verifica_integritate(domain_id, row) else "COMPROMIS"
    try:
        if isinstance(row.get("data"), str): row["data"] = json.loads(row["data"])
    except: pass
    try:
        tabel_linii = domain_id + "_linii_comanda" if USE_PG else "linii_comanda"
        row["linii"] = registry.query(domain_id, "SELECT * FROM " + tabel_linii + " WHERE comanda_id=?", (entity_id,))
    except: row["linii"] = []
    trace_request("/entities/" + entity_id, domain_id, current["tenant_id"], {}, {"id": entity_id}, (time.time()-t0)*1000)
    return row


@app.post("/api/domains/{domain_id}/entities")
def create_entity(domain_id: str, body: dict, current: dict = Depends(get_current_tenant)):
    t0 = time.time()
    require_domain(domain_id, current)

    tenant_id = body.get("tenant_id", current["tenant_id"])
    data      = body.get("data", {})

    if not data:
        raise HTTPException(400, "Campul data este obligatoriu")

    valoare = data.get("valoare", 0)
    if isinstance(valoare, (int, float)) and valoare < 0:
        raise HTTPException(400, "Valoarea nu poate fi negativa")

    data_str = json.dumps(data, ensure_ascii=False)
    if len(data_str) > 50000:
        raise HTTPException(413, "Payload prea mare — maxim 50KB")

    entity_id  = uuid.uuid4().hex
    cfg        = registry.get(domain_id)
    fsm_states = cfg.get("fsm", {}).get("states", ["DRAFT"])
    status_init = fsm_states[0] if fsm_states else "DRAFT"
    owner_key  = registry.owner_key(domain_id)
    tabel      = detecteaza_tabel(domain_id)
    now        = utcnow()

    hash_val = hmac.new(SECRET.encode(), (entity_id + data_str).encode(), hashlib.sha256).hexdigest()

    if USE_PG:
        _, conn = registry.get_db(domain_id)
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO {tabel} (id, domain_id, {owner_key}, data, hash, status, valoare, urgent, created_at, updated_at) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (entity_id, domain_id, tenant_id, data_str, hash_val, status_init,
             float(valoare), int(data.get("urgent", 0)), now, now)
        )
        cur.execute(
            f"INSERT INTO {domain_id}_audit_log (id, domain_id, comanda_id, action, tenant_id, timestamp, details) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (uuid.uuid4().hex, domain_id, entity_id, "CREATE", tenant_id, now,
             json.dumps({"status": status_init}))
        )
    else:
        registry.query(domain_id,
            f"INSERT INTO {tabel} (id, domain_id, {owner_key}, data, hash, status, valoare, urgent, created_at, updated_at) "
            f"VALUES (?,?,?,?,?,?,?,?,?,?)",
            (entity_id, domain_id, tenant_id, data_str, hash_val, status_init,
             float(valoare), int(data.get("urgent", 0)), now, now))

    trace_request("/entities POST", domain_id, tenant_id, body,
                  {"id": entity_id, "status": status_init}, (time.time()-t0)*1000)
    return {"id": entity_id, "domain_id": domain_id, "tenant_id": tenant_id,
            "status": status_init, "created_at": now}


@app.post("/api/domains/{domain_id}/entities/{entity_id}/transition")
def transition_entity(domain_id: str, entity_id: str, body: dict,
                      current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)

    trigger = body.get("trigger", "")
    if not trigger:
        raise HTTPException(400, "Campul trigger este obligatoriu")

    tabel = detecteaza_tabel(domain_id)
    row   = registry.query_one(domain_id, f"SELECT * FROM {tabel} WHERE id=?", (entity_id,))
    if not row:
        raise HTTPException(404, "Entitate negasita")

    cfg         = registry.get(domain_id)
    transitions = cfg.get("fsm", {}).get("transitions", [])
    status_cur  = row.get("status", "DRAFT")

    tranzitie = next(
        (t for t in transitions if t["trigger"] == trigger and t["source"] == status_cur),
        None
    )
    if not tranzitie:
        raise HTTPException(400, f"Tranzitie invalida: '{trigger}' din starea '{status_cur}'")

    status_nou = tranzitie["dest"]
    now        = utcnow()

    if USE_PG:
        _, conn = registry.get_db(domain_id)
        cur = conn.cursor()
        cur.execute(f"UPDATE {tabel} SET status=%s, updated_at=%s WHERE id=%s",
                    (status_nou, now, entity_id))
        cur.execute(
            f"INSERT INTO {domain_id}_audit_log (id, domain_id, comanda_id, action, tenant_id, timestamp, details) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (uuid.uuid4().hex, domain_id, entity_id, f"TRANSITION:{trigger}",
             current["tenant_id"], now, json.dumps({"from": status_cur, "to": status_nou}))
        )
    else:
        registry.query(domain_id, f"UPDATE {tabel} SET status=?, updated_at=? WHERE id=?",
                       (status_nou, now, entity_id))

    return {"id": entity_id, "status_anterior": status_cur,
            "status_nou": status_nou, "trigger": trigger, "updated_at": now}

@app.get("/api/domains/{domain_id}/audit")
def get_audit(domain_id: str, entity_id: Optional[str]=None,
              limit: int=Query(50,ge=1,le=200), current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    tabel = domain_id + "_audit_log" if USE_PG else "audit_log"
    if entity_id:
        rows = registry.query(domain_id, "SELECT * FROM " + tabel + " WHERE comanda_id=? ORDER BY timestamp DESC LIMIT ?", (entity_id, limit))
    else:
        rows = registry.query(domain_id, "SELECT * FROM " + tabel + " ORDER BY timestamp DESC LIMIT ?", (limit,))
    return {"audit": rows, "total": len(rows)}

@app.get("/api/domains/{domain_id}/stats")
def get_stats(domain_id: str, current: dict = Depends(get_current_tenant)):
    t0 = time.time()
    require_domain(domain_id, current)
    tabel = detecteaza_tabel(domain_id)
    cfg   = registry.get(domain_id)
    nr_total  = (registry.query_one(domain_id, "SELECT COUNT(*) as nr FROM " + tabel) or {}).get("nr", 0)
    val_total = (registry.query_one(domain_id, "SELECT SUM(valoare) as s FROM " + tabel) or {}).get("s", 0) or 0
    try:    nr_urgent = (registry.query_one(domain_id, "SELECT COUNT(*) as nr FROM " + tabel + " WHERE urgent=1") or {}).get("nr", 0)
    except: nr_urgent = 0
    tabel_audit = domain_id + "_audit_log" if USE_PG else "audit_log"
    nr_audit = (registry.query_one(domain_id, "SELECT COUNT(*) as nr FROM " + tabel_audit) or {}).get("nr", 0)
    try:
        tabel_fact = domain_id + "_facturi" if USE_PG else "facturi"
        nr_facturi = (registry.query_one(domain_id, "SELECT COUNT(*) as nr FROM " + tabel_fact) or {}).get("nr", 0)
        val_fact   = (registry.query_one(domain_id, "SELECT SUM(total) as s FROM " + tabel_fact) or {}).get("s", 0) or 0
    except: nr_facturi = 0; val_fact = 0
    status_rows = registry.query(domain_id, "SELECT status, COUNT(*) as nr FROM " + tabel + " GROUP BY status ORDER BY nr DESC")
    toate    = registry.query(domain_id, "SELECT * FROM " + tabel)
    ok_count = sum(1 for r in toate if verifica_integritate(domain_id, r))
    result = {"domain_id": domain_id, "display_name": cfg.get("display_name", domain_id),
            "entitati_total": nr_total, "valoare_totala": round(float(val_total), 2),
            "urgent_count": nr_urgent, "audit_events": nr_audit,
            "facturi_count": nr_facturi, "valoare_facturata": round(float(val_fact), 2),
            "integritate_ok": ok_count, "integritate_fail": nr_total - ok_count,
            "distributie_status": {r["status"]: r["nr"] for r in status_rows},
            "tenanti_count": len(cfg.get("tenants", [])), "timestamp": utcnow()}
    trace_request("/stats", domain_id, current["tenant_id"], {}, {"entitati": nr_total}, (time.time()-t0)*1000)
    return result

@app.get("/api/domains/{domain_id}/facturi")
def get_facturi(domain_id: str, limit: int=Query(50,ge=1,le=200),
                current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    try:
        tabel = domain_id + "_facturi" if USE_PG else "facturi"
        rows  = registry.query(domain_id, "SELECT * FROM " + tabel + " ORDER BY emisa_la DESC LIMIT ?", (limit,))
        return {"facturi": rows, "total": len(rows)}
    except: return {"facturi": [], "total": 0}

@app.get("/api/domains/{domain_id}/aprobari")
def get_aprobari(domain_id: str, entity_id: Optional[str]=None,
                 current: dict = Depends(get_current_tenant)):
    require_domain(domain_id, current)
    try:
        tabel = domain_id + "_aprobari" if USE_PG else "aprobari"
        if entity_id:
            rows = registry.query(domain_id, "SELECT * FROM " + tabel + " WHERE comanda_id=? ORDER BY timestamp", (entity_id,))
        else:
            rows = registry.query(domain_id, "SELECT * FROM " + tabel + " ORDER BY timestamp DESC LIMIT 50")
        return {"aprobari": rows, "total": len(rows)}
    except: return {"aprobari": [], "total": 0}

@app.get("/api/stats/global")
def global_stats(current: dict = Depends(get_current_tenant)):
    t0 = time.time()
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
    out = {"domenii": result, "totals": totals,
           "db": "postgresql" if USE_PG else "sqlite", "timestamp": utcnow()}
    trace_request("/stats/global", "all", current["tenant_id"], {},
                  {"entitati": totals["entitati"]}, (time.time()-t0)*1000)
    return out
