import os, json, hmac, hashlib, uuid, sqlite3
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

def utcnow():
    return datetime.now(timezone.utc).isoformat()

BASE        = os.environ.get("NEXUS_BASE", ".")
DOMAINS_DIR = os.path.join(BASE, "domains")
SECRET      = os.environ.get("NEXUS_SECRET", "nexus-dev-secret-uniform-2026")

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
            db_path = os.path.join(DOMAINS_DIR, domain_id, f"{domain_id}.db")
            if not os.path.exists(db_path):
                raise HTTPException(404, f"DB inexistenta: {domain_id}")
            conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self.connections[domain_id] = conn
        return self.connections[domain_id]

    def owner_key(self, domain_id):
        """Citit din config.json - zero hardcoding."""
        return self.domains.get(domain_id, {}).get("owner_key", "tenant_id")

registry = DomainRegistry()

def detecteaza_tabel(domain_id):
    conn = registry.get_db(domain_id)
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
        data_obj  = json.loads(row["data"])
        nonce     = data_obj.get("_nonce", "")
        timestamp = data_obj.get("_timestamp", "")
        valoare   = safe_get(row, "valoare", 0) or 0
        owner_key = registry.owner_key(domain_id)
        owner_id  = safe_get(row, owner_key, "")
        pd = {
            "comanda_id": row["id"],
            owner_key:    owner_id,
            "data":       row["data"],
            "timestamp":  timestamp,
            "nonce":      nonce,
            "valoare":    valoare
        }
        canonical = json.dumps(pd, ensure_ascii=True, sort_keys=True, separators=(",",":"))
        expected  = hmac.new(SECRET.encode(), (row["id"] + canonical).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, row["hash"])
    except:
        return False

app = FastAPI(title="Nexus Platform API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"platform": "Nexus Platform", "version": "1.0.0",
            "domenii": list(registry.domains.keys()), "status": "operational", "timestamp": utcnow()}

@app.get("/health")
def health():
    status = {}
    for domain_id in registry.domains:
        try:
            conn  = registry.get_db(domain_id)
            tabel = detecteaza_tabel(domain_id)
            nr    = conn.execute(f"SELECT COUNT(*) FROM {tabel}").fetchone()[0]
            status[domain_id] = {"status": "ok", "entitati": nr}
        except Exception as e:
            status[domain_id] = {"status": "error", "detail": str(e)}
    return {"platform": "Nexus", "domenii": status, "timestamp": utcnow()}

@app.get("/api/domains")
def list_domains():
    result = []
    for domain_id, cfg in registry.domains.items():
        try:
            conn  = registry.get_db(domain_id)
            tabel = detecteaza_tabel(domain_id)
            nr    = conn.execute(f"SELECT COUNT(*) FROM {tabel}").fetchone()[0]
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

@app.get("/api/domains/{domain_id}/tenants")
def get_tenants(domain_id: str):
    conn = registry.get_db(domain_id)
    try:
        rows = conn.execute("SELECT * FROM tenanti ORDER BY tenant_id").fetchall()
        return {"tenanti": [dict(r) for r in rows], "total": len(rows)}
    except:
        cfg = registry.get(domain_id)
        return {"tenanti": cfg.get("tenants", []), "total": len(cfg.get("tenants", []))}

@app.get("/api/domains/{domain_id}/entities")
def get_entities(domain_id: str, tenant_id: Optional[str]=None,
                 status: Optional[str]=None, urgent: Optional[bool]=None,
                 limit: int=Query(50,ge=1,le=200), offset: int=Query(0,ge=0)):
    conn      = registry.get_db(domain_id)
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
    rows = conn.execute(query, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["integritate"] = "OK" if verifica_integritate(domain_id, r) else "COMPROMIS"
        try:    d["data"] = json.loads(d["data"])
        except: pass
        result.append(d)
    return {"domain_id": domain_id, "entitati": result, "total": len(result), "limit": limit, "offset": offset}

@app.get("/api/domains/{domain_id}/entities/{entity_id}")
def get_entity(domain_id: str, entity_id: str):
    conn  = registry.get_db(domain_id)
    tabel = detecteaza_tabel(domain_id)
    row   = conn.execute(f"SELECT * FROM {tabel} WHERE id=?", (entity_id,)).fetchone()
    if not row: raise HTTPException(404, f"Entitate {entity_id} negasita")
    d = dict(row)
    d["integritate"] = "OK" if verifica_integritate(domain_id, row) else "COMPROMIS"
    try:    d["data"] = json.loads(d["data"])
    except: pass
    try:
        linii = conn.execute("SELECT * FROM linii_comanda WHERE comanda_id=?", (entity_id,)).fetchall()
        d["linii"] = [dict(l) for l in linii]
    except: d["linii"] = []
    return d

@app.get("/api/domains/{domain_id}/audit")
def get_audit(domain_id: str, entity_id: Optional[str]=None, limit: int=Query(50,ge=1,le=200)):
    conn = registry.get_db(domain_id)
    if entity_id:
        rows = conn.execute("SELECT * FROM audit_log WHERE comanda_id=? ORDER BY timestamp DESC LIMIT ?", (entity_id, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return {"audit": [dict(r) for r in rows], "total": len(rows)}

@app.get("/api/domains/{domain_id}/stats")
def get_stats(domain_id: str):
    conn  = registry.get_db(domain_id)
    tabel = detecteaza_tabel(domain_id)
    cfg   = registry.get(domain_id)
    nr_total  = conn.execute(f"SELECT COUNT(*) FROM {tabel}").fetchone()[0]
    val_total = conn.execute(f"SELECT SUM(valoare) FROM {tabel}").fetchone()[0] or 0
    nr_audit  = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    try:    nr_urgent = conn.execute(f"SELECT COUNT(*) FROM {tabel} WHERE urgent=1").fetchone()[0]
    except: nr_urgent = 0
    try:
        nr_facturi = conn.execute("SELECT COUNT(*) FROM facturi").fetchone()[0]
        val_fact   = conn.execute("SELECT SUM(total) FROM facturi").fetchone()[0] or 0
    except: nr_facturi = 0; val_fact = 0
    status_rows = conn.execute(f"SELECT status, COUNT(*) as nr FROM {tabel} GROUP BY status ORDER BY nr DESC").fetchall()
    toate    = conn.execute(f"SELECT * FROM {tabel}").fetchall()
    ok_count = sum(1 for r in toate if verifica_integritate(domain_id, r))
    return {"domain_id": domain_id, "display_name": cfg.get("display_name", domain_id),
            "entitati_total": nr_total, "valoare_totala": round(val_total,2),
            "urgent_count": nr_urgent, "audit_events": nr_audit,
            "facturi_count": nr_facturi, "valoare_facturata": round(val_fact,2),
            "integritate_ok": ok_count, "integritate_fail": nr_total-ok_count,
            "distributie_status": {r["status"]: r["nr"] for r in status_rows},
            "tenanti_count": len(cfg.get("tenants",[])), "timestamp": utcnow()}

@app.get("/api/domains/{domain_id}/facturi")
def get_facturi(domain_id: str, limit: int=Query(50,ge=1,le=200)):
    conn = registry.get_db(domain_id)
    try:
        rows = conn.execute("SELECT * FROM facturi ORDER BY emisa_la DESC LIMIT ?", (limit,)).fetchall()
        return {"facturi": [dict(r) for r in rows], "total": len(rows)}
    except: return {"facturi": [], "total": 0}

@app.get("/api/domains/{domain_id}/aprobari")
def get_aprobari(domain_id: str, entity_id: Optional[str]=None):
    conn = registry.get_db(domain_id)
    try:
        if entity_id:
            rows = conn.execute("SELECT * FROM aprobari WHERE comanda_id=? ORDER BY timestamp", (entity_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM aprobari ORDER BY timestamp DESC LIMIT 50").fetchall()
        return {"aprobari": [dict(r) for r in rows], "total": len(rows)}
    except: return {"aprobari": [], "total": 0}

@app.get("/api/stats/global")
def global_stats():
    result = {}
    totals = {"entitati": 0, "valoare": 0.0, "facturi": 0}
    for domain_id in registry.domains:
        try:
            s = get_stats(domain_id)
            result[domain_id] = s
            totals["entitati"] += s["entitati_total"]
            totals["valoare"]  += s["valoare_totala"]
            totals["facturi"]  += s["facturi_count"]
        except Exception as e:
            result[domain_id] = {"error": str(e)}
    return {"domenii": result, "totals": totals, "timestamp": utcnow()}
