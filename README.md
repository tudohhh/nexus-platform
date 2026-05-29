# Nexus Platform

White-label AI call center platform. One codebase, N domains, N clients.
New domain = JSON config. Zero new code.

## Live Domains

| Domain | Description | Tenants |
|--------|-------------|---------|
| restaurant | B2B catering orders with delivery | 3 |
| farmacie | Medical supplies between clinics and suppliers | 6 |
| constructii | Construction materials with approval chain | 10 |

## API Endpoints

GET  /                                  # platform status
GET  /health                            # all domains health
GET  /api/domains                       # list domains
GET  /api/stats/global                  # global stats
GET  /api/domains/{id}/config           # domain config
GET  /api/domains/{id}/tenants          # active tenants
GET  /api/domains/{id}/entities         # entities
GET  /api/domains/{id}/entities/{eid}   # single entity
GET  /api/domains/{id}/audit            # audit log
GET  /api/domains/{id}/stats            # domain stats
GET  /api/domains/{id}/facturi          # invoices
GET  /api/domains/{id}/aprobari         # approvals

## Adding a New Domain

1. Create domains/{domain_id}/config.json
2. Define FSM, schemas, tenants, owner_key
3. Zero other changes. Server auto-detects.

## Security

HMAC-SHA256 per contract · Canonical JSON · Nonce anti-replay
Tenant ownership check · JSON Schema strict · Append-only audit log

## Stack

Python 3.12 · FastAPI · SQLite WAL · Railway · GitHub CI/CD

---
Built in Romania · May 2026
