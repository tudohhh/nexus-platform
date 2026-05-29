import os, hmac, hashlib, uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY  = os.environ.get("NEXUS_SECRET", "nexus-dev-secret-uniform-2026")
ALGORITHM   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer      = HTTPBearer()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload["iat"] = datetime.now(timezone.utc)
    payload["jti"] = uuid.uuid4().hex
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Token invalid: " + str(e))

def get_current_tenant(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    payload = decode_token(credentials.credentials)
    tenant_id = payload.get("tenant_id")
    domain_id = payload.get("domain_id")
    role      = payload.get("role", "user")
    if not tenant_id or not domain_id:
        raise HTTPException(status_code=401, detail="Token incomplet")
    return {"tenant_id": tenant_id, "domain_id": domain_id, "role": role}

def require_domain(domain_id: str, current: dict):
    if current["domain_id"] != domain_id and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Acces interzis pentru domeniu: " + domain_id)

def require_admin(current: dict):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Doar adminii pot face asta")
