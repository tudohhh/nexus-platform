import os
from datetime import datetime, timezone
from typing import Optional

LANGFUSE_ENABLED = bool(os.environ.get("LANGFUSE_SECRET_KEY"))

if LANGFUSE_ENABLED:
    from langfuse import Langfuse
    _lf = Langfuse(
        secret_key=os.environ.get("LANGFUSE_SECRET_KEY"),
        public_key=os.environ.get("LANGFUSE_PUBLIC_KEY"),
        host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
    )
    print("Tracing: LangFuse ON")
else:
    _lf = None
    print("Tracing: OFF (set LANGFUSE_SECRET_KEY to enable)")

def trace(name: str, input: dict, output: dict = None,
          tenant_id: str = None, domain_id: str = None,
          level: str = "DEFAULT", status: str = "SUCCESS"):
    if not LANGFUSE_ENABLED or not _lf:
        return None
    try:
        t = _lf.trace(
            name=name,
            input=input,
            output=output or {},
            metadata={
                "tenant_id": tenant_id,
                "domain_id": domain_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level,
                "status": status,
            }
        )
        return t
    except Exception as e:
        print("Tracing ERR: " + str(e)[:100])
        return None

def trace_request(endpoint: str, domain_id: str, tenant_id: str,
                  params: dict, result: dict, duration_ms: float = 0):
    return trace(
        name="api_request",
        input={"endpoint": endpoint, "params": params},
        output={"result_keys": list(result.keys()) if isinstance(result, dict) else "list",
                "duration_ms": round(duration_ms, 2)},
        tenant_id=tenant_id,
        domain_id=domain_id,
    )

def trace_error(endpoint: str, domain_id: str, tenant_id: str,
                error: str, params: dict = None):
    return trace(
        name="api_error",
        input={"endpoint": endpoint, "params": params or {}},
        output={"error": error},
        tenant_id=tenant_id,
        domain_id=domain_id,
        level="ERROR",
        status="ERROR",
    )

def trace_auth(action: str, tenant_id: str, domain_id: str,
               success: bool, detail: str = ""):
    return trace(
        name="auth_" + action,
        input={"tenant_id": tenant_id, "domain_id": domain_id},
        output={"success": success, "detail": detail},
        tenant_id=tenant_id,
        domain_id=domain_id,
        level="WARNING" if not success else "DEFAULT",
        status="SUCCESS" if success else "ERROR",
    )

def flush():
    if LANGFUSE_ENABLED and _lf:
        try: _lf.flush()
        except: pass
