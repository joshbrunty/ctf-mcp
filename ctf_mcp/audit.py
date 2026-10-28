"""Structured audit logging for tool calls, uploads, and scope denials.

JSON lines to stderr and CTF_MCP_AUDIT_LOG (defaults under the workspace when hosted).
Caller identity comes from HTTP bearer client_id when present.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .config import audit_enabled, hosted_mode

# Keys whose values are redacted in argument summaries.
_SECRET_KEYS = frozenset({
    "secret", "password", "token", "authorization", "cookie", "cookies",
    "api_key", "apikey", "stdin", "body", "code", "json_body",
})


def _redact_value(key: str, value: Any) -> Any:
    lk = key.lower()
    if lk in _SECRET_KEYS or any(s in lk for s in ("secret", "password", "token", "auth")):
        if value is None or value == "" or value == {} or value == []:
            return value
        return "<redacted>"
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + f"…(+{len(value) - 200})"
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes:{len(value)}>"
    if isinstance(value, dict):
        return {k: _redact_value(str(k), v) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [_redact_value(key, v) for v in value[:20]]
    return value


def summarize_args(args: tuple = (), kwargs: dict | None = None) -> dict:
    out: dict[str, Any] = {}
    if args:
        out["args"] = [_redact_value(f"arg{i}", a) for i, a in enumerate(args[:8])]
    for k, v in (kwargs or {}).items():
        out[k] = _redact_value(k, v)
    return out


def _caller_id() -> str:
    explicit = os.environ.get("CTF_MCP_CALLER", "").strip()
    if explicit:
        return explicit
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token

        token = get_access_token()
        if token and token.client_id:
            return token.client_id
    except Exception:
        pass
    return "stdio-local"


def audit_log_path() -> str | None:
    """File path for JSONL audit, if any."""
    path = os.environ.get("CTF_MCP_AUDIT_LOG", "").strip()
    if path:
        return path
    if hosted_mode():
        # Stable default so the coach desk can tail activity without extra env.
        from .common import workspace_root

        root = workspace_root()
        root.mkdir(parents=True, exist_ok=True)
        return str(root / "audit.jsonl")
    return None


def audit(event: str, **fields: Any) -> None:
    """Emit one structured audit record if auditing is enabled."""
    if not audit_enabled():
        return
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "caller": _caller_id(),
        **fields,
    }
    line = json.dumps(record, default=str, ensure_ascii=False)
    print(line, file=sys.stderr, flush=True)
    path = audit_log_path()
    if path:
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
