"""Runtime safety knobs for local vs hosted profiles.

``CTF_MCP_HOSTED=1`` opts into stricter defaults (disable exec, deny allow-any-tool,
factordb off, audit on, session isolation). Phase 2 adds streamable-http + bearer.
"""

from __future__ import annotations

import os


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _explicit(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower()


def hosted_mode() -> bool:
    """Stricter defaults for a shared/hosted process."""
    return _truthy("CTF_MCP_HOSTED")


def path_jail_enabled() -> bool:
    """Reject paths that resolve outside CTF_WORKSPACE.

    Always on in hosted mode. Locally on by default; set CTF_MCP_ALLOW_HOST_PATHS=1 to
    read absolute paths anywhere on a trusted laptop.
    """
    if hosted_mode():
        return True
    return not _truthy("CTF_MCP_ALLOW_HOST_PATHS")


def exec_enabled() -> bool:
    """Whether run_python may execute user code.

    Hosted default: disabled. Re-enable only with CTF_MCP_DISABLE_EXEC=0 (sandbox still stubbed).
    Local default: enabled unless CTF_MCP_DISABLE_EXEC=1.
    """
    explicit = _explicit("CTF_MCP_DISABLE_EXEC")
    if explicit is not None:
        return explicit in ("0", "false", "no", "off")
    return not hosted_mode()


def allow_any_tool_enabled() -> bool:
    """CTF_MCP_ALLOW_ANY_TOOL is ignored (denied) in hosted mode."""
    if hosted_mode():
        return False
    return _truthy("CTF_MCP_ALLOW_ANY_TOOL")


def factordb_default() -> bool:
    """Default for rsa_solve use_factordb. Hosted / CTF_MCP_ALLOW_FACTORDB=0 → False."""
    explicit = _explicit("CTF_MCP_ALLOW_FACTORDB")
    if explicit is not None:
        return explicit in ("1", "true", "yes", "on")
    return not hosted_mode()


def scope_verify_ips() -> bool:
    """When scope includes CIDRs, require resolved IPs to land in one of them.

    Hosted default: on. Local default: off (hostname allow is enough for laptop events).
    Override with CTF_SCOPE_VERIFY_IPS=0|1.
    """
    explicit = _explicit("CTF_SCOPE_VERIFY_IPS")
    if explicit is not None:
        return explicit not in ("0", "false", "no", "off")
    return hosted_mode()


def audit_enabled() -> bool:
    """Structured audit lines to stderr / CTF_MCP_AUDIT_LOG. Hosted default on."""
    explicit = _explicit("CTF_MCP_AUDIT")
    if explicit is not None:
        return explicit not in ("0", "false", "no", "off")
    return hosted_mode()


def sandbox_requested() -> bool:
    """Future container/Firejail path. Still stubbed; does not grant exec by itself."""
    return _truthy("CTF_MCP_SANDBOX")


def isolate_sessions() -> bool:
    """Per-bearer-label workspace under CTF_WORKSPACE/users/<label>.

    Hosted default: on. Local stdio default: off. Override with CTF_MCP_ISOLATE_SESSIONS=0|1.
    """
    explicit = _explicit("CTF_MCP_ISOLATE_SESSIONS")
    if explicit is not None:
        return explicit not in ("0", "false", "no", "off")
    return hosted_mode()


def transport_name() -> str:
    """stdio | streamable-http | sse (sse discouraged)."""
    return os.environ.get("CTF_MCP_TRANSPORT", "stdio").strip().lower() or "stdio"


def http_host() -> str:
    """Bind address. Default loopback — Tailscale/private first; set explicitly for mesh IP."""
    return os.environ.get("CTF_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1"


def http_port() -> int:
    raw = os.environ.get("CTF_MCP_PORT", "8765").strip() or "8765"
    return int(raw)


def http_path() -> str:
    path = os.environ.get("CTF_MCP_HTTP_PATH", "/mcp").strip() or "/mcp"
    if not path.startswith("/"):
        path = "/" + path
    return path


def public_base_url() -> str | None:
    """Optional advertised URL for AuthSettings / connect docs (e.g. http://100.x.y.z:8765)."""
    raw = os.environ.get("CTF_MCP_PUBLIC_URL", "").strip()
    return raw.rstrip("/") or None


def allowed_hosts() -> list[str]:
    """Host headers allowed when DNS-rebinding protection is on."""
    raw = os.environ.get("CTF_MCP_ALLOWED_HOSTS", "").strip()
    if raw:
        return [h.strip() for h in raw.split(",") if h.strip()]
    host = http_host()
    port = http_port()
    return [
        f"{host}:{port}",
        f"{host}:*",
        "127.0.0.1:*",
        "localhost:*",
        "[::1]:*",
    ]


def safety_snapshot() -> dict:
    """Values surfaced by toolchain_status."""
    return {
        "hosted_mode": hosted_mode(),
        "path_jail": path_jail_enabled(),
        "run_python_enabled": exec_enabled(),
        "allow_any_tool": allow_any_tool_enabled(),
        "factordb_default": factordb_default(),
        "scope_verify_ips": scope_verify_ips(),
        "audit": audit_enabled(),
        "isolate_sessions": isolate_sessions(),
        "sandbox": "stub" if sandbox_requested() or hosted_mode() else "off",
        "transport": transport_name(),
    }
