"""MCP server entry point: registers every tool module and the solving prompt."""

from __future__ import annotations

import argparse
import functools
import os
import sys
import time
from typing import Any

from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import crypto, execution, forensics, reversing, web
from .audit import audit, summarize_args
from .auth import StaticBearerVerifier, parse_auth_tokens, verifier_from_env
from .config import (
    allowed_hosts,
    hosted_mode,
    http_host,
    http_path,
    http_port,
    public_base_url,
    safety_snapshot,
    transport_name,
)
from .desk import register_desk_routes

INSTRUCTIONS = """\
CTF solving toolkit for Marshall University's cyber team.

Workflow:
1. Start every file with file_triage (or binary_info for executables). Run toolchain_status
   if unsure what external tools are installed.
2. Encoded/odd text: auto_decode first, then transform for a specific chain.
3. Follow the category tools: crypto (xor_crack, vigenere_crack, rsa_solve, hash_crack),
   forensics/stego (image_analyze, stego_lsb_scan, extract_embedded, pcap_summary, zip_crack),
   reversing/pwn (disassemble, find_gadgets, cyclic_find), web (web_recon, http_request, jwt_*).
4. Use run_python for custom solvers and run_tool for installed CLI tools.
Relative file paths resolve inside the workspace jail; absolute paths outside it are rejected
unless CTF_MCP_ALLOW_HOST_PATHS=1 on a trusted laptop. Carved/extracted output is written there.
Every tool reports flags matching the event's flag format in a `flags` field; verify a flag
before submitting. Only interact with hosts that are in scope for the event (CTF_SCOPE);
never attack the scoring platform or other teams' infrastructure.

On the team server, players upload challenges via the Challenge Desk browser UI; files land under
the workspace (users/<you>/challenges/... or shared/challenges/...). Triage those paths.
"""

VERSION = "0.2.0"


def _report_errors(fn):
    # The SDK hides the text of unexpected exceptions from the client. Here the reason
    # ("outside CTF_SCOPE", "not installed", bad input) is exactly what Claude needs.
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start = time.monotonic()
        try:
            result = fn(*args, **kwargs)
            audit(
                "tool_ok",
                tool=fn.__name__,
                duration_ms=int((time.monotonic() - start) * 1000),
                args=summarize_args(args, kwargs),
            )
            return result
        except Exception as exc:
            audit(
                "tool_error",
                tool=fn.__name__,
                duration_ms=int((time.monotonic() - start) * 1000),
                error=f"{type(exc).__name__}: {exc}",
                args=summarize_args(args, kwargs),
            )
            raise ToolError(f"{type(exc).__name__}: {exc}") from exc

    return wrapper


def _register_tools(server: MCPServer) -> None:
    for module in (crypto, forensics, reversing, web, execution):
        for fn in module.TOOLS:
            server.tool()(_report_errors(fn))

    @server.prompt()
    def solve_challenge(category: str, description: str, files: str = "", connection: str = "") -> str:
        """Kick off a structured solve of one CTF challenge."""
        return f"""Solve this {category} CTF challenge.

Description:
{description}

Files: {files or "none"}
Connection info: {connection or "none"}

Work methodically: triage first, state your hypothesis before each tool call, and keep notes of
what you ruled out. When you find the flag, show the exact steps that produced it so the team
can reproduce them and write it up. If you get stuck, list the three most likely next angles."""


def _advertised_base(host: str, port: int) -> str:
    return public_base_url() or f"http://{host}:{port}"


def create_server(
    *,
    token_verifier: StaticBearerVerifier | None = None,
    auth: AuthSettings | None = None,
    include_http_routes: bool = False,
) -> MCPServer:
    """Build a configured MCPServer. Auth kwargs required together for HTTP."""
    server = MCPServer(
        "ctf-solver",
        instructions=INSTRUCTIONS,
        version=VERSION,
        token_verifier=token_verifier,
        auth=auth,
    )
    _register_tools(server)

    if include_http_routes:
        if token_verifier is None:
            raise ValueError("include_http_routes requires token_verifier")

        @server.custom_route("/health", methods=["GET"])
        async def health(_request: Request) -> Response:
            snap = safety_snapshot()
            return JSONResponse(
                {
                    "status": "ok",
                    "service": "ctf-mcp",
                    "version": VERSION,
                    "hosted": snap["hosted_mode"],
                    "exec_enabled": snap["run_python_enabled"],
                    "desk": True,
                }
            )

        register_desk_routes(server, token_verifier)

    return server


# Default stdio instance (import-time) so existing entrypoints keep working.
mcp = create_server()


def build_auth_settings(host: str, port: int, path: str) -> AuthSettings:
    base = _advertised_base(host, port)
    resource = f"{base}{path}"
    return AuthSettings(
        issuer_url=AnyHttpUrl(base),
        resource_server_url=AnyHttpUrl(resource),
        required_scopes=["mcp"],
        validate_token_resource=False,
    )


def build_http_app(
    *,
    host: str | None = None,
    port: int | None = None,
    path: str | None = None,
    credentials: list | None = None,
    transport_security: TransportSecuritySettings | None = None,
) -> Any:
    """Starlette app for streamable-http (used by tests and custom runners)."""
    host = host if host is not None else http_host()
    port = port if port is not None else http_port()
    path = path if path is not None else http_path()

    if credentials is None:
        verifier = verifier_from_env()
        if verifier is None:
            raise RuntimeError(
                "streamable-http requires CTF_MCP_AUTH_TOKEN or CTF_MCP_AUTH_TOKENS"
            )
    else:
        verifier = StaticBearerVerifier(credentials)

    auth = build_auth_settings(host, port, path)
    server = create_server(token_verifier=verifier, auth=auth, include_http_routes=True)

    if transport_security is None:
        if host in ("127.0.0.1", "localhost", "::1"):
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=allowed_hosts(),
                allowed_origins=[
                    "http://127.0.0.1:*",
                    "http://localhost:*",
                    "http://[::1]:*",
                ],
            )
        else:
            transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=allowed_hosts(),
                allowed_origins=[],
            )

    return server.streamable_http_app(
        streamable_http_path=path,
        host=host,
        transport_security=transport_security,
    )


def _ensure_hosted_defaults_for_http() -> None:
    """When serving HTTP, prefer hosted safety profile unless already configured."""
    if "CTF_MCP_HOSTED" not in os.environ:
        os.environ["CTF_MCP_HOSTED"] = "1"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="ctf-mcp", description="CTF solver MCP server")
    p.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default=None,
        help="Override CTF_MCP_TRANSPORT (default: stdio)",
    )
    p.add_argument("--host", default=None, help="HTTP bind host (default CTF_MCP_HOST / 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="HTTP port (default CTF_MCP_PORT / 8765)")
    p.add_argument("--path", default=None, help="MCP path (default CTF_MCP_HTTP_PATH / /mcp)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    transport = (args.transport or transport_name()).strip().lower()

    if transport == "stdio":
        mcp.run(transport="stdio")
        return

    if transport == "sse":
        print(
            "sse transport is legacy; prefer streamable-http. Continuing anyway.",
            file=sys.stderr,
        )

    if transport not in ("streamable-http", "sse"):
        print(f"Unknown transport {transport!r}", file=sys.stderr)
        sys.exit(2)

    host = args.host or http_host()
    port = args.port if args.port is not None else http_port()
    path = args.path or http_path()

    if args.host:
        os.environ["CTF_MCP_HOST"] = host
    if args.port is not None:
        os.environ["CTF_MCP_PORT"] = str(port)
    if args.path:
        os.environ["CTF_MCP_HTTP_PATH"] = path
    os.environ["CTF_MCP_TRANSPORT"] = transport

    _ensure_hosted_defaults_for_http()

    try:
        creds = parse_auth_tokens()
    except ValueError as exc:
        print(f"auth config error: {exc}", file=sys.stderr)
        sys.exit(2)

    if not creds:
        print(
            "Refusing HTTP transport without auth. Set CTF_MCP_AUTH_TOKEN "
            "or CTF_MCP_AUTH_TOKENS (label:secret,...).",
            file=sys.stderr,
        )
        sys.exit(2)

    if host in ("0.0.0.0", "::", "*"):
        print(
            f"WARNING: binding {host}:{port} — prefer Tailscale/private IP. Auth is required.",
            file=sys.stderr,
        )

    if not os.environ.get("CTF_MCP_COACH_TOKEN", "").strip():
        print(
            "NOTE: CTF_MCP_COACH_TOKEN unset — coach desk visibility disabled until you set one.",
            file=sys.stderr,
        )

    verifier = StaticBearerVerifier(creds)
    auth = build_auth_settings(host, port, path)
    server = create_server(token_verifier=verifier, auth=auth, include_http_routes=True)

    if host in ("127.0.0.1", "localhost", "::1"):
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts(),
            allowed_origins=[
                "http://127.0.0.1:*",
                "http://localhost:*",
                "http://[::1]:*",
            ],
        )
    else:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts(),
            allowed_origins=[],
        )

    base = _advertised_base(host, port)
    print(
        f"ctf-mcp {VERSION} {transport} on {host}:{port}{path} "
        f"(hosted={hosted_mode()}, desk={base}/, public={base})",
        file=sys.stderr,
    )

    if transport == "streamable-http":
        server.run(
            transport="streamable-http",
            host=host,
            port=port,
            streamable_http_path=path,
            transport_security=security,
        )
    else:
        server.run(
            transport="sse",
            host=host,
            port=port,
            transport_security=security,
        )


if __name__ == "__main__":
    main()
