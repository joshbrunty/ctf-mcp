"""Phase 1 hardening: path jail, scope holes, exec/hosted defaults, audit stubs."""

from __future__ import annotations

import json

import httpx
import pytest

from ctf_mcp import crypto, execution, web
from ctf_mcp.audit import summarize_args
from ctf_mcp.common import assert_in_workspace, output_path, resolve_path, workspace
from ctf_mcp.config import (
    allow_any_tool_enabled,
    exec_enabled,
    factordb_default,
    path_jail_enabled,
    safety_snapshot,
)


def test_path_jail_blocks_absolute_escape(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("CTF_WORKSPACE", str(ws))
    monkeypatch.delenv("CTF_MCP_ALLOW_HOST_PATHS", raising=False)
    monkeypatch.delenv("CTF_MCP_HOSTED", raising=False)
    outside = tmp_path / "secret.txt"
    outside.write_text("nope")
    assert path_jail_enabled()
    with pytest.raises(PermissionError, match="escapes CTF_WORKSPACE"):
        resolve_path(str(outside))


def test_path_jail_blocks_dotdot(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    monkeypatch.setenv("CTF_WORKSPACE", str(ws))
    monkeypatch.delenv("CTF_MCP_ALLOW_HOST_PATHS", raising=False)
    (tmp_path / "outside.txt").write_text("x")
    with pytest.raises(PermissionError, match="escapes CTF_WORKSPACE"):
        resolve_path("../outside.txt")


def test_path_jail_allows_workspace_relative(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("CTF_WORKSPACE", str(ws))
    target = workspace() / "chal.bin"
    target.write_bytes(b"flag{ok}")
    assert resolve_path("chal.bin") == target.resolve()
    assert resolve_path(str(target)) == target.resolve()


def test_path_jail_symlink_escape(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    monkeypatch.setenv("CTF_WORKSPACE", str(ws))
    monkeypatch.delenv("CTF_MCP_ALLOW_HOST_PATHS", raising=False)
    outside = tmp_path / "host-secret"
    outside.write_text("secret")
    link = ws / "leak"
    link.symlink_to(outside)
    with pytest.raises(PermissionError, match="escapes CTF_WORKSPACE"):
        resolve_path("leak")


def test_allow_host_paths_opt_out(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("CTF_WORKSPACE", str(ws))
    monkeypatch.setenv("CTF_MCP_ALLOW_HOST_PATHS", "1")
    outside = tmp_path / "ok.txt"
    outside.write_text("yes")
    assert resolve_path(str(outside)).read_text() == "yes"


def test_hosted_ignores_allow_host_paths(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("CTF_WORKSPACE", str(ws))
    monkeypatch.setenv("CTF_MCP_HOSTED", "1")
    monkeypatch.setenv("CTF_MCP_ALLOW_HOST_PATHS", "1")
    outside = tmp_path / "nope.txt"
    outside.write_text("x")
    with pytest.raises(PermissionError):
        resolve_path(str(outside))


def test_output_path_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKSPACE", str(tmp_path / "ws"))
    with pytest.raises(PermissionError):
        output_path("..", "x")
    with pytest.raises(PermissionError):
        output_path("scripts", "../x.py")
    with pytest.raises(PermissionError):
        output_path("a/../../etc", "x")
    p = output_path("extracted/chal", "ok.bin")
    assert assert_in_workspace(p) == p
    assert p.parent.name == "chal"


def test_dns_lookup_is_scoped(monkeypatch):
    monkeypatch.setenv("CTF_SCOPE", "*.ctf.marshall.edu,10.10.0.0/16")
    with pytest.raises(PermissionError):
        web.dns_lookup("evil.example.com")
    # In-scope name is allowed (verify_ips off for dns_lookup itself).
    monkeypatch.setattr(web.socket, "getaddrinfo", lambda *a, **k: [
        (0, 0, 0, "", ("10.10.1.2", 0)),
    ])
    monkeypatch.setattr(web.socket, "gethostbyaddr", lambda ip: ("web1.ctf.marshall.edu", [], [ip]))
    out = web.dns_lookup("web1.ctf.marshall.edu")
    assert out["addresses"] == ["10.10.1.2"]


def test_scope_verifies_resolved_ips_when_enabled(monkeypatch):
    monkeypatch.setenv("CTF_SCOPE", "*.ctf.marshall.edu,10.10.0.0/16")
    monkeypatch.setenv("CTF_SCOPE_VERIFY_IPS", "1")
    monkeypatch.setattr(web.socket, "getaddrinfo", lambda *a, **k: [
        (0, 0, 0, "", ("8.8.8.8", 0)),
    ])
    with pytest.raises(PermissionError, match="resolved to 8.8.8.8"):
        web.check_scope("web1.ctf.marshall.edu")
    monkeypatch.setattr(web.socket, "getaddrinfo", lambda *a, **k: [
        (0, 0, 0, "", ("10.10.9.9", 0)),
    ])
    assert web.check_scope("web1.ctf.marshall.edu") == ""


def test_http_request_rechecks_redirect_host(monkeypatch):
    monkeypatch.setenv("CTF_SCOPE", "in.example.com")
    monkeypatch.setenv("CTF_SCOPE_VERIFY_IPS", "0")

    calls = {"n": 0}

    class FakeResponse:
        def __init__(self, status, url, location=None, content=b"ok", headers=None):
            self.status_code = status
            self.url = url
            self.content = content
            self.text = content.decode()
            self.headers = httpx.Headers(headers or ({"location": location} if location else {}))
            self.cookies = httpx.Cookies()
            self.history = []
            self.is_redirect = status in (301, 302, 303, 307, 308)

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeResponse(302, url, location="http://out.example.com/flag")
            return FakeResponse(200, url, content=b"flag{redirected}")

    monkeypatch.setattr(httpx, "Client", FakeClient)
    with pytest.raises(PermissionError, match="out.example.com"):
        web.http_request("http://in.example.com/start")


def test_hosted_exec_defaults(monkeypatch):
    monkeypatch.setenv("CTF_MCP_HOSTED", "1")
    monkeypatch.delenv("CTF_MCP_DISABLE_EXEC", raising=False)
    monkeypatch.delenv("CTF_MCP_UNSAFE_EXEC", raising=False)
    assert not exec_enabled()
    assert not allow_any_tool_enabled()
    assert not factordb_default()
    with pytest.raises(PermissionError):
        execution.run_python("print(1)")
    monkeypatch.setenv("CTF_MCP_ALLOW_ANY_TOOL", "1")
    assert not allow_any_tool_enabled()
    with pytest.raises(PermissionError, match="hosted"):
        execution.run_tool(["rm", "-rf", "/"])


def test_hosted_sandbox_stub_blocks_forced_exec(monkeypatch):
    monkeypatch.setenv("CTF_MCP_HOSTED", "1")
    monkeypatch.setenv("CTF_MCP_DISABLE_EXEC", "0")
    monkeypatch.delenv("CTF_MCP_UNSAFE_EXEC", raising=False)
    assert exec_enabled()
    with pytest.raises(PermissionError, match="sandbox"):
        execution.run_python("print(1)")


def test_factordb_default_respects_env(monkeypatch):
    monkeypatch.delenv("CTF_MCP_HOSTED", raising=False)
    monkeypatch.setenv("CTF_MCP_ALLOW_FACTORDB", "0")
    assert factordb_default() is False
    # rsa_solve with None should not call factordb; use a composite that local methods miss.
    # Small-e path still works without factordb:
    m = int.from_bytes(b"hi!", "big")
    p, q = 1000000007, 1000000009
    n = p * q
    out = crypto.rsa_solve(str(n), "65537", str(pow(m, 65537, n)))
    assert out["plaintext"]["text"] == "hi!"


def test_toolchain_status_includes_safety(monkeypatch):
    monkeypatch.setenv("CTF_MCP_HOSTED", "1")
    out = execution.toolchain_status()
    assert out["safety"]["hosted_mode"] is True
    assert out["run_python_enabled"] is False
    assert safety_snapshot()["sandbox"] == "stub"


def test_audit_redacts_secrets():
    summary = summarize_args((), {"secret": "hunter2", "code": "print('x'*5000)", "url": "http://x"})
    assert summary["secret"] == "<redacted>"
    assert summary["code"] == "<redacted>"
    assert summary["url"] == "http://x"


def test_audit_emits_when_enabled(monkeypatch, tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CTF_MCP_AUDIT", "1")
    monkeypatch.setenv("CTF_MCP_AUDIT_LOG", str(log))
    from ctf_mcp.audit import audit

    audit("scope_denied", host="evil.test")
    err = capsys.readouterr().err
    assert "scope_denied" in err
    line = log.read_text().strip()
    record = json.loads(line)
    assert record["event"] == "scope_denied"
    assert record["caller"] == "stdio-local"
