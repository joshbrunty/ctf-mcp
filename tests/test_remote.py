"""Phase 2: bearer auth, streamable-http smoke, challenge desk + coach visibility."""

from __future__ import annotations

import json

import pytest
from mcp.server.transport_security import TransportSecuritySettings
from starlette.testclient import TestClient

from ctf_mcp.auth import BearerCredential, StaticBearerVerifier, parse_auth_tokens
from ctf_mcp.desk import list_all_challenges, list_challenges_for, save_challenge
from ctf_mcp.server import build_http_app


@pytest.fixture
def tokens():
    return [
        BearerCredential(label="alice", secret="alice-secret-token"),
        BearerCredential(label="bob", secret="bob-secret-token"),
    ]


@pytest.fixture
def app(tmp_path, monkeypatch, tokens):
    monkeypatch.setenv("CTF_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setenv("CTF_MCP_HOSTED", "1")
    monkeypatch.setenv("CTF_MCP_ISOLATE_SESSIONS", "1")
    monkeypatch.setenv("CTF_MCP_COACH_TOKEN", "coach-secret-token")
    monkeypatch.setenv("CTF_MCP_PUBLIC_URL", "http://127.0.0.1:8765")
    monkeypatch.setenv("CTF_MCP_AUDIT_LOG", str(tmp_path / "ws" / "audit.jsonl"))
    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return build_http_app(
        host="127.0.0.1",
        port=8765,
        path="/mcp",
        credentials=tokens,
        transport_security=security,
    )


def test_parse_auth_tokens_single_and_multi(monkeypatch):
    monkeypatch.delenv("CTF_MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("CTF_MCP_AUTH_TOKENS", raising=False)
    creds = parse_auth_tokens(single="team-secret", multi="alice:a1,bob:b2")
    assert [c.label for c in creds] == ["team", "alice", "bob"]


def test_static_verifier_accepts_and_rejects(tokens):
    import anyio

    v = StaticBearerVerifier(tokens)

    async def _run():
        ok = await v.verify_token("alice-secret-token")
        bad = await v.verify_token("nope")
        assert ok is not None and ok.client_id == "alice"
        assert bad is None

    anyio.run(_run)


def test_mcp_requires_bearer(app):
    with TestClient(app) as client:
        r = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            },
        )
        assert r.status_code == 401


def test_mcp_accepts_valid_bearer(app):
    with TestClient(app) as client:
        r = client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer alice-secret-token",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            },
        )
        assert r.status_code == 200
        assert "ctf-solver" in r.text


def test_health_and_desk_pages(app):
    with TestClient(app) as client:
        h = client.get("/health")
        assert h.status_code == 200
        body = h.json()
        assert body["status"] == "ok"
        assert body["desk"] is True
        desk = client.get("/")
        assert desk.status_code == 200
        assert b"Challenge Desk" in desk.content or b"Upload a challenge" in desk.content


def test_desk_upload_and_list(app, tmp_path):
    with TestClient(app) as client:
        assert client.get("/api/me").status_code == 401
        me = client.get("/api/me", headers={"Authorization": "Bearer alice-secret-token"})
        assert me.status_code == 200
        assert me.json()["label"] == "alice"

        files = {"files": ("chal.txt", b"flag{desk_upload}", "text/plain")}
        data = {
            "title": "Warmup",
            "category": "misc",
            "description": "easy",
            "shared": "0",
        }
        up = client.post(
            "/api/challenges",
            headers={"Authorization": "Bearer alice-secret-token"},
            data=data,
            files=files,
        )
        assert up.status_code == 200, up.text
        chal = up.json()["challenge"]
        assert chal["title"] == "Warmup"
        assert chal["owner"] == "alice"
        assert "users/alice/challenges/" in chal["rel_dir"]

        listed = client.get(
            "/api/challenges", headers={"Authorization": "Bearer alice-secret-token"}
        )
        assert listed.status_code == 200
        assert any(c["id"] == chal["id"] for c in listed.json()["challenges"])

        # Bob cannot see Alice's private challenge list entry as owner alice... 
        # actually list_challenges_for(bob) + shared — alice's private won't show for bob
        bob_list = client.get(
            "/api/challenges", headers={"Authorization": "Bearer bob-secret-token"}
        )
        assert all(c.get("owner") != "alice" for c in bob_list.json()["challenges"])


def test_shared_upload_visible_to_peers(app):
    with TestClient(app) as client:
        files = {"files": ("note.bin", b"abc", "application/octet-stream")}
        up = client.post(
            "/api/challenges",
            headers={"Authorization": "Bearer alice-secret-token"},
            data={"title": "Team Pack", "category": "forensics", "shared": "1"},
            files=files,
        )
        assert up.status_code == 200
        bob = client.get(
            "/api/challenges", headers={"Authorization": "Bearer bob-secret-token"}
        )
        assert any(c["title"] == "Team Pack" for c in bob.json()["challenges"])


def test_coach_overview(app):
    with TestClient(app) as client:
        forbidden = client.get(
            "/api/coach/overview", headers={"Authorization": "Bearer alice-secret-token"}
        )
        assert forbidden.status_code == 403

        # seed a challenge
        client.post(
            "/api/challenges",
            headers={"Authorization": "Bearer alice-secret-token"},
            data={"title": "Coach Sees", "category": "crypto", "shared": "0"},
            files={"files": ("c.txt", b"x", "text/plain")},
        )

        overview = client.get(
            "/api/coach/overview", headers={"Authorization": "Bearer coach-secret-token"}
        )
        assert overview.status_code == 200
        data = overview.json()
        assert any(p["label"] == "alice" for p in data["players"])
        assert any(c["title"] == "Coach Sees" for c in data["challenges"])
        assert any(a.get("event") == "challenge_upload" for a in data["activity"])


def test_save_challenge_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setenv("CTF_MCP_HOSTED", "1")
    meta = save_challenge(
        owner="alice",
        title="Unit",
        category="misc",
        description="",
        files=[("a.txt", b"hi")],
        shared=False,
    )
    assert list_challenges_for("alice")
    assert meta["id"] in {c["id"] for c in list_all_challenges()}


def test_http_refuses_without_auth_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.delenv("CTF_MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("CTF_MCP_AUTH_TOKENS", raising=False)
    from ctf_mcp.server import main

    with pytest.raises(SystemExit) as ei:
        main(["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8765"])
    assert ei.value.code == 2
