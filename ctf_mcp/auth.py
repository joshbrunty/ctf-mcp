"""Static bearer-token auth for streamable-http (Phase 2 MVP).

Shared-secret tokens only — no OAuth/IdP yet. Configure with:

- ``CTF_MCP_AUTH_TOKEN`` — one team secret (client id ``team``)
- ``CTF_MCP_AUTH_TOKENS`` — comma-separated ``label:secret`` (or bare secrets)

Labels become MCP ``client_id`` values and drive per-user workspace folders when
session isolation is on.
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
from dataclasses import dataclass

from mcp.server.auth.provider import AccessToken

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class BearerCredential:
    label: str
    secret: str


def sanitize_label(label: str) -> str:
    """Filesystem-safe client label; raises ValueError if empty/unsafe."""
    cleaned = label.strip()
    if not cleaned or not _LABEL_RE.match(cleaned):
        raise ValueError(
            f"invalid auth label {label!r}: use 1–64 chars of [A-Za-z0-9._-], starting alnum"
        )
    return cleaned


def parse_auth_tokens(
    single: str | None = None,
    multi: str | None = None,
) -> list[BearerCredential]:
    """Parse env-style token config into credentials.

    ``multi`` entries are ``label:secret``. A bare secret (no colon) gets label
    ``userN``. ``single`` is always label ``team``.
    """
    creds: list[BearerCredential] = []
    seen_labels: set[str] = set()

    def _add(label: str, secret: str) -> None:
        secret = secret.strip()
        if not secret:
            raise ValueError("empty auth token secret")
        label = sanitize_label(label)
        if label in seen_labels:
            raise ValueError(f"duplicate auth label {label!r}")
        seen_labels.add(label)
        creds.append(BearerCredential(label=label, secret=secret))

    raw_single = single if single is not None else os.environ.get("CTF_MCP_AUTH_TOKEN")
    if raw_single is not None and raw_single.strip():
        _add("team", raw_single.strip())

    raw_multi = multi if multi is not None else os.environ.get("CTF_MCP_AUTH_TOKENS")
    if raw_multi is not None and raw_multi.strip():
        anon = 0
        for part in raw_multi.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                label, secret = part.split(":", 1)
                _add(label, secret)
            else:
                anon += 1
                _add(f"user{anon}", part)

    return creds


def generate_token(nbytes: int = 24) -> str:
    """URL-safe random token for .env bootstrap."""
    return secrets.token_urlsafe(nbytes)


class StaticBearerVerifier:
    """``TokenVerifier`` that accepts configured shared secrets."""

    def __init__(self, credentials: list[BearerCredential]):
        if not credentials:
            raise ValueError("at least one bearer credential is required")
        self._credentials = list(credentials)

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        for cred in self._credentials:
            if hmac.compare_digest(token, cred.secret):
                return AccessToken(
                    token=token,
                    client_id=cred.label,
                    scopes=["mcp"],
                    subject=cred.label,
                )
        return None


def verifier_from_env() -> StaticBearerVerifier | None:
    """Build a verifier from env, or ``None`` if no tokens configured."""
    creds = parse_auth_tokens()
    if not creds:
        return None
    return StaticBearerVerifier(creds)
