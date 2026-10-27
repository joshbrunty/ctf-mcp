"""Web, network and OSINT tools. Every outbound connection is checked against CTF_SCOPE."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse

from .common import clip, find_flags, preview, to_text


def scope_rules() -> list[str]:
    return [s.strip().lower() for s in os.environ.get("CTF_SCOPE", "").split(",") if s.strip()]


def check_scope(host: str) -> str:
    """Raise if host is outside CTF_SCOPE (comma-separated hosts, *.domains, IPs or CIDRs).
    Returns a warning string when no scope is configured."""
    rules = scope_rules()
    if not rules:
        return "CTF_SCOPE is not set: no target restriction. Set it to the event's hosts/CIDRs."
    host = host.lower().strip("[]")
    for rule in rules:
        if rule.startswith("*.") and (host.endswith(rule[1:]) or host == rule[2:]):
            return ""
        if host == rule:
            return ""
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False):
                return ""
        except ValueError:
            pass
    raise PermissionError(f"{host} is outside CTF_SCOPE ({', '.join(rules)}). Only attack in-scope targets.")


def _html_findings(body: str) -> dict:
    return {
        "html_comments": [c.strip()[:300] for c in re.findall(r"<!--(.*?)-->", body, re.S)][:30],
        "forms": [{"form": f[:200], "inputs": re.findall(r'name=["\']?([^"\'\s>]+)', f)}
                  for f in re.findall(r"<form.*?</form>", body, re.S | re.I)][:10],
        "scripts": re.findall(r'<script[^>]+src=["\']?([^"\'\s>]+)', body, re.I)[:30],
        "links": sorted(set(re.findall(r'(?:href|action)=["\']?([^"\'\s>#]+)', body, re.I)))[:60],
    }


def http_request(url: str, method: str = "GET", headers: dict | None = None, body: str = "",
                 params: dict | None = None, cookies: dict | None = None, json_body: dict | None = None,
                 follow_redirects: bool = True, verify_tls: bool = False, timeout: int = 20) -> dict:
    """Send an HTTP request to an in-scope target and return status, headers, cookies, body,
    HTML comments/forms/links, and any flags. TLS verification is off by default because
    CTF services often use self-signed certificates."""
    import httpx

    warning = check_scope(urllib.parse.urlsplit(url).hostname or "")
    with httpx.Client(verify=verify_tls, follow_redirects=follow_redirects, timeout=timeout) as client:
        r = client.request(method.upper(), url, headers=headers, params=params, cookies=cookies,
                           content=body.encode() if body else None, json=json_body)
    content = r.content
    text = r.text if "text" in r.headers.get("content-type", "") or "json" in r.headers.get("content-type", "") \
        or "javascript" in r.headers.get("content-type", "") else None
    out = {
        "status": r.status_code,
        "url": str(r.url),
        "redirects": [f"{h.status_code} {h.url}" for h in r.history],
        "headers": dict(r.headers),
        "cookies": dict(r.cookies),
        "body": clip(text, 15000) if text is not None else preview(content, 3000),
        "flags": find_flags(content + " ".join(f"{k}: {v}" for k, v in r.headers.items()).encode()),
    }
    if text and "html" in r.headers.get("content-type", ""):
        out.update(_html_findings(text))
    if warning:
        out["scope_warning"] = warning
    return out


RECON_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".svn/entries", ".env", ".DS_Store",
    "backup.zip", "index.php.bak", "index.php~", "admin", "login", "flag", "flag.txt", "api",
    "swagger.json", "api/docs", "graphql", "server-status", ".well-known/security.txt", "debug",
    "console", "source", "app.py", "config.php.bak",
]


def web_recon(base_url: str, extra_paths: list[str] | None = None) -> dict:
    """Light recon of an in-scope web challenge: fetch the index (headers, comments, forms,
    tech hints) and check common CTF leak paths (.git, robots.txt, backups, .env, flag.txt...)."""
    import httpx

    parts = urllib.parse.urlsplit(base_url)
    warning = check_scope(parts.hostname or "")
    base = base_url if base_url.endswith("/") else base_url + "/"
    found = []
    with httpx.Client(verify=False, follow_redirects=False, timeout=10) as client:
        index = client.get(base)
        for path in RECON_PATHS + (extra_paths or []):
            try:
                r = client.get(urllib.parse.urljoin(base, path))
            except httpx.HTTPError as exc:
                found.append({"path": path, "error": str(exc)})
                continue
            if r.status_code != 404:
                found.append({"path": path, "status": r.status_code, "length": len(r.content),
                              "location": r.headers.get("location", ""),
                              "start": clip(to_text(r.content[:200]), 200), "flags": find_flags(r.content)})
    tech = {k: v for k, v in index.headers.items()
            if k.lower() in ("server", "x-powered-by", "set-cookie", "x-aspnet-version", "via")}
    out = {"index_status": index.status_code, "tech_headers": tech, "paths": found,
           "flags": find_flags(index.content) + [f for x in found for f in x.get("flags", [])]}
    out.update(_html_findings(index.text))
    if any(x["path"].startswith(".git") and x.get("status") == 200 for x in found):
        out["hint"] = "Exposed .git: dump it with git-dumper (pip install git-dumper) via run_python, then read history."
    if warning:
        out["scope_warning"] = warning
    return out


def tcp_exchange(host: str, port: int, send: list[str] | None = None, read_timeout: float = 3.0,
                 use_tls: bool = False, append_newline: bool = True) -> dict:
    """Talk to an in-scope netcat-style service: connect, read the banner, then send each
    line in `send` and capture the reply. For multi-round puzzles where each answer depends
    on the last prompt, write a pwntools/socket script with run_python instead."""
    warning = check_scope(host)
    sock = socket.create_connection((host, port), timeout=10)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.settimeout(read_timeout)

    def read_all() -> bytes:
        buf = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            buf += chunk
        return buf

    transcript = [{"recv": to_text(read_all())}]
    try:
        for line in send or []:
            data = line.encode("latin-1") + (b"\n" if append_newline and not line.endswith("\n") else b"")
            sock.sendall(data)
            transcript.append({"sent": line, "recv": to_text(read_all())})
    finally:
        sock.close()
    out = {"transcript": transcript, "flags": find_flags(json.dumps(transcript))}
    if warning:
        out["scope_warning"] = warning
    return out


def dns_lookup(host: str) -> dict:
    """Resolve a hostname (A/AAAA) and reverse-resolve IPs. Use run_tool with dig for TXT/MX/AXFR."""
    out: dict = {"host": host}
    try:
        out["addresses"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        out["error"] = str(exc)
        return out
    reverse = {}
    for ip in out["addresses"][:5]:
        try:
            reverse[ip] = socket.gethostbyaddr(ip)[0]
        except OSError:
            reverse[ip] = None
    out["reverse"] = reverse
    return out


# --------------------------------------------------------------------------- JWT

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def jwt_decode(token: str) -> dict:
    """Decode a JWT's header and payload (no verification) and point out weaknesses to try."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    alg = str(header.get("alg", ""))
    hints = []
    if alg in HMAC_ALGS:
        hints.append("HMAC-signed: try jwt_crack for a weak secret, then jwt_forge.")
    if alg.upper() == "NONE" or not (parts[2:] and parts[2]):
        hints.append("Unsigned token: the server may accept forged payloads.")
    if alg.startswith(("RS", "ES", "PS")):
        hints.append("Asymmetric: try alg=none, or algorithm confusion (sign HS256 with the public key as secret).")
    for k in ("kid", "jku", "x5u", "jwk"):
        if k in header:
            hints.append(f"Header has {k!r}: may be injectable (path traversal / SQLi in kid, attacker URL in jku/x5u).")
    for k in ("exp", "iat", "nbf"):
        if isinstance(payload.get(k), (int, float)):
            payload[f"{k}_readable"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(payload[k]))
    return {"header": header, "payload": payload, "signature_hex": _b64url_decode(parts[2]).hex() if len(parts) > 2 and parts[2] else "",
            "hints": hints, "flags": find_flags(json.dumps(payload))}


def jwt_crack(token: str, wordlist: str = "", words: list[str] | None = None, time_limit: int = 120) -> dict:
    """Dictionary attack the secret of an HS256/384/512 JWT."""
    from .crypto import iter_words

    head, body, sig = token.strip().split(".")
    alg = json.loads(_b64url_decode(head)).get("alg")
    if alg not in HMAC_ALGS:
        raise ValueError(f"alg {alg} is not HMAC; nothing to crack")
    target = _b64url_decode(sig)
    msg = f"{head}.{body}".encode()
    digest = HMAC_ALGS[alg]
    deadline = time.monotonic() + time_limit
    tried = 0
    for word in iter_words(wordlist, (words or []) + ["secret", "key", "jwt", "secretkey", "your-256-bit-secret",
                                                      "changeme", "supersecret", "s3cr3t", "jwtsecret"]):
        tried += 1
        if hmac.compare_digest(hmac.new(word.encode("latin-1", "replace"), msg, digest).digest(), target):
            return {"cracked": True, "secret": word, "tried": tried}
        if tried % 50_000 == 0 and time.monotonic() > deadline:
            break
    return {"cracked": False, "tried": tried}


def jwt_forge(payload: dict, secret: str = "", alg: str = "HS256", header_extra: dict | None = None) -> dict:
    """Build a JWT with any payload. alg "none" produces an unsigned token; HS* signs with secret
    (for algorithm confusion, pass the server's PEM public key as the secret)."""
    header = {"alg": alg, "typ": "JWT", **(header_extra or {})}
    signing_input = _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64url(json.dumps(payload, separators=(",", ":")).encode())
    if alg.lower() == "none":
        return {"token": signing_input + ".", "variants": [signing_input + ".", signing_input]}
    if alg not in HMAC_ALGS:
        raise ValueError("Only none and HS256/384/512 are supported")
    sig = hmac.new(secret.encode(), signing_input.encode(), HMAC_ALGS[alg]).digest()
    return {"token": signing_input + "." + _b64url(sig)}


TOOLS = [http_request, web_recon, tcp_exchange, dns_lookup, jwt_decode, jwt_crack, jwt_forge]
