"""Minimal Challenge Desk — beginner upload + coach visibility.

Browser UI (not a full agent chat). Players paste their bearer token, name a
challenge, upload files. Coach token sees every player's challenges and recent
tool activity. MCP solving still happens in Claude/Cursor.
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from .audit import audit
from .auth import StaticBearerVerifier, sanitize_label
from .common import workspace_root
from .config import http_host, http_path, http_port, public_base_url

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # 32 MiB per file
_MAX_FILES = 20


def coach_token() -> str | None:
    raw = os.environ.get("CTF_MCP_COACH_TOKEN", "").strip()
    return raw or None


def _base_url() -> str:
    return public_base_url() or f"http://{http_host()}:{http_port()}"


def _mcp_url() -> str:
    return f"{_base_url()}{http_path()}"


def _slug(name: str) -> str:
    base = _SAFE_NAME.sub("-", name.strip().lower()).strip("-._")[:48] or "challenge"
    return f"{base}-{secrets.token_hex(3)}"


def _user_challenges_dir(label: str) -> Path:
    path = workspace_root() / "users" / sanitize_label(label) / "challenges"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _shared_challenges_dir() -> Path:
    path = workspace_root() / "shared" / "challenges"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _extract_bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    # Browser forms / fetch can send token in header X-CTF-Token or cookie.
    hdr = request.headers.get("x-ctf-token")
    if hdr and hdr.strip():
        return hdr.strip()
    return request.cookies.get("ctf_mcp_token") or None


async def resolve_desk_principal(
    request: Request,
    verifier: StaticBearerVerifier,
) -> dict[str, Any] | None:
    """Return {label, is_coach} if the request bears a valid token."""
    token = _extract_bearer(request)
    if not token:
        return None
    coach = coach_token()
    if coach and secrets.compare_digest(token, coach):
        return {"label": "coach", "is_coach": True, "token": token}
    access = await verifier.verify_token(token)
    if access is None:
        return None
    return {"label": access.client_id, "is_coach": False, "token": token}


def list_challenges_for(label: str) -> list[dict[str, Any]]:
    root = _user_challenges_dir(label)
    return _read_challenge_metas(root, owner=label)


def list_shared_challenges() -> list[dict[str, Any]]:
    return _read_challenge_metas(_shared_challenges_dir(), owner="shared")


def list_all_challenges() -> list[dict[str, Any]]:
    """Coach view: every user + shared challenges, newest first."""
    items: list[dict[str, Any]] = []
    items.extend(list_shared_challenges())
    users_root = workspace_root() / "users"
    if users_root.is_dir():
        for user_dir in sorted(users_root.iterdir()):
            if user_dir.is_dir():
                items.extend(list_challenges_for(user_dir.name))
    items.sort(key=lambda m: m.get("uploaded_at", ""), reverse=True)
    return items


def _read_challenge_metas(root: Path, *, owner: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for chal in sorted(root.iterdir(), reverse=True):
        meta_path = chal / "meta.json"
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        meta.setdefault("id", chal.name)
        meta.setdefault("owner", owner)
        meta["path"] = str(chal.relative_to(workspace_root()))
        out.append(meta)
    return out


def save_challenge(
    *,
    owner: str,
    title: str,
    category: str,
    description: str,
    files: list[tuple[str, bytes]],
    shared: bool = False,
) -> dict[str, Any]:
    if not title.strip():
        raise ValueError("Challenge title is required")
    if not files:
        raise ValueError("Upload at least one file")
    if len(files) > _MAX_FILES:
        raise ValueError(f"Too many files (max {_MAX_FILES})")

    chal_id = _slug(title)
    root = _shared_challenges_dir() if shared else _user_challenges_dir(owner)
    dest = root / chal_id
    files_dir = dest / "files"
    files_dir.mkdir(parents=True, exist_ok=False)

    saved: list[dict[str, Any]] = []
    for name, data in files:
        safe = Path(name).name
        safe = _SAFE_NAME.sub("_", safe).strip("._") or "file.bin"
        if len(data) > _MAX_UPLOAD_BYTES:
            raise ValueError(f"{safe} exceeds {_MAX_UPLOAD_BYTES} byte limit")
        path = files_dir / safe
        path.write_bytes(data)
        saved.append({"name": safe, "bytes": len(data)})

    meta = {
        "id": chal_id,
        "title": title.strip()[:120],
        "category": (category or "misc").strip()[:40],
        "description": (description or "").strip()[:2000],
        "owner": "shared" if shared else owner,
        "uploaded_by": owner,
        "uploaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": saved,
        "rel_dir": str(dest.relative_to(workspace_root())),
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    audit(
        "challenge_upload",
        owner=meta["owner"],
        challenge_id=chal_id,
        title=meta["title"],
        files=[f["name"] for f in saved],
    )
    return meta


def recent_activity(limit: int = 80) -> list[dict[str, Any]]:
    """Tail CTF_MCP_AUDIT_LOG for coach visibility (best-effort)."""
    path = os.environ.get("CTF_MCP_AUDIT_LOG", "").strip()
    if not path:
        # Default under workspace so compose always has something to show.
        path = str(workspace_root() / "audit.jsonl")
    p = Path(path)
    if not p.is_file():
        return []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    events.reverse()
    return events


def list_players() -> list[dict[str, Any]]:
    """Coach roster from users/ dirs + challenge counts."""
    users_root = workspace_root() / "users"
    players: list[dict[str, Any]] = []
    if not users_root.is_dir():
        return players
    for user_dir in sorted(users_root.iterdir()):
        if not user_dir.is_dir():
            continue
        chals = list_challenges_for(user_dir.name)
        players.append(
            {
                "label": user_dir.name,
                "challenges": len(chals),
                "latest": chals[0]["uploaded_at"] if chals else None,
            }
        )
    return players


def desk_html(*, mcp_url: str, error: str = "", flash: str = "") -> str:
    """Single-page desk: player upload + connect, coach panel."""
    err = f'<p class="flash err">{html.escape(error)}</p>' if error else ""
    ok = f'<p class="flash ok">{html.escape(flash)}</p>' if flash else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ctf-mcp Challenge Desk</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Serif:wght@500;600&display=swap" rel="stylesheet"/>
  <style>
    :root {{
      --ink:#152033; --muted:#5a6578; --line:#cfd6e4; --paper:#fff;
      --bg0:#e7eef8; --bg1:#f4f6fa; --bg2:#e6f2ec; --accent:#0a4fd6; --ok:#0d7a4f; --err:#b42318;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; min-height:100vh; color:var(--ink);
      font-family:"IBM Plex Sans", system-ui, sans-serif;
      background:
        radial-gradient(900px 420px at 10% -10%, var(--bg0), transparent 60%),
        radial-gradient(700px 380px at 100% 0%, var(--bg2), transparent 55%),
        linear-gradient(180deg, var(--bg1), #eef1f6 70%);
    }}
    main {{ max-width:52rem; margin:0 auto; padding:2.25rem 1.15rem 4rem; }}
    h1 {{ font-family:"IBM Plex Serif", Georgia, serif; font-size:clamp(1.8rem,4vw,2.35rem); margin:0 0 .25rem; }}
    .lede {{ color:var(--muted); max-width:38rem; line-height:1.45; margin:0 0 1.5rem; }}
    nav {{ display:flex; gap:.5rem; flex-wrap:wrap; margin:0 0 1.25rem; }}
    nav button {{
      border:1px solid var(--line); background:rgba(255,255,255,.7); color:var(--ink);
      border-radius:6px; padding:.45rem .85rem; font:500 .9rem "IBM Plex Sans", sans-serif; cursor:pointer;
    }}
    nav button.active {{ background:var(--ink); color:#fff; border-color:var(--ink); }}
    section {{ display:none; }}
    section.active {{ display:block; }}
    .panel {{
      background:var(--paper); border:1px solid var(--line); border-radius:10px;
      padding:1.1rem 1.15rem; margin:0 0 1rem;
    }}
    .panel h2 {{ font-size:1.05rem; margin:0 0 .75rem; }}
    label {{ display:block; font-size:.78rem; letter-spacing:.03em; text-transform:uppercase; color:var(--muted); margin:.65rem 0 .3rem; }}
    input[type=text], input[type=password], textarea, select {{
      width:100%; border:1px solid var(--line); border-radius:6px; padding:.55rem .65rem;
      font:400 .95rem "IBM Plex Sans", sans-serif; background:#fbfcfe;
    }}
    textarea {{ min-height:4.5rem; resize:vertical; }}
    input[type=file] {{ width:100%; margin-top:.25rem; }}
    .row {{ display:grid; gap:.75rem; grid-template-columns:1fr; }}
    @media (min-width:640px) {{ .row.two {{ grid-template-columns:1fr 1fr; }} }}
    .actions {{ display:flex; gap:.6rem; flex-wrap:wrap; margin-top:1rem; }}
    button.primary, .actions button {{
      border:0; border-radius:6px; padding:.6rem 1rem; cursor:pointer;
      font:600 .92rem "IBM Plex Sans", sans-serif; background:var(--accent); color:#fff;
    }}
    button.ghost {{ background:transparent; color:var(--ink); border:1px solid var(--line); }}
    pre, code {{ font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:.82rem; }}
    pre {{
      margin:.35rem 0 0; padding:.75rem .8rem; background:#0f1724; color:#e8eef8;
      border-radius:6px; overflow:auto; white-space:pre-wrap; word-break:break-word;
    }}
    .hint {{ color:var(--muted); font-size:.9rem; line-height:1.4; }}
    .flash {{ border-radius:6px; padding:.65rem .8rem; margin:0 0 1rem; }}
    .flash.ok {{ background:#e6f6ee; color:var(--ok); }}
    .flash.err {{ background:#fdecea; color:var(--err); }}
    table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
    th, td {{ text-align:left; padding:.45rem .35rem; border-bottom:1px solid var(--line); vertical-align:top; }}
    th {{ color:var(--muted); font-weight:500; font-size:.75rem; text-transform:uppercase; letter-spacing:.03em; }}
    .empty {{ color:var(--muted); font-style:italic; }}
    .pill {{ display:inline-block; padding:.1rem .45rem; border-radius:999px; background:#eef2ff; font-size:.75rem; }}
  </style>
</head>
<body>
<main>
  <h1>ctf-mcp</h1>
  <p class="lede">Load a challenge, connect Claude or Cursor, solve. Coach can watch uploads and tool activity. Private Tailscale / lab use — not the public internet.</p>
  {err}{ok}
  <nav>
    <button type="button" class="active" data-tab="play">Player</button>
    <button type="button" data-tab="coach">Coach</button>
    <button type="button" data-tab="connect">Connect MCP</button>
  </nav>

  <section id="tab-play" class="active">
    <div class="panel">
      <h2>1. Your team token</h2>
      <p class="hint">Paste the token Josh gave you. It stays in this browser (local storage) and is sent only to this server.</p>
      <label for="token">Bearer token</label>
      <input id="token" type="password" autocomplete="off" placeholder="paste token"/>
      <div class="actions">
        <button type="button" class="primary" id="save-token">Save token</button>
        <button type="button" class="ghost" id="clear-token">Clear</button>
      </div>
      <p class="hint" id="whoami"></p>
    </div>
    <div class="panel">
      <h2>2. Upload a challenge</h2>
      <p class="hint">Drop the zip, binary, pcap, image, or notes the challenge gave you. Then open Claude/Cursor with the MCP connected and ask it to triage these files.</p>
      <form id="upload-form">
        <label for="title">Challenge name</label>
        <input id="title" name="title" type="text" required placeholder="e.g. Easy RSA"/>
        <div class="row two">
          <div>
            <label for="category">Category</label>
            <select id="category" name="category">
              <option>misc</option><option>crypto</option><option>forensics</option>
              <option>stego</option><option>reversing</option><option>pwn</option>
              <option>web</option><option>osint</option>
            </select>
          </div>
          <div>
            <label for="shared">Visibility</label>
            <select id="shared" name="shared">
              <option value="0">Just my folder</option>
              <option value="1">Shared team inbox</option>
            </select>
          </div>
        </div>
        <label for="description">Short description (optional)</label>
        <textarea id="description" name="description" placeholder="prompt text, host:port, anything useful"></textarea>
        <label for="files">Files</label>
        <input id="files" name="files" type="file" multiple required/>
        <div class="actions">
          <button type="submit" class="primary">Upload</button>
        </div>
      </form>
    </div>
    <div class="panel">
      <h2>3. Your challenges</h2>
      <div id="my-challenges"><p class="empty">Save a token to list your uploads.</p></div>
    </div>
  </section>

  <section id="tab-coach">
    <div class="panel">
      <h2>Coach sign-in</h2>
      <p class="hint">Use the coach token (<code>CTF_MCP_COACH_TOKEN</code>). Same paste field as players — save it above, then refresh this view.</p>
      <div class="actions">
        <button type="button" class="primary" id="refresh-coach">Refresh visibility</button>
      </div>
    </div>
    <div class="panel">
      <h2>Players</h2>
      <div id="coach-players"><p class="empty">Coach token required.</p></div>
    </div>
    <div class="panel">
      <h2>All challenges</h2>
      <div id="coach-challenges"><p class="empty">Coach token required.</p></div>
    </div>
    <div class="panel">
      <h2>Recent activity</h2>
      <p class="hint">Tool calls and uploads from the audit log (hosted mode).</p>
      <div id="coach-activity"><p class="empty">Coach token required.</p></div>
    </div>
  </section>

  <section id="tab-connect">
    <div class="panel">
      <h2>MCP URL</h2>
      <pre>{html.escape(mcp_url)}</pre>
      <p class="hint">Header: <code>Authorization: Bearer &lt;your token&gt;</code></p>
    </div>
    <div class="panel">
      <h2>Claude Code</h2>
      <pre>claude mcp add ctf-solver --transport http \\
  --url {html.escape(mcp_url)} \\
  --header "Authorization: Bearer $CTF_MCP_TOKEN"</pre>
    </div>
    <div class="panel">
      <h2>Cursor</h2>
      <pre>{{
  "mcpServers": {{
    "ctf-solver": {{
      "url": "{html.escape(mcp_url)}",
      "headers": {{ "Authorization": "Bearer YOUR_TOKEN" }}
    }}
  }}
}}</pre>
    </div>
    <div class="panel">
      <h2>After upload — what to tell Claude</h2>
      <pre>Use ctf-mcp. My challenge files are under the workspace path shown after upload.
Start with toolchain_status, then file_triage on each file, then solve.</pre>
    </div>
  </section>
</main>
<script>
const mcpUrl = {json.dumps(mcp_url)};
const tokenEl = document.getElementById('token');
const who = document.getElementById('whoami');

function token() {{ return localStorage.getItem('ctf_mcp_token') || ''; }}
function setToken(v) {{
  if (v) localStorage.setItem('ctf_mcp_token', v); else localStorage.removeItem('ctf_mcp_token');
  tokenEl.value = v || '';
}}
tokenEl.value = token();

document.querySelectorAll('nav button').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  }});
}});

async function api(path, opts={{}}) {{
  const headers = Object.assign({{}}, opts.headers || {{}});
  const t = token();
  if (t) headers['Authorization'] = 'Bearer ' + t;
  const res = await fetch(path, Object.assign({{}}, opts, {{ headers }}));
  const data = await res.json().catch(() => ({{}}));
  if (!res.ok) throw new Error(data.error || res.statusText || 'request failed');
  return data;
}}

function renderChallenges(el, items) {{
  if (!items.length) {{ el.innerHTML = '<p class="empty">No challenges yet.</p>'; return; }}
  el.innerHTML = '<table><thead><tr><th>Title</th><th>Owner</th><th>Category</th><th>Files</th><th>When</th><th>Workspace path</th></tr></thead><tbody>' +
    items.map(c => `<tr>
      <td><strong>${{escapeHtml(c.title)}}</strong><div class="hint">${{escapeHtml(c.description||'')}}</div></td>
      <td><span class="pill">${{escapeHtml(c.owner)}}</span></td>
      <td>${{escapeHtml(c.category||'')}}</td>
      <td>${{(c.files||[]).map(f=>escapeHtml(f.name)).join(', ')}}</td>
      <td>${{escapeHtml(c.uploaded_at||'')}}</td>
      <td><code>${{escapeHtml(c.rel_dir||c.path||'')}}</code></td>
    </tr>`).join('') + '</tbody></table>';
}}

function escapeHtml(s) {{
  return String(s).replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[ch]);
}}

async function refreshMe() {{
  if (!token()) {{ who.textContent = ''; document.getElementById('my-challenges').innerHTML = '<p class="empty">Save a token to list your uploads.</p>'; return; }}
  try {{
    const me = await api('/api/me');
    who.textContent = me.is_coach ? 'Signed in as coach (full visibility).' : ('Signed in as ' + me.label + '.');
    const list = await api('/api/challenges');
    renderChallenges(document.getElementById('my-challenges'), list.challenges || []);
  }} catch (e) {{
    who.textContent = 'Token not accepted: ' + e.message;
  }}
}}

async function refreshCoach() {{
  const players = document.getElementById('coach-players');
  const chals = document.getElementById('coach-challenges');
  const act = document.getElementById('coach-activity');
  try {{
    const data = await api('/api/coach/overview');
    if (!data.players.length) players.innerHTML = '<p class="empty">No player folders yet.</p>';
    else players.innerHTML = '<table><thead><tr><th>Player</th><th>Challenges</th><th>Latest upload</th></tr></thead><tbody>' +
      data.players.map(p => `<tr><td>${{escapeHtml(p.label)}}</td><td>${{p.challenges}}</td><td>${{escapeHtml(p.latest||'—')}}</td></tr>`).join('') + '</tbody></table>';
    renderChallenges(chals, data.challenges || []);
    if (!(data.activity||[]).length) act.innerHTML = '<p class="empty">No audit lines yet. Tool use will show up here.</p>';
    else act.innerHTML = '<table><thead><tr><th>Time</th><th>Event</th><th>Caller</th><th>Detail</th></tr></thead><tbody>' +
      data.activity.map(a => `<tr><td>${{escapeHtml(a.ts||'')}}</td><td>${{escapeHtml(a.event||'')}}</td><td>${{escapeHtml(a.caller||'')}}</td><td><code>${{escapeHtml(JSON.stringify(a.tool || a.title || a.error || a.args || ''))}}</code></td></tr>`).join('') + '</tbody></table>';
  }} catch (e) {{
    players.innerHTML = chals.innerHTML = act.innerHTML = '<p class="empty">' + escapeHtml(e.message) + '</p>';
  }}
}}

document.getElementById('save-token').onclick = () => {{ setToken(tokenEl.value.trim()); refreshMe(); }};
document.getElementById('clear-token').onclick = () => {{ setToken(''); refreshMe(); }};
document.getElementById('refresh-coach').onclick = () => refreshCoach();

document.getElementById('upload-form').addEventListener('submit', async (ev) => {{
  ev.preventDefault();
  if (!token()) {{ alert('Save your token first'); return; }}
  const fd = new FormData();
  fd.append('title', document.getElementById('title').value);
  fd.append('category', document.getElementById('category').value);
  fd.append('description', document.getElementById('description').value);
  fd.append('shared', document.getElementById('shared').value);
  for (const f of document.getElementById('files').files) fd.append('files', f);
  try {{
    const res = await fetch('/api/challenges', {{ method:'POST', headers: {{ 'Authorization': 'Bearer ' + token() }}, body: fd }});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'upload failed');
    alert('Uploaded. Workspace path: ' + data.challenge.rel_dir + '\\n\\nConnect MCP, then ask Claude to triage files under that path.');
    document.getElementById('upload-form').reset();
    refreshMe();
  }} catch (e) {{ alert(e.message); }}
}});

refreshMe();
</script>
</body>
</html>"""


def register_desk_routes(server: MCPServer, verifier: StaticBearerVerifier) -> None:
    """Attach desk + JSON API routes to an MCPServer (custom_route = no SDK auth wrap)."""

    @server.custom_route("/", methods=["GET"])
    @server.custom_route("/desk", methods=["GET"])
    @server.custom_route("/connect", methods=["GET"])
    async def desk_home(_request: Request) -> Response:
        return HTMLResponse(desk_html(mcp_url=_mcp_url()))

    @server.custom_route("/api/me", methods=["GET"])
    async def api_me(request: Request) -> Response:
        principal = await resolve_desk_principal(request, verifier)
        if principal is None:
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        return JSONResponse(
            {"label": principal["label"], "is_coach": principal["is_coach"], "mcp_url": _mcp_url()}
        )

    @server.custom_route("/api/challenges", methods=["GET"])
    async def api_list_challenges(request: Request) -> Response:
        principal = await resolve_desk_principal(request, verifier)
        if principal is None:
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        if principal["is_coach"]:
            challenges = list_all_challenges()
        else:
            challenges = list_challenges_for(principal["label"]) + list_shared_challenges()
        return JSONResponse({"challenges": challenges})

    @server.custom_route("/api/challenges", methods=["POST"])
    async def api_upload(request: Request) -> Response:
        principal = await resolve_desk_principal(request, verifier)
        if principal is None:
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        form = await request.form()
        title = str(form.get("title") or "")
        category = str(form.get("category") or "misc")
        description = str(form.get("description") or "")
        shared = str(form.get("shared") or "0") in ("1", "true", "on", "yes")
        # Coach uploads go to the shared inbox when "shared" is selected; otherwise coach folder.
        owner = "coach" if principal["is_coach"] else principal["label"]
        uploads: list[tuple[str, bytes]] = []
        for entry in form.getlist("files"):
            filename = getattr(entry, "filename", None) or "file.bin"
            data = await entry.read()  # type: ignore[union-attr]
            uploads.append((str(filename), data))
        try:
            meta = save_challenge(
                owner=owner,
                title=title,
                category=category,
                description=description,
                files=uploads,
                shared=shared,
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except FileExistsError:
            return JSONResponse({"error": "challenge id collision; retry"}, status_code=409)
        return JSONResponse({"challenge": meta})

    @server.custom_route("/api/coach/overview", methods=["GET"])
    async def api_coach(request: Request) -> Response:
        principal = await resolve_desk_principal(request, verifier)
        if principal is None:
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        if not principal["is_coach"]:
            return JSONResponse({"error": "Coach token required"}, status_code=403)
        return JSONResponse(
            {
                "players": list_players(),
                "challenges": list_all_challenges(),
                "activity": recent_activity(),
            }
        )
