# Team remote MCP + Challenge Desk (Phase 2)

Private **streamable-http** MCP with **bearer tokens**, plus a beginner-friendly **Challenge Desk** in the browser. Defaults assume Tailscale / campus VLAN — not a public internet deploy.

Players upload challenge files in the desk; Claude/Cursor still does the solving over MCP. Josh (coach) uses a separate coach token to see every player’s uploads and recent tool activity.

## Quick start (Docker Compose)

```bash
cp .env.example .env
# set CTF_MCP_AUTH_TOKEN (or per-player CTF_MCP_AUTH_TOKENS)
# set CTF_MCP_COACH_TOKEN for coach visibility
# optional: CTF_MCP_PUBLIC_URL=http://<tailscale-ip>:8765
docker compose up --build
```

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8765/` | Challenge Desk (upload + coach tabs) |
| `http://127.0.0.1:8765/health` | Health JSON |
| `http://127.0.0.1:8765/mcp` | MCP endpoint (Bearer required) |

Compose publishes **127.0.0.1:8765** only. Run Tailscale on the host and give teammates the Tailscale IP, or adjust `ports:` + `CTF_MCP_ALLOWED_HOSTS`.

## Player flow (beginner)

1. Open the desk URL; paste the token Josh gave you; **Save token**.
2. Name the challenge, pick a category, attach the zip/binary/pcap/image, **Upload**.
3. Optional: “Shared team inbox” so everyone sees that challenge.
4. Open **Connect MCP**, configure Claude Code or Cursor with the same token.
5. Tell Claude: *triage the files under the workspace path shown after upload* (e.g. `users/alice/challenges/warmup-a1b2c3/files/...`).

## Coach flow (Josh)

1. Set `CTF_MCP_COACH_TOKEN` in `.env` (different from player tokens).
2. In the desk, paste the **coach** token → **Coach** tab → **Refresh visibility**.
3. See: player roster, all challenges (every user + shared), recent audit activity (uploads + tool calls).

Per-player tokens (`CTF_MCP_AUTH_TOKENS=alice:…,bob:…`) give each student their own `users/<name>/` folder. A single shared `CTF_MCP_AUTH_TOKEN` puts everyone under `users/team/`.

## Without Docker

```bash
python -m venv .venv && .venv/bin/pip install -e .
export CTF_MCP_HOSTED=1
export CTF_MCP_TRANSPORT=streamable-http
export CTF_MCP_HOST=127.0.0.1 CTF_MCP_PORT=8765
export CTF_MCP_AUTH_TOKENS="alice:$(openssl rand -hex 16),bob:$(openssl rand -hex 16)"
export CTF_MCP_COACH_TOKEN="$(openssl rand -hex 16)"
export CTF_WORKSPACE="$PWD/data/workspaces"
.venv/bin/ctf-mcp
```

## Client config

### Claude Code

```bash
export CTF_MCP_TOKEN='…player token…'
claude mcp add ctf-solver --transport http \
  --url http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $CTF_MCP_TOKEN"
```

### Cursor / generic HTTP MCP

```json
{
  "mcpServers": {
    "ctf-solver": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  }
}
```

## Auth & isolation

| Variable | Purpose |
|---|---|
| `CTF_MCP_AUTH_TOKEN` | Single shared bearer → client id `team` |
| `CTF_MCP_AUTH_TOKENS` | `alice:secret,bob:secret` → per-player folders |
| `CTF_MCP_COACH_TOKEN` | Coach desk overview (not an MCP tool principal unless also listed above) |
| `CTF_MCP_ISOLATE_SESSIONS` | Hosted default **on** → `CTF_WORKSPACE/users/<label>/` |
| `CTF_MCP_HOSTED` | Auto-set for HTTP if unset; disables `run_python` by default |

HTTP without player token config **exits**. Binding `0.0.0.0` warns; prefer loopback or Tailscale IP.

## Safety (hosted)

Path jail locked, `run_python` off, `ALLOW_ANY_TOOL` denied, factordb default off, audit on (JSONL under the workspace for the coach tab). Re-enable exec only with `CTF_MCP_DISABLE_EXEC=0` **and** `CTF_MCP_UNSAFE_EXEC=1` (lab break-glass).

## Follow-ups

- Richer Challenge Desk (event profiles, flag board, live session list)
- TLS / campus DNS + Marshall SSO or GitHub OIDC
- Real container sandbox for `run_python`
- Curated Kali-tool image beyond the slim Dockerfile

## Laptop stdio

Unchanged: `./scripts/install.sh` and `ctf-mcp` with no `--transport` still speak stdio for Claude Desktop.
