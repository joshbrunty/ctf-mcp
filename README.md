# ctf-mcp

An [MCP](https://modelcontextprotocol.io) server that gives an AI assistant a CTF toolkit: 47
tools across crypto, forensics/stego, reversing/pwn and web, plus a guided `solve_challenge`
prompt. Works with Claude (Desktop or Code) and GitHub Copilot (VS Code agent mode or Copilot
CLI). Built for the Marshall University cyber team.

Most tools are pure Python, so a fresh laptop works without Kali. When `binwalk`, `exiftool`,
`tshark`, `john`, `r2` and similar are installed, Claude can also call them through `run_tool`.

> **Check the event rules first.** Many competitions (NCL, CCDC, plenty of CTFtime events)
> restrict or ban AI assistance. Only use this where the rules allow it.

## Install

Requires Python 3.10+.

**macOS / Linux**

```bash
git clone https://github.com/joshbrunty/ctf-mcp.git && cd ctf-mcp
./scripts/install.sh          # add --pwn to also install pwntools
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/joshbrunty/ctf-mcp.git; cd ctf-mcp
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

The installer creates `.venv` and registers the server with every supported client it can:

- **Claude Code**: `claude mcp add --scope user`, if the `claude` CLI is installed.
- **Claude Desktop**: adds it to the app's config, if Claude Desktop is installed.
- **GitHub Copilot**: adds it to `~/.copilot/mcp-config.json`, which both VS Code and Copilot
  CLI read.

Existing config files are backed up as `.bak`. Restart Claude Desktop or VS Code afterwards.

**Using it from Copilot in VS Code:** open Copilot Chat, switch the mode to **Agent**, and
check that `ctf-solver` is ticked in the tools picker. VS Code asks before each tool runs.

**ChatGPT** can't use this install: it only connects to MCP servers on the public internet over
HTTPS, with OAuth or no sign-in. Students without Claude should use Copilot in VS Code.

### Manual setup

Claude Code:

```bash
claude mcp add ctf-solver --scope user -e CTF_WORKSPACE=$HOME/ctf-workspace -- /full/path/to/ctf-mcp/.venv/bin/ctf-mcp
```

Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "ctf-solver": {
      "command": "/full/path/to/ctf-mcp/.venv/bin/ctf-mcp",
      "env": {
        "CTF_WORKSPACE": "/Users/you/ctf-workspace",
        "CTF_FLAG_REGEX": "MUCTF\\{[^}]+\\}",
        "CTF_SCOPE": "*.ctf.example.edu,10.10.0.0/16"
      }
    }
  }
}
```

On Windows the command is `C:\\path\\to\\ctf-mcp\\.venv\\Scripts\\ctf-mcp.exe`.

GitHub Copilot (VS Code and Copilot CLI): `~/.copilot/mcp-config.json`
(`%USERPROFILE%\.copilot\mcp-config.json` on Windows):

```json
{
  "mcpServers": {
    "ctf-solver": {
      "type": "stdio",
      "command": "/full/path/to/ctf-mcp/.venv/bin/ctf-mcp",
      "args": [],
      "env": { "CTF_WORKSPACE": "/Users/you/ctf-workspace" },
      "tools": ["*"]
    }
  }
}
```

Or with Copilot CLI: `copilot mcp add ctf-solver --env CTF_WORKSPACE=$HOME/ctf-workspace -- /full/path/to/ctf-mcp/.venv/bin/ctf-mcp`.

To connect VS Code to the team server instead (see Team remote below), run **MCP: Open User
Configuration** from the Command Palette and add the following. VS Code prompts for the token
once and stores it securely:

```json
{
  "inputs": [
    { "id": "ctf-token", "type": "promptString", "description": "ctf-mcp player token", "password": true }
  ],
  "servers": {
    "ctf-solver": {
      "type": "http",
      "url": "http://<team-server>:8765/mcp",
      "headers": { "Authorization": "Bearer ${input:ctf-token}" }
    }
  }
}
```

## Competition-day checklist

1. **Set the flag format** with `CTF_FLAG_REGEX`, e.g. `picoCTF\{[^}]+\}`. Every tool reports
   matches in a `flags` field. The default matches anything shaped like `word{...}`.
2. **Set the scope** with `CTF_SCOPE`: comma-separated hostnames, `*.domain` wildcards, IPs
   or CIDRs from the rules. `http_request`, `web_recon`, `tcp_exchange` and `dns_lookup` refuse
   anything outside it; HTTP redirects are re-checked per hop. With no scope set they allow any
   host and warn about it.
3. Put challenge files in the workspace (default `~/ctf-workspace`). Relative paths resolve
   there; absolute paths outside the workspace are rejected (path jail). Carved files, fixed
   images, extracted archives and solver scripts are written there.
4. Run `toolchain_status` once to see which optional CLI tools are missing.
5. Start a challenge with the **solve_challenge** prompt (Claude Desktop: the "+" menu →
   ctf-solver; Claude Code: `/mcp__ctf-solver__solve_challenge`; Copilot in VS Code: type `/`
   in Agent mode and pick ctf-solver's solve_challenge), or just paste the challenge and point
   at the file.

Restart Claude Desktop after changing `env`. For Claude Code, re-run `claude mcp add` with
new `-e` values. For Copilot, edit `env` in `~/.copilot/mcp-config.json` and restart VS Code.

| Variable | Default | Purpose |
|---|---|---|
| `CTF_WORKSPACE` | `~/ctf-workspace` | Where inputs are looked up and outputs written |
| `CTF_FLAG_REGEX` | `word{...}` | The event's flag format |
| `CTF_SCOPE` | unset (any host) | Hosts/CIDRs the network tools may contact |
| `CTF_SCOPE_VERIFY_IPS` | off locally / on when hosted | Require hostname targets to resolve inside scope CIDRs |
| `CTF_WORDLIST` | rockyou.txt if found | Wordlist for hash/zip/JWT cracking |
| `CTF_MCP_DISABLE_EXEC` | unset (off locally) | `1` disables `run_python`; hosted defaults to disabled |
| `CTF_MCP_ALLOW_ANY_TOOL` | unset | `1` lets `run_tool` run binaries outside the allowlist (denied when hosted) |
| `CTF_MCP_ALLOW_FACTORDB` | on locally / off when hosted | Default for `rsa_solve` factordb lookups |
| `CTF_MCP_ALLOW_HOST_PATHS` | unset | `1` allows absolute paths outside the workspace (ignored when hosted) |
| `CTF_MCP_HOSTED` | unset | Stricter shared-host profile (see below) |
| `CTF_MCP_AUDIT` | off locally / on when hosted | JSON audit lines on stderr / `CTF_MCP_AUDIT_LOG` |
| `CTF_MCP_TRANSPORT` | `stdio` | `streamable-http` enables remote MCP (auth required) |
| `CTF_MCP_AUTH_TOKEN` | unset | Bearer secret for remote transport |

## Tools

**Crypto & encoding**: `auto_decode` (recursive base64/32/58/85, hex, binary, decimal, octal,
URL, HTML, morse, plus rot/atbash/Caesar), `transform` (CyberChef-style chains),
`caesar_bruteforce`, `vigenere`, `vigenere_crack`, `frequency_analysis`, `xor_data`,
`xor_crack` (single-byte, repeating-key, known-plaintext), `hash_identify`, `hash_crack`,
`rsa_solve` (small e, trial/multi-prime, Fermat, Pollard p-1, Wiener, factordb),
`rsa_hastad`, `rsa_common_modulus`, `rsa_shared_prime`, `rsa_parse_key`.

**Forensics & stego**: `file_triage`, `extract_strings`, `hexdump`, `carve`,
`extract_embedded` (binwalk-style), `image_analyze` (EXIF, PNG chunks/CRC, trailers),
`png_fix_dimensions`, `lsb_extract`, `stego_lsb_scan`, `image_bit_planes`, `zip_inspect`,
`zip_crack`, `pcap_summary` (protocols, DNS, HTTP, cleartext creds), `pcap_streams`.

**Reversing & pwn**: `binary_info` (checksec, imports, win-like functions, PE/.NET/UPX
detection), `list_functions`, `disassemble` (PLT-annotated, string refs), `find_gadgets`,
`cyclic` / `cyclic_find` (pwntools-compatible), `pack` / `unpack`.

**Web & OSINT**: `http_request`, `web_recon` (robots, .git, backups, .env...), `tcp_exchange`
(nc-style services), `dns_lookup`, `jwt_decode`, `jwt_crack`, `jwt_forge`.

**Execution**: `run_tool` (allowlisted CLI tools, no shell), `run_python` (solver scripts,
saved to `workspace/scripts` for writeups), `toolchain_status`.

### Safety notes

- Paths are jailed to `CTF_WORKSPACE` (symlink-aware). Opt out on a trusted laptop with
  `CTF_MCP_ALLOW_HOST_PATHS=1`.
- `run_python` runs arbitrary code as the user, and the network scope does not apply to it.
  Claude Desktop, Claude Code and VS Code Copilot ask before each tool call; leave that
  approval on during events (don't auto-approve ctf-solver tools), or set `CTF_MCP_DISABLE_EXEC=1`.
- `run_tool` leaves out network clients (curl, nmap, nc) so traffic goes through the
  scope-checked tools.
- `rsa_solve` queries factordb.com by default on a laptop; pass `use_factordb=false` or set
  `CTF_MCP_ALLOW_FACTORDB=0` if the event forbids outside lookups.

### Hosted profile

```bash
export CTF_MCP_HOSTED=1
# implies: path jail locked on, run_python disabled, ALLOW_ANY_TOOL denied,
# factordb default off, audit on, scope IP verify on, per-token workspace isolation
```

Container/Firejail sandbox for `run_python` is stubbed: even with `CTF_MCP_DISABLE_EXEC=0`,
hosted mode refuses unsandboxed exec unless `CTF_MCP_UNSAFE_EXEC=1` (lab break-glass only).

### Team remote + Challenge Desk (Phase 2)

Private **streamable-http** + **bearer tokens** + a beginner **Challenge Desk**
(upload challenges in the browser; coach visibility). See [docs/team-remote.md](docs/team-remote.md).

```bash
cp .env.example .env   # player token(s) + CTF_MCP_COACH_TOKEN
docker compose up --build
# Desk:  http://127.0.0.1:8765/
# MCP:   http://127.0.0.1:8765/mcp
```

Players: paste token → upload files → connect Claude, Copilot or Cursor.

Coach (Josh): paste coach token → Coach tab → roster, all uploads, recent tool activity.

| Variable | Default | Purpose |
|---|---|---|
| `CTF_MCP_TRANSPORT` | `stdio` | `streamable-http` for remote |
| `CTF_MCP_HOST` / `CTF_MCP_PORT` | `127.0.0.1` / `8765` | Bind address (loopback first) |
| `CTF_MCP_AUTH_TOKEN` | unset | Shared player bearer |
| `CTF_MCP_AUTH_TOKENS` | unset | `label:secret,…` per-player workspaces |
| `CTF_MCP_COACH_TOKEN` | unset | Coach desk overview |
| `CTF_MCP_ISOLATE_SESSIONS` | on when hosted | `CTF_WORKSPACE/users/<label>/` |
| `CTF_MCP_PUBLIC_URL` | derived | Advertised desk / MCP URL |

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

CI runs the same pytest matrix on Python 3.10–3.12 (`.github/workflows/ci.yml`).

Tests build their own fixtures (a hand-assembled x86-64 ELF, stego PNGs, a pcap), so they need
no external tools. Add a tool by writing a typed function with a docstring in the right module
and appending it to that module's `TOOLS` list.
