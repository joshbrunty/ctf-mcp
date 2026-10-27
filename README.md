# ctf-mcp

An [MCP](https://modelcontextprotocol.io) server that gives Claude (Desktop or Code) a CTF
toolkit: 47 tools across crypto, forensics/stego, reversing/pwn and web, plus a guided
`solve_challenge` prompt. Built for the Marshall University cyber team.

Most tools are pure Python, so a fresh laptop works without Kali. When `binwalk`, `exiftool`,
`tshark`, `john`, `r2` and similar are installed, Claude can also call them through `run_tool`.

> **Check the event rules first.** Many competitions (NCL, CCDC, plenty of CTFtime events)
> restrict or ban AI assistance. Only use this where the rules allow it.

## Install

Requires Python 3.10+.

**macOS / Linux**

```bash
git clone <this repo> ctf-mcp && cd ctf-mcp
./scripts/install.sh          # add --pwn to also install pwntools
```

**Windows (PowerShell)**

```powershell
git clone <this repo> ctf-mcp; cd ctf-mcp
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

The installer creates `.venv`, registers the server with Claude Code (`claude mcp add --scope
user`) if the CLI is installed, and adds it to Claude Desktop's config (keeping a `.bak`).
Restart Claude Desktop afterwards.

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

## Competition-day checklist

1. **Set the flag format** with `CTF_FLAG_REGEX`, e.g. `picoCTF\{[^}]+\}`. Every tool reports
   matches in a `flags` field. The default matches anything shaped like `word{...}`.
2. **Set the scope** with `CTF_SCOPE`: comma-separated hostnames, `*.domain` wildcards, IPs
   or CIDRs from the rules. `http_request`, `web_recon` and `tcp_exchange` refuse anything
   outside it, which keeps Claude off the scoreboard and other teams' boxes. With no scope set
   they allow any host and warn about it.
3. Put challenge files in the workspace (default `~/ctf-workspace`). Relative paths resolve
   there, and carved files, fixed images, extracted archives and solver scripts are written there.
4. Run `toolchain_status` once to see which optional CLI tools are missing.
5. Start a challenge with the **solve_challenge** prompt (Claude Desktop: the "+" menu →
   ctf-solver; Claude Code: `/mcp__ctf-solver__solve_challenge`), or just paste the
   challenge and point at the file.

Restart Claude Desktop after changing `env`. For Claude Code, re-run `claude mcp add` with
new `-e` values.

| Variable | Default | Purpose |
|---|---|---|
| `CTF_WORKSPACE` | `~/ctf-workspace` | Where inputs are looked up and outputs written |
| `CTF_FLAG_REGEX` | `word{...}` | The event's flag format |
| `CTF_SCOPE` | unset (any host) | Hosts/CIDRs the network tools may contact |
| `CTF_WORDLIST` | rockyou.txt if found | Wordlist for hash/zip/JWT cracking |
| `CTF_MCP_DISABLE_EXEC` | unset | `1` disables `run_python` |
| `CTF_MCP_ALLOW_ANY_TOOL` | unset | `1` lets `run_tool` run binaries outside the allowlist |

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

- `run_python` runs arbitrary code as the user, and the network scope does not apply to it.
  Claude Desktop and Claude Code ask before each tool call; leave that approval on during
  events, or set `CTF_MCP_DISABLE_EXEC=1`.
- `run_tool` leaves out network clients (curl, nmap, nc) so traffic goes through the
  scope-checked tools.
- `rsa_solve` queries factordb.com by default; pass `use_factordb=false` if the event forbids
  outside lookups.

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

Tests build their own fixtures (a hand-assembled x86-64 ELF, stego PNGs, a pcap), so they need
no external tools. Add a tool by writing a typed function with a docstring in the right module
and appending it to that module's `TOOLS` list.
