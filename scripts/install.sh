#!/usr/bin/env bash
# Install ctf-mcp into .venv and register it with Claude Code and Claude Desktop.
# Usage: ./scripts/install.sh [--pwn]     (--pwn also installs pwntools)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
EXTRAS=""
[[ "${1:-}" == "--pwn" ]] && EXTRAS="[pwn]"

"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "Python 3.10+ is required (found $("$PYTHON" --version))"; exit 1; }

echo "==> Creating virtualenv in $ROOT/.venv"
"$PYTHON" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -q --upgrade pip
"$ROOT/.venv/bin/pip" install -q -e "$ROOT$EXTRAS"

SERVER="$ROOT/.venv/bin/ctf-mcp"
WORKSPACE="${CTF_WORKSPACE:-$HOME/ctf-workspace}"
mkdir -p "$WORKSPACE"

if command -v claude >/dev/null 2>&1; then
    echo "==> Registering with Claude Code (user scope)"
    claude mcp remove ctf-solver --scope user >/dev/null 2>&1 || true
    claude mcp add ctf-solver --scope user -e CTF_WORKSPACE="$WORKSPACE" -- "$SERVER"
else
    echo "--> Claude Code CLI not found; skipping. Later run:"
    echo "    claude mcp add ctf-solver --scope user -e CTF_WORKSPACE=$WORKSPACE -- $SERVER"
fi

case "$(uname -s)" in
    Darwin) DESKTOP_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json" ;;
    *) DESKTOP_CONFIG="" ;;
esac

if [[ -n "$DESKTOP_CONFIG" && -d "$(dirname "$DESKTOP_CONFIG")" ]]; then
    echo "==> Adding ctf-solver to Claude Desktop config"
    [[ -f "$DESKTOP_CONFIG" ]] && cp "$DESKTOP_CONFIG" "$DESKTOP_CONFIG.bak"
    "$ROOT/.venv/bin/python" - "$DESKTOP_CONFIG" "$SERVER" "$WORKSPACE" <<'EOF'
import json, sys
from pathlib import Path
path, server, workspace = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
config = json.loads(path.read_text()) if path.exists() and path.read_text().strip() else {}
entry = config.setdefault("mcpServers", {}).get("ctf-solver", {})
env = entry.get("env", {})
env["CTF_WORKSPACE"] = workspace
config["mcpServers"]["ctf-solver"] = {"command": server, "args": [], "env": env}
path.write_text(json.dumps(config, indent=2) + "\n")
EOF
    echo "    Restart Claude Desktop to load it (backup: $DESKTOP_CONFIG.bak)"
else
    echo "--> Claude Desktop config folder not found; skipping (see README for manual setup)"
fi

# GitHub Copilot: VS Code (agent mode) and Copilot CLI both read this portable file.
COPILOT_CONFIG="${COPILOT_HOME:-$HOME/.copilot}/mcp-config.json"
echo "==> Adding ctf-solver to GitHub Copilot config ($COPILOT_CONFIG)"
mkdir -p "$(dirname "$COPILOT_CONFIG")"
[[ -f "$COPILOT_CONFIG" ]] && cp "$COPILOT_CONFIG" "$COPILOT_CONFIG.bak"
"$ROOT/.venv/bin/python" - "$COPILOT_CONFIG" "$SERVER" "$WORKSPACE" <<'EOF'
import json, sys
from pathlib import Path
path, server, workspace = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
config = json.loads(path.read_text()) if path.exists() and path.read_text().strip() else {}
entry = config.setdefault("mcpServers", {}).get("ctf-solver", {})
env = entry.get("env", {})
env["CTF_WORKSPACE"] = workspace
config["mcpServers"]["ctf-solver"] = {"type": "stdio", "command": server, "args": [], "env": env, "tools": ["*"]}
path.write_text(json.dumps(config, indent=2) + "\n")
EOF
echo "    In VS Code, open Copilot Chat in Agent mode; ctf-solver appears under the tools picker."

echo "==> Done. Workspace: $WORKSPACE"
echo "    Check optional tools with the toolchain_status tool, or: $ROOT/.venv/bin/python -c 'from ctf_mcp.execution import toolchain_status as t; import json; print(json.dumps(t(), indent=2))'"
