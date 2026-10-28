# Install ctf-mcp into .venv and register it with Claude Code and Claude Desktop (Windows).
# Usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-Pwn]
param([switch]$Pwn)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Extras = if ($Pwn) { "[pwn]" } else { "" }

Write-Host "==> Creating virtualenv in $Root\.venv"
py -3 -m venv "$Root\.venv"
& "$Root\.venv\Scripts\python.exe" -m pip install -q --upgrade pip
& "$Root\.venv\Scripts\python.exe" -m pip install -q -e "$Root$Extras"

$Server = "$Root\.venv\Scripts\ctf-mcp.exe"
$Workspace = if ($env:CTF_WORKSPACE) { $env:CTF_WORKSPACE } else { "$HOME\ctf-workspace" }
New-Item -ItemType Directory -Force -Path $Workspace | Out-Null

if (Get-Command claude -ErrorAction SilentlyContinue) {
    Write-Host "==> Registering with Claude Code (user scope)"
    claude mcp remove ctf-solver --scope user 2>$null
    claude mcp add ctf-solver --scope user -e CTF_WORKSPACE="$Workspace" -- "$Server"
} else {
    Write-Host "--> Claude Code CLI not found; later run:"
    Write-Host "    claude mcp add ctf-solver --scope user -e CTF_WORKSPACE=$Workspace -- $Server"
}

$ConfigDir = "$env:APPDATA\Claude"
$Config = "$ConfigDir\claude_desktop_config.json"
if (Test-Path $ConfigDir) {
    Write-Host "==> Adding ctf-solver to Claude Desktop config"
    if (Test-Path $Config) { Copy-Item $Config "$Config.bak" -Force }
    & "$Root\.venv\Scripts\python.exe" -c @"
import json, sys
from pathlib import Path
path, server, workspace = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
config = json.loads(path.read_text()) if path.exists() and path.read_text().strip() else {}
entry = config.setdefault('mcpServers', {}).get('ctf-solver', {})
env = entry.get('env', {})
env['CTF_WORKSPACE'] = workspace
config['mcpServers']['ctf-solver'] = {'command': server, 'args': [], 'env': env}
path.write_text(json.dumps(config, indent=2) + '\n')
"@ $Config $Server $Workspace
    Write-Host "    Restart Claude Desktop to load it (backup: $Config.bak)"
} else {
    Write-Host "--> Claude Desktop config folder not found; skipping (see README)"
}
# GitHub Copilot: VS Code (agent mode) and Copilot CLI both read this portable file.
$CopilotHome = if ($env:COPILOT_HOME) { $env:COPILOT_HOME } else { "$HOME\.copilot" }
$CopilotConfig = "$CopilotHome\mcp-config.json"
Write-Host "==> Adding ctf-solver to GitHub Copilot config ($CopilotConfig)"
New-Item -ItemType Directory -Force -Path $CopilotHome | Out-Null
if (Test-Path $CopilotConfig) { Copy-Item $CopilotConfig "$CopilotConfig.bak" -Force }
& "$Root\.venv\Scripts\python.exe" -c @"
import json, sys
from pathlib import Path
path, server, workspace = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
config = json.loads(path.read_text()) if path.exists() and path.read_text().strip() else {}
entry = config.setdefault('mcpServers', {}).get('ctf-solver', {})
env = entry.get('env', {})
env['CTF_WORKSPACE'] = workspace
config['mcpServers']['ctf-solver'] = {'type': 'stdio', 'command': server, 'args': [], 'env': env, 'tools': ['*']}
path.write_text(json.dumps(config, indent=2) + '\n')
"@ $CopilotConfig $Server $Workspace
Write-Host "    In VS Code, open Copilot Chat in Agent mode; ctf-solver appears under the tools picker."

Write-Host "==> Done. Workspace: $Workspace"
