"""MCP server entry point: registers every tool module and the solving prompt."""

from __future__ import annotations

import functools

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import crypto, execution, forensics, reversing, web

INSTRUCTIONS = """\
CTF solving toolkit for Marshall University's cyber team.

Workflow:
1. Start every file with file_triage (or binary_info for executables). Run toolchain_status
   if unsure what external tools are installed.
2. Encoded/odd text: auto_decode first, then transform for a specific chain.
3. Follow the category tools: crypto (xor_crack, vigenere_crack, rsa_solve, hash_crack),
   forensics/stego (image_analyze, stego_lsb_scan, extract_embedded, pcap_summary, zip_crack),
   reversing/pwn (disassemble, find_gadgets, cyclic_find), web (web_recon, http_request, jwt_*).
4. Use run_python for custom solvers and run_tool for installed CLI tools.
Relative file paths resolve inside the workspace; carved/extracted output is written there.
Every tool reports flags matching the event's flag format in a `flags` field; verify a flag
before submitting. Only interact with hosts that are in scope for the event (CTF_SCOPE);
never attack the scoring platform or other teams' infrastructure.
"""

mcp = MCPServer("ctf-solver", instructions=INSTRUCTIONS, version="0.1.0")



def _report_errors(fn):
    # The SDK hides the text of unexpected exceptions from the client. Here the reason
    # ("outside CTF_SCOPE", "not installed", bad input) is exactly what Claude needs.
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            raise ToolError(f"{type(exc).__name__}: {exc}") from exc

    return wrapper


for module in (crypto, forensics, reversing, web, execution):
    for fn in module.TOOLS:
        mcp.tool()(_report_errors(fn))


@mcp.prompt()
def solve_challenge(category: str, description: str, files: str = "", connection: str = "") -> str:
    """Kick off a structured solve of one CTF challenge."""
    return f"""Solve this {category} CTF challenge.

Description:
{description}

Files: {files or "none"}
Connection info: {connection or "none"}

Work methodically: triage first, state your hypothesis before each tool call, and keep notes of
what you ruled out. When you find the flag, show the exact steps that produced it so the team
can reproduce them and write it up. If you get stuck, list the three most likely next angles."""


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
