"""Running external CTF tools and solver scripts in the workspace."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import importlib.util

from .audit import audit
from .common import clip, find_flags, output_path, workspace
from .config import allow_any_tool_enabled, exec_enabled, hosted_mode, safety_snapshot, sandbox_requested

# Offline analysis tools. Network clients (curl, nmap, nc) are left out on purpose so every
# connection goes through the scope-checked web tools.
ALLOWED_TOOLS = {
    "file", "strings", "xxd", "hexdump", "od", "binwalk", "foremost", "exiftool", "pngcheck",
    "zsteg", "steghide", "stegseek", "outguess", "tshark", "capinfos", "tcpdump", "objdump",
    "readelf", "nm", "otool", "r2", "rabin2", "rasm2", "radare2", "gdb", "checksec", "ROPgadget",
    "ropper", "one_gadget", "ltrace", "strace", "upx", "john", "zip2john", "rar2john",
    "hashcat", "bkcrack", "openssl", "unzip", "7z", "7zz", "tar", "gzip", "bzip2", "xz",
    "base64", "dig", "whois", "qpdf", "pdftotext", "pdfimages", "sox", "ffmpeg", "identify",
    "convert", "magick", "sqlite3", "volatility", "vol", "vol.py", "ilspycmd", "jadx",
    "apktool", "uncompyle6", "pycdc", "decompyle3", "sha256sum", "md5sum", "ls", "cat", "head",
    "tail", "wc", "sort", "uniq", "grep", "diff", "cmp", "fcrackzip", "pdfcrack",
}

INSTALL_HINTS = {
    "binwalk": "brew install binwalk  |  apt install binwalk",
    "exiftool": "brew install exiftool  |  apt install libimage-exiftool-perl",
    "tshark": "brew install wireshark  |  apt install tshark",
    "zsteg": "gem install zsteg",
    "steghide": "apt install steghide (no current Homebrew formula; use Kali/WSL)",
    "stegseek": "github.com/RickdeJager/stegseek releases (Linux)",
    "r2": "brew install radare2  |  apt install radare2",
    "checksec": "brew install checksec  |  apt install checksec",
    "john": "brew install john-jumbo  |  apt install john",
    "hashcat": "brew install hashcat  |  apt install hashcat",
    "pngcheck": "brew install pngcheck  |  apt install pngcheck",
    "foremost": "brew install foremost  |  apt install foremost",
    "ROPgadget": "pip install ROPgadget",
    "one_gadget": "gem install one_gadget",
    "upx": "brew install upx  |  apt install upx",
    "gdb": "apt install gdb (Linux; use lldb on macOS)",
    "7zz": "brew install sevenzip  |  apt install 7zip",
    "bkcrack": "github.com/kimci86/bkcrack releases",
    "volatility": "pip install volatility3",
}


def run_tool(command: list[str], timeout: int = 120, stdin: str = "") -> dict:
    """Run an installed CTF command-line tool (binwalk, exiftool, tshark, r2, john, steghide,
    zsteg, objdump, openssl, ...) with the workspace as working directory. `command` is an
    argument list, e.g. ["binwalk", "-e", "image.png"]. No shell, so no pipes or globs."""
    if not command:
        raise ValueError("command is empty")
    name = os.path.basename(command[0])
    if name not in ALLOWED_TOOLS and not allow_any_tool_enabled():
        if hosted_mode() and os.environ.get("CTF_MCP_ALLOW_ANY_TOOL") == "1":
            raise PermissionError(
                f"{name} is not on the allowlist, and CTF_MCP_ALLOW_ANY_TOOL is denied in hosted mode."
            )
        raise PermissionError(f"{name} is not on the allowlist. Use run_python, or set CTF_MCP_ALLOW_ANY_TOOL=1.")
    exe = shutil.which(command[0])
    if not exe:
        hint = INSTALL_HINTS.get(name, "install it with brew/apt/pip")
        raise FileNotFoundError(f"{name} is not installed ({hint})")
    start = time.monotonic()
    audit("run_tool", tool=name, argv=command[:12], timeout=timeout)
    try:
        proc = subprocess.run([exe] + command[1:], cwd=workspace(), input=stdin.encode() if stdin else None,
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"timed_out": True, "stdout": clip((exc.stdout or b"").decode(errors="replace"))}
    stdout = proc.stdout.decode(errors="replace")
    stderr = proc.stderr.decode(errors="replace")
    return {"exit_code": proc.returncode, "seconds": round(time.monotonic() - start, 2),
            "stdout": clip(stdout), "stderr": clip(stderr, 5000), "flags": find_flags(stdout + stderr)}


def _sandbox_stub_message() -> str:
    return (
        "Hosted sandbox exec is not implemented yet (Phase 1 stub). "
        "Keep CTF_MCP_DISABLE_EXEC unset/1, or run locally without CTF_MCP_HOSTED. "
        "Container/Firejail isolation lands with remote hosting."
    )


def run_python(code: str, timeout: int = 120, stdin: str = "") -> dict:
    """Run a Python 3 solver script (with pycryptodome, Pillow, scapy, capstone and, if
    installed, pwntools available) in the workspace. Print results to stdout. The script is
    saved under workspace/scripts so the team can reuse it in writeups.

    Disabled when CTF_MCP_DISABLE_EXEC=1, and by default when CTF_MCP_HOSTED=1.
    Note: scripts are not limited by CTF_SCOPE. Hosted sandbox path is stubbed.
    """
    if not exec_enabled():
        audit("run_python_denied", reason="exec_disabled", hosted=hosted_mode())
        raise PermissionError(
            "run_python is disabled "
            f"({'CTF_MCP_HOSTED=1 defaults to no exec' if hosted_mode() else 'CTF_MCP_DISABLE_EXEC=1'}). "
            "Set CTF_MCP_DISABLE_EXEC=0 only on a trusted host."
        )
    if hosted_mode() or sandbox_requested():
        # Phase 1: prefer disable-by-default; if someone forces exec on hosted, still refuse
        # until a real sandbox exists — unless they explicitly opt into unsandboxed with
        # CTF_MCP_UNSAFE_EXEC=1 (documented break-glass for lab boxes).
        if not os.environ.get("CTF_MCP_UNSAFE_EXEC") == "1":
            audit("run_python_denied", reason="sandbox_stub")
            raise PermissionError(_sandbox_stub_message())
    script = output_path("scripts", time.strftime("solve_%Y%m%d_%H%M%S.py"))
    script.write_text(code)
    env = {**os.environ, "PWNLIB_NOTERM": "1", "PYTHONUNBUFFERED": "1"}
    audit("run_python", script=str(script), timeout=timeout, code_len=len(code))
    try:
        proc = subprocess.run([sys.executable, str(script)], cwd=workspace(), env=env,
                              input=stdin.encode() if stdin else None, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"timed_out": True, "script": str(script),
                "stdout": clip((exc.stdout or b"").decode(errors="replace"))}
    stdout = proc.stdout.decode(errors="replace")
    stderr = proc.stderr.decode(errors="replace")
    return {"exit_code": proc.returncode, "script": str(script), "stdout": clip(stdout),
            "stderr": clip(stderr, 8000), "flags": find_flags(stdout)}


def toolchain_status() -> dict:
    """Which external tools and Python packages are available, with install hints for missing ones.
    Also shows the workspace, flag regex and scope settings in effect."""
    from .common import flag_regex
    from .web import scope_rules

    tools = sorted(set(INSTALL_HINTS) | {"file", "strings", "objdump", "readelf", "openssl", "unzip"})
    present = {t: shutil.which(t) is not None for t in tools}
    modules = {m: importlib.util.find_spec(m) is not None
               for m in ("pwn", "Crypto", "PIL", "scapy", "capstone", "elftools", "pefile", "gmpy2", "sympy")}
    return {
        "workspace": str(workspace()),
        "flag_regex": flag_regex().pattern,
        "scope": scope_rules() or "unrestricted (set CTF_SCOPE)",
        "run_python_enabled": exec_enabled(),
        "safety": safety_snapshot(),
        "tools": present,
        "missing_install_hints": {t: INSTALL_HINTS.get(t, "") for t, ok in present.items() if not ok},
        "python_modules": modules,
    }


TOOLS = [run_tool, run_python, toolchain_status]
