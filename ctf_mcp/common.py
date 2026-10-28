"""Helpers shared by every tool module: flag detection, input loading, output limits."""

from __future__ import annotations

import base64
import math
import os
import re
from collections import Counter
from pathlib import Path

from .config import isolate_sessions, path_jail_enabled

# Matches flag{...}, picoCTF{...}, MUCTF{...} and similar. Override per event with CTF_FLAG_REGEX.
DEFAULT_FLAG_REGEX = r"[A-Za-z0-9_\-]{2,32}\{[^{}\s]{1,256}\}"
MAX_OUTPUT = 20_000
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def flag_regex() -> re.Pattern[str]:
    return re.compile(os.environ.get("CTF_FLAG_REGEX", DEFAULT_FLAG_REGEX))


def find_flags(data: bytes | str, limit: int = 50) -> list[str]:
    """Return distinct flag-looking strings in `data`, in order of appearance."""
    if isinstance(data, bytes):
        data = data.decode("latin-1")
    found: list[str] = []
    for m in flag_regex().finditer(data):
        if m.group(0) not in found:
            found.append(m.group(0))
            if len(found) >= limit:
                break
    return found


def workspace_root() -> Path:
    """Configured CTF_WORKSPACE root (before per-user isolation)."""
    path = Path(os.environ.get("CTF_WORKSPACE", Path.home() / "ctf-workspace")).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _session_label() -> str | None:
    """Bearer client_id when HTTP auth context is active."""
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token
    except ImportError:  # pragma: no cover
        return None
    token = get_access_token()
    if token is None or not token.client_id:
        return None
    # Labels were validated at token parse time; re-scrub for the filesystem.
    label = re.sub(r"[^A-Za-z0-9_.-]", "_", token.client_id)[:64]
    return label or None


def workspace() -> Path:
    """Directory where carved files, fixed images and scripts are written.

    With session isolation (hosted default), authenticated HTTP callers get
    ``CTF_WORKSPACE/users/<label>/`` so team tokens do not share files.
    """
    path = workspace_root()
    if isolate_sessions():
        label = _session_label()
        if label:
            path = path / "users" / label
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(path.resolve()), str(root.resolve())]) == str(root.resolve())
    except ValueError:
        return False


def assert_in_workspace(path: Path, *, label: str = "path") -> Path:
    """Resolve `path` and raise PermissionError if the path jail rejects it."""
    root = workspace()
    resolved = path.expanduser()
    # Resolve without requiring the leaf to exist (parents must be resolvable).
    resolved = resolved.resolve()
    if path_jail_enabled() and not _is_within(resolved, root):
        raise PermissionError(
            f"{label} escapes CTF_WORKSPACE ({root}): {resolved}. "
            "Use a path under the workspace, or set CTF_MCP_ALLOW_HOST_PATHS=1 on a trusted laptop."
        )
    return resolved


def resolve_path(path: str) -> Path:
    """Resolve a tool path under the workspace jail.

    Relative paths are taken from CTF_WORKSPACE. Absolute paths must still resolve inside
    the workspace unless CTF_MCP_ALLOW_HOST_PATHS=1 (ignored in hosted mode).
    """
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = workspace() / p
    p = assert_in_workspace(p)
    if not p.exists():
        raise FileNotFoundError(f"No such file: {p}")
    return p


def output_path(subdir: str, name: str) -> Path:
    """Create a workspace subdirectory and return a jailed destination path.

    `subdir` may be nested (`extracted/chal`) but must not contain `..` or absolute roots.
    `name` must be a single path segment (no separators / traversal).
    """
    sub = Path(subdir)
    if sub.is_absolute() or any(p in ("", "..") for p in sub.parts):
        raise PermissionError(f"invalid output subdir: {subdir!r}")
    leaf = Path(name)
    if leaf.is_absolute() or len(leaf.parts) != 1 or leaf.parts[0] in ("", ".", ".."):
        raise PermissionError(f"invalid output name: {name!r}")
    out = assert_in_workspace(workspace() / sub, label="output dir")
    out.mkdir(parents=True, exist_ok=True)
    return assert_in_workspace(out / leaf, label="output file")


def load_input(data: str, data_format: str = "text") -> bytes:
    """Turn a tool argument into bytes. Formats: text, hex, base64, int, file."""
    fmt = data_format.lower()
    if fmt == "text":
        return data.encode("utf-8")
    if fmt == "hex":
        return bytes.fromhex(re.sub(r"0[xX]|\\x|[^0-9a-fA-F]", "", data))
    if fmt in ("base64", "b64"):
        t = re.sub(r"\s", "", data).replace("-", "+").replace("_", "/")
        return base64.b64decode(t + "=" * (-len(t) % 4))
    if fmt == "int":
        n = int(data, 0)
        return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if fmt == "file":
        return resolve_path(data).read_bytes()
    raise ValueError(f"Unknown data_format {data_format!r}; use text, hex, base64, int or file")


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if x in PRINTABLE) / len(b)


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def to_text(b: bytes) -> str:
    return b.decode("utf-8", errors="backslashreplace")


def clip(s: str, limit: int = MAX_OUTPUT) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n... [truncated {len(s) - limit} chars]"


def preview(b: bytes, limit: int = 2000) -> dict:
    """Text and hex views of a byte string, both clipped."""
    return {
        "length": len(b),
        "text": clip(to_text(b), limit),
        "hex": b[: limit // 2].hex(),
        "printable_ratio": round(printable_ratio(b), 3),
    }
