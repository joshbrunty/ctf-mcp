import struct
import zlib

import pytest


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.delenv("CTF_SCOPE", raising=False)
    monkeypatch.delenv("CTF_FLAG_REGEX", raising=False)
    return tmp_path / "ws"


def build_elf() -> bytes:
    """A minimal static x86-64 ELF executable with main/win symbols, a `pop rdi; ret`
    gadget and a flag string, so reversing tools can be tested without a Linux toolchain."""
    base, code_off = 0x400000, 0x200
    win_off = 10
    # main: push rbp; mov rbp, rsp; call win; ret  (the call ends at byte 9)
    main = b"\x55\x48\x89\xe5\xe8" + struct.pack("<i", win_off - 9) + b"\xc3"
    win = b"\x5f\xc3\x0f\x05"  # pop rdi; ret; syscall
    text = main.ljust(win_off, b"\x90") + win
    rodata = b"/bin/sh\x00flag{elf_test}\x00"
    body = text + rodata

    strtab = b"\x00main\x00win\x00"
    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    sym = lambda name, value, size: struct.pack("<IBBHQQ", name, 0x12, 0, 1, value, size)
    symtab = b"\x00" * 24 + sym(1, base + code_off, len(main)) + sym(6, base + code_off + win_off, 2)

    off_symtab = code_off + len(body)
    off_strtab = off_symtab + len(symtab)
    off_shstr = off_strtab + len(strtab)
    shoff = (off_shstr + len(shstrtab) + 7) & ~7
    ehdr = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0x3E, 1, base + code_off, 64, shoff, 0, 64, 56, 2, 64, 5, 4)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, off_symtab, off_symtab, 0x1000)
    phdrs += struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    sh = lambda n, t, fl, addr, off, size, link=0, info=0, ent=0: struct.pack(
        "<IIQQQQIIQQ", n, t, fl, addr, off, size, link, info, 1, ent)
    shdrs = (sh(0, 0, 0, 0, 0, 0) + sh(1, 1, 6, base + code_off, code_off, len(body))
             + sh(7, 2, 0, 0, off_symtab, len(symtab), 3, 1, 24) + sh(15, 3, 0, 0, off_strtab, len(strtab))
             + sh(23, 3, 0, 0, off_shstr, len(shstrtab)))
    image = (ehdr + phdrs).ljust(code_off, b"\x00") + body + symtab + strtab + shstrtab
    return image.ljust(shoff, b"\x00") + shdrs


def png_bytes(width: int, height: int, pixels: list[tuple[int, int, int]]) -> bytes:
    raw = b"".join(b"\x00" + b"".join(bytes(p) for p in pixels[y * width : (y + 1) * width]) for y in range(height))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
