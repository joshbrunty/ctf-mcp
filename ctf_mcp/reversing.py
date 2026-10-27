"""Reversing and pwn tools: binary info / checksec, symbols, disassembly, ROP gadgets, cyclic patterns."""

from __future__ import annotations

import re

from .common import clip, find_flags, resolve_path

DANGEROUS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "__isoc99_scanf", "fscanf",
    "read", "memcpy", "printf", "fprintf", "snprintf", "system", "execve", "execl", "popen",
    "mprotect", "mmap", "free", "malloc", "realloc", "alarm", "setvbuf", "fgets", "strncpy",
}


def _kind(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    return "unknown"


# --------------------------------------------------------------------------- ELF helpers

def _elf_symbols(elf) -> dict[str, dict]:
    from elftools.elf.sections import SymbolTableSection

    syms = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for s in sec.iter_symbols():
            if not s.name:
                continue
            syms.setdefault(s.name, {"name": s.name, "addr": s["st_value"], "size": s["st_size"],
                                     "type": s["st_info"]["type"], "bind": s["st_info"]["bind"],
                                     "defined": s["st_shndx"] != "SHN_UNDEF", "table": sec.name})
    return syms


def _cs(elf):
    import capstone as cs

    arch = elf.get_machine_arch()
    little = elf.little_endian
    endian = cs.CS_MODE_LITTLE_ENDIAN if little else cs.CS_MODE_BIG_ENDIAN
    table = {
        "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "ARM": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | endian),
        "AArch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM | endian),
        "MIPS": (cs.CS_ARCH_MIPS, (cs.CS_MODE_MIPS64 if elf.elfclass == 64 else cs.CS_MODE_MIPS32) | endian),
        "RISC-V": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64 if elf.elfclass == 64 else cs.CS_MODE_RISCV32),
    }
    if arch not in table:
        raise ValueError(f"Unsupported architecture {arch}")
    md = cs.Cs(*table[arch])
    md.detail = True
    return md


def _vaddr_to_offset(elf, addr: int) -> tuple[int, int] | None:
    """File offset of a virtual address and how many bytes remain in that segment."""
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= addr < seg["p_vaddr"] + seg["p_filesz"]:
            return seg["p_offset"] + addr - seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"] - addr
    return None


def _plt_names(elf, md) -> dict[int, str]:
    """Map PLT stub addresses to imported function names so calls read `call puts@plt`."""
    import capstone.x86 as x86

    got = {}
    for sec in elf.iter_sections():
        if sec.name in (".rela.plt", ".rel.plt") and hasattr(sec, "iter_relocations"):
            symtab = elf.get_section(sec["sh_link"])
            for rel in sec.iter_relocations():
                sym = symtab.get_symbol(rel["r_info_sym"])
                if sym and sym.name:
                    got[rel["r_offset"]] = sym.name
    names = {}
    if elf.get_machine_arch() not in ("x64", "x86"):
        return names
    for secname in (".plt.sec", ".plt", ".plt.got"):
        sec = elf.get_section_by_name(secname)
        if not sec:
            continue
        data, base = sec.data(), sec["sh_addr"]
        for off in range(0, len(data), 16 if secname != ".plt.got" else 8):
            for insn in md.disasm(data[off : off + 16], base + off):
                if insn.mnemonic.endswith("jmp") and insn.operands and insn.operands[0].type == x86.X86_OP_MEM:
                    mem = insn.operands[0].mem
                    if mem.base == x86.X86_REG_RIP:
                        target = insn.address + insn.size + mem.disp
                    elif mem.base == 0:
                        target = mem.disp
                    else:
                        continue
                    if target in got:
                        names.setdefault(base + off, got[target] + "@plt")
                    break
    return names


def binary_info(path: str) -> dict:
    """checksec plus triage for ELF/PE binaries: architecture, PIE, NX, RELRO, canary, stripped,
    imports, dangerous/interesting functions (gets, system, win...), and interesting strings."""
    p = resolve_path(path)
    data = p.read_bytes()
    kind = _kind(data[:8])
    strings = [s.decode() for s in re.findall(rb"[\x20-\x7e]{5,}", data)]
    interesting = [s for s in strings if re.search(r"(?i)flag|/bin/sh|cat |password|secret|correct|wrong|win", s)][:40]
    out: dict = {"path": str(p), "format": kind, "flags": find_flags(data), "interesting_strings": interesting}

    if kind == "elf":
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.elffile import ELFFile

        with open(p, "rb") as f:
            elf = ELFFile(f)
            segs = {s["p_type"]: s for s in elf.iter_segments()}
            stack = segs.get("PT_GNU_STACK")
            bind_now = False
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_BIND_NOW" or \
                           (tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 0x8) or \
                           (tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 0x1):
                            bind_now = True
            syms = _elf_symbols(elf)
            imports = sorted(n for n, s in syms.items() if not s["defined"])
            funcs = sorted((s for s in syms.values() if s["defined"] and s["type"] == "STT_FUNC"),
                           key=lambda s: s["addr"])
            user_funcs = [s for s in funcs if not s["name"].startswith(("_", "deregister_tm", "register_tm", "frame_dummy"))]
            out.update({
                "arch": elf.get_machine_arch(),
                "bits": elf.elfclass,
                "endian": "little" if elf.little_endian else "big",
                "entry": hex(elf["e_entry"]),
                "statically_linked": "PT_INTERP" not in segs,
                "checksec": {
                    "pie": elf["e_type"] == "ET_DYN",
                    "nx": bool(stack) and not stack["p_flags"] & 1,
                    "relro": "full" if "PT_GNU_RELRO" in segs and bind_now else ("partial" if "PT_GNU_RELRO" in segs else "none"),
                    "canary": "__stack_chk_fail" in syms,
                    "fortify": any(n.endswith("_chk") and n.startswith("__") for n in syms),
                    "stripped": elf.get_section_by_name(".symtab") is None,
                    "rwx_segments": any(s["p_type"] == "PT_LOAD" and s["p_flags"] & 7 == 7 for s in elf.iter_segments()),
                },
                "imports": imports[:150],
                "dangerous_imports": sorted(DANGEROUS.intersection(i.split("@")[0] for i in imports)),
                "functions": [f"{hex(s['addr'])} {s['name']} ({s['size']} bytes)" for s in user_funcs][:150],
                "win_like_functions": [s["name"] for s in user_funcs if re.search(r"(?i)win|flag|shell|secret|backdoor|give", s["name"])],
                "sections": [f"{s.name} {hex(s['sh_addr'])} size={s['sh_size']}" for s in elf.iter_sections() if s.name],
            })
        hints = []
        cs_ = out["checksec"]
        if "gets" in out["dangerous_imports"] or "read" in out["dangerous_imports"]:
            hints.append("Possible stack overflow: find the offset with cyclic/cyclic_find.")
        if not cs_["canary"] and not cs_["pie"]:
            hints.append("No canary + no PIE: ret2win / ROP with fixed addresses (find_gadgets).")
        if not cs_["nx"]:
            hints.append("NX disabled: shellcode on the stack is possible.")
        if "printf" in out["dangerous_imports"]:
            hints.append("printf imported: check for format string bugs (user input as the format).")
        if cs_["relro"] != "full":
            hints.append("GOT is writable (RELRO not full): GOT overwrite is possible.")
        out["hints"] = hints
    elif kind == "pe":
        import pefile

        pe = pefile.PE(data=data)
        chars = pe.OPTIONAL_HEADER.DllCharacteristics
        out.update({
            "machine": hex(pe.FILE_HEADER.Machine),
            "bits": 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32,
            "entry": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase),
            "dotnet": pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0,
            "aslr": bool(chars & 0x40),
            "dep_nx": bool(chars & 0x100),
            "sections": [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"), "vaddr": hex(s.VirtualAddress),
                          "size": s.SizeOfRawData, "entropy": round(s.get_entropy(), 2)} for s in pe.sections],
            "imports": {e.dll.decode(): [i.name.decode() for i in e.imports if i.name][:60]
                        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])},
        })
        if out["dotnet"]:
            out["hints"] = [".NET assembly: decompile with ILSpy/dnSpy (ilspycmd via run_tool) instead of disassembling."]
        if any(s["name"].startswith("UPX") for s in out["sections"]):
            out.setdefault("hints", []).append("UPX packed: unpack with `upx -d` via run_tool.")
    elif kind == "macho":
        out["hint"] = "Mach-O: use run_tool with objdump/otool/nm for details."
    if b"UPX!" in data[:4096]:
        out.setdefault("hints", []).append("UPX signature found: `upx -d` via run_tool.")
    if b"PyInstaller" in data or b"pyi-runtime" in data:
        out.setdefault("hints", []).append("PyInstaller bundle: extract with pyinstxtractor, then decompile .pyc.")
    return out


def list_functions(path: str, pattern: str = "") -> dict:
    """All function symbols (defined and imported) in an ELF, with addresses and sizes."""
    from elftools.elf.elffile import ELFFile

    with open(resolve_path(path), "rb") as f:
        elf = ELFFile(f)
        syms = _elf_symbols(elf)
        plt = {v: k for k, v in _plt_names(elf, _cs(elf)).items()}
    rows = []
    for s in sorted(syms.values(), key=lambda s: s["addr"]):
        if s["type"] != "STT_FUNC":
            continue
        if pattern and not re.search(pattern, s["name"], re.I):
            continue
        addr = s["addr"] or plt.get(s["name"] + "@plt", 0)
        rows.append(f"{addr:#x} {'' if s['defined'] else '[import] '}{s['name']} size={s['size']}")
    return {"functions": rows[:1000], "count": len(rows)}


def disassemble(path: str, function: str = "", address: str = "", length: int = 400,
                syntax: str = "intel") -> dict:
    """Disassemble an ELF function by name (e.g. "main") or a virtual address (hex string).
    Calls are annotated with symbol and PLT names; string references are shown when found."""
    import capstone as cs
    from elftools.elf.elffile import ELFFile

    with open(resolve_path(path), "rb") as f:
        raw = f.read()
        f.seek(0)
        elf = ELFFile(f)
        md = _cs(elf)
        if syntax == "att" and elf.get_machine_arch() in ("x64", "x86"):
            md.syntax = cs.CS_OPT_SYNTAX_ATT
        syms = _elf_symbols(elf)
        names = {s["addr"]: s["name"] for s in syms.values() if s["defined"] and s["addr"]}
        names.update(_plt_names(elf, md))
        if function:
            if function not in syms or not syms[function]["defined"]:
                close = [n for n in syms if function.lower() in n.lower()][:10]
                raise ValueError(f"No defined function {function!r}. Similar: {close}. Stripped binaries need an address.")
            start, size = syms[function]["addr"], syms[function]["size"] or length
        elif address:
            start, size = int(address, 16), length
        else:
            start, size = elf["e_entry"], length
        loc = _vaddr_to_offset(elf, start)
        if not loc:
            raise ValueError(f"Address {start:#x} is not in a loaded segment")
        off, remaining = loc
        code = raw[off : off + min(size, remaining)]

        lines = []
        for insn in md.disasm(code, start):
            note = ""
            targets = re.findall(r"0x[0-9a-f]+", insn.op_str)
            for t in targets:
                v = int(t, 16)
                if v in names:
                    note = f"  <{names[v]}>"
                elif insn.mnemonic in ("lea", "mov", "push", "adr", "adrp") and (o := _vaddr_to_offset(elf, v)):
                    s = re.match(rb"[\x20-\x7e]{4,}", raw[o[0] : o[0] + 120])
                    if s:
                        note = f'  ; "{s.group().decode()[:80]}"'
            if "rip +" in insn.op_str or "rip -" in insn.op_str:
                m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", insn.op_str)
                tgt = insn.address + insn.size + (int(m.group(2), 16) * (1 if m.group(1) == "+" else -1))
                if tgt in names:
                    note = f"  <{names[tgt]}>"
                elif o := _vaddr_to_offset(elf, tgt):
                    s = re.match(rb"[\x20-\x7e]{4,}", raw[o[0] : o[0] + 120])
                    note = f'  ; {tgt:#x} "{s.group().decode()[:80]}"' if s else f"  ; {tgt:#x}"
            label = f"\n<{names[insn.address]}>:\n" if insn.address in names and insn.address != start else ""
            lines.append(f"{label}{insn.address:#x}: {insn.mnemonic:<7} {insn.op_str}{note}")
    header = f"<{names.get(start, hex(start))}>:"
    return {"disassembly": clip(header + "\n" + "\n".join(lines), 30000)}


def find_gadgets(path: str, query: str = "", max_instructions: int = 5, limit: int = 150) -> dict:
    """ROP gadgets ending in ret/syscall/int 0x80 in executable segments (x86/x64 ELF).
    `query` filters by substring, e.g. "pop rdi" or "syscall"."""
    from elftools.elf.elffile import ELFFile

    with open(resolve_path(path), "rb") as f:
        raw = f.read()
        f.seek(0)
        elf = ELFFile(f)
        if elf.get_machine_arch() not in ("x64", "x86"):
            raise ValueError("Gadget search supports x86/x64; use ROPgadget/ropper via run_tool for others")
        md = _cs(elf)
        md.detail = False
        segs = [(s["p_vaddr"], raw[s["p_offset"] : s["p_offset"] + s["p_filesz"]])
                for s in elf.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1]
    enders = [b"\xc3", b"\x0f\x05", b"\xcd\x80"]
    gadgets: dict[str, int] = {}
    for base, code in segs:
        for ender in enders:
            pos = code.find(ender)
            while pos != -1:
                end = pos + len(ender)
                for back in range(len(ender), 21):
                    start = end - back
                    if start < 0:
                        break
                    insns = list(md.disasm_lite(code[start:end], base + start))
                    if not insns or sum(i[1] for i in insns) != back or len(insns) > max_instructions + 1:
                        continue
                    if insns[-1][2] not in ("ret", "syscall", "int"):
                        continue
                    if any(i[2] in ("ret", "jmp", "call") for i in insns[:-1]):
                        continue
                    text = " ; ".join(f"{m} {o}".strip() for _, _, m, o in insns)
                    gadgets.setdefault(text, base + start)
                pos = code.find(ender, pos + 1)
    rows = [(a, t) for t, a in gadgets.items() if query.lower() in t.lower()]
    rows.sort(key=lambda r: (len(r[1]), r[0]))
    return {"gadgets": [f"{a:#x}: {t}" for a, t in rows[:limit]], "count": len(rows),
            "note": "PIE binaries: these are offsets from the load base."}


# --------------------------------------------------------------------------- exploitation helpers

def _de_bruijn(alphabet: str, n: int):
    k = len(alphabet)
    a = [0] * k * n

    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    return db(1, 1)


def _cyclic_str(length: int, n: int) -> str:
    out = []
    for ch in _de_bruijn("abcdefghijklmnopqrstuvwxyz", n):
        out.append(ch)
        if len(out) >= length:
            break
    return "".join(out)


def cyclic(length: int = 200, n: int = 4) -> dict:
    """pwntools-compatible De Bruijn pattern to find overflow offsets."""
    return {"pattern": _cyclic_str(length, n)}


def cyclic_find(value: str, n: int = 4) -> dict:
    """Offset of a crash value in the cyclic pattern. Give the register value as hex
    (e.g. "0x6161616c" from EIP, or the 8-byte RSP/RBP contents) or as raw text ("laaa")."""
    v = value.strip()
    if v.lower().startswith("0x"):
        num = int(v, 16)
        size = 8 if num > 0xFFFFFFFF else 4
        needle = num.to_bytes(size, "little")[:n].decode("latin-1")
    else:
        needle = v[:n]
    pattern = _cyclic_str(26 ** n if n <= 4 else 1_000_000, n)
    idx = pattern.find(needle)
    return {"needle": needle, "offset": idx if idx >= 0 else None,
            "note": "" if idx >= 0 else "Not found; check endianness or that the value came from the cyclic pattern."}


def pack(value: str, bits: int = 64, endian: str = "little") -> dict:
    """p64/p32-style packing of an integer, returned as hex and a Python bytes literal."""
    v = int(value, 0)
    b = (v & ((1 << bits) - 1)).to_bytes(bits // 8, endian)
    return {"hex": b.hex(), "python": repr(b), "escaped": "".join(f"\\x{x:02x}" for x in b)}


def unpack(data_hex: str, bits: int = 64, endian: str = "little") -> dict:
    """u64/u32-style unpacking of leaked bytes (hex string), padded to the word size."""
    b = bytes.fromhex(re.sub(r"0[xX]|\\x|[^0-9a-fA-F]", "", data_hex))
    b = b[: bits // 8].ljust(bits // 8, b"\x00")
    v = int.from_bytes(b, endian)
    return {"value": hex(v), "decimal": v}


TOOLS = [binary_info, list_functions, disassemble, find_gadgets, cyclic, cyclic_find, pack, unpack]
