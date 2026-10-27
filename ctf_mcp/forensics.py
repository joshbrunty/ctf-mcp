"""Forensics and steganography tools: triage, strings, carving, images, archives, pcaps."""

from __future__ import annotations

import hashlib
import mmap
import re
import shutil
import struct
import subprocess
import zipfile
import zlib
from collections import Counter, defaultdict
from pathlib import Path

from .common import clip, entropy, find_flags, output_path, preview, printable_ratio, resolve_path, to_text

# (name, magic, extension). Offsets for formats whose magic is not at byte 0 are handled in _signature_at.
SIGNATURES = [
    ("PNG image", b"\x89PNG\r\n\x1a\n", "png"),
    ("JPEG image", b"\xff\xd8\xff", "jpg"),
    ("GIF image", b"GIF8", "gif"),
    ("BMP image", b"BM", "bmp"),
    ("PDF document", b"%PDF-", "pdf"),
    ("ZIP archive (also docx/xlsx/jar/apk)", b"PK\x03\x04", "zip"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c", "7z"),
    ("RAR archive", b"Rar!\x1a\x07", "rar"),
    ("gzip", b"\x1f\x8b\x08", "gz"),
    ("bzip2", b"BZh", "bz2"),
    ("xz", b"\xfd7zXZ\x00", "xz"),
    ("zlib stream", b"\x78\x9c", "zlib"),
    ("ELF executable", b"\x7fELF", "elf"),
    ("PE executable", b"MZ", "exe"),
    ("Mach-O 64", b"\xcf\xfa\xed\xfe", "macho"),
    ("SQLite database", b"SQLite format 3\x00", "sqlite"),
    ("RIFF (WAV/AVI/WEBP)", b"RIFF", "riff"),
    ("OGG", b"OggS", "ogg"),
    ("FLAC audio", b"fLaC", "flac"),
    ("MP3 (ID3)", b"ID3", "mp3"),
    ("pcap", b"\xd4\xc3\xb2\xa1", "pcap"),
    ("pcap (big endian)", b"\xa1\xb2\xc3\xd4", "pcap"),
    ("pcapng", b"\x0a\x0d\x0d\x0a", "pcapng"),
    ("PGP/GPG armored", b"-----BEGIN PGP", "asc"),
    ("PEM key/cert", b"-----BEGIN ", "pem"),
    ("OLE2 (doc/xls/msg)", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    ("TAR archive", b"ustar", "tar"),
]
# Short magics produce many false positives when scanning inside a file.
EMBEDDED_SKIP = {"BMP image", "PE executable", "zlib stream", "bzip2", "TAR archive"}


def _open_map(path: Path):
    f = open(path, "rb")
    if path.stat().st_size == 0:
        return f, b""
    return f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)


def _identify(head: bytes) -> str:
    if len(head) > 262 and head[257:262] == b"ustar":
        return "TAR archive"
    for name, magic, _ in SIGNATURES:
        if name != "TAR archive" and head.startswith(magic):
            return name
    return "unknown"


def _scan_signatures(data, limit: int = 200) -> list[dict]:
    hits = []
    for name, magic, ext in SIGNATURES:
        if name in EMBEDDED_SKIP:
            continue
        pos = data.find(magic, 1)
        while pos != -1 and len(hits) < limit:
            hits.append({"offset": pos, "hex_offset": hex(pos), "type": name, "ext": ext})
            pos = data.find(magic, pos + 1)
    return sorted(hits, key=lambda h: h["offset"])


def _format_end(data, kind: str) -> int | None:
    """Offset just past the logical end of a PNG/JPEG/GIF/ZIP/PDF that starts at 0."""
    if kind == "PNG image":
        i = data.find(b"IEND")
        return i + 8 if i != -1 else None
    if kind == "JPEG image":
        i = data.rfind(b"\xff\xd9")
        return i + 2 if i != -1 else None
    if kind == "GIF image":
        i = data.rfind(b"\x00\x3b")
        return i + 2 if i != -1 else None
    if kind.startswith("ZIP"):
        i = data.rfind(b"PK\x05\x06")
        if i != -1 and i + 22 <= len(data):
            return i + 22 + struct.unpack("<H", data[i + 20 : i + 22])[0]
    if kind == "PDF document":
        i = data.rfind(b"%%EOF")
        return i + 5 if i != -1 else None
    return None


def file_triage(path: str) -> dict:
    """First look at any challenge file: type (magic bytes and `file`), size, hashes, entropy,
    extension mismatch, embedded files, data appended after the end of the format,
    flags in plain/UTF-16 strings, and suggested next tools."""
    p = resolve_path(path)
    f, data = _open_map(p)
    try:
        kind = _identify(bytes(data[:512]))
        sample = bytes(data[: 64 * 1024 * 1024])
        out: dict = {
            "path": str(p),
            "size": len(data),
            "detected_type": kind,
            "md5": hashlib.md5(sample).hexdigest(),
            "sha256": hashlib.sha256(sample).hexdigest(),
            "entropy_bits_per_byte": round(entropy(sample), 3),
        }
        if shutil.which("file"):
            out["file_command"] = subprocess.run(["file", "-b", str(p)], capture_output=True,
                                                 text=True).stdout.strip()
        ext = p.suffix.lower().lstrip(".")
        expected = next((e for n, m, e in SIGNATURES if n == kind), None)
        if expected and ext and ext not in (expected, "jpeg", "docx", "xlsx", "pptx", "jar", "apk", "odt"):
            out["extension_mismatch"] = f".{ext} file is really {kind}"
        end = _format_end(data, kind)
        if end and end < len(data):
            trailer = bytes(data[end : end + 4096])
            out["appended_data"] = {"offset": end, "length": len(data) - end, "preview": preview(trailer, 600)}
        out["embedded_signatures"] = _scan_signatures(data, 40)
        ascii_strings = re.findall(rb"[\x20-\x7e]{6,}", sample)
        utf16 = [s.decode("utf-16le").encode() for s in re.findall(rb"(?:[\x20-\x7e]\x00){6,}", sample)]
        out["flags"] = find_flags(b"\n".join(ascii_strings + utf16))
        out["interesting_strings"] = [s.decode() for s in ascii_strings
                                      if re.search(rb"(?i)flag|ctf|pass|key|secret|http|base64", s)][:30]
        hints = []
        if out["entropy_bits_per_byte"] > 7.5 and kind == "unknown":
            hints.append("High entropy, unknown type: encrypted or compressed. Try xor_crack or check for a key elsewhere.")
        if kind in ("PNG image", "JPEG image", "GIF image", "BMP image"):
            hints.append("Image: run image_analyze, then stego_lsb_scan; try steghide/stegseek for JPEG via run_tool.")
        if kind.startswith("ZIP"):
            hints.append("Archive: zip_inspect, then zip_crack if encrypted.")
        if kind.startswith("pcap"):
            hints.append("Capture: pcap_summary, then pcap_streams.")
        if kind in ("ELF executable", "PE executable", "Mach-O 64"):
            hints.append("Binary: binary_info, list_functions, disassemble.")
        if out["embedded_signatures"]:
            hints.append("Embedded signatures found: extract_embedded writes each one out.")
        out["next_steps"] = hints
        return out
    finally:
        if isinstance(data, mmap.mmap):
            data.close()
        f.close()


def extract_strings(path: str, min_length: int = 4, encoding: str = "both", pattern: str = "",
                    limit: int = 400) -> dict:
    """Printable strings (ASCII and/or UTF-16LE) with offsets, optionally filtered by a regex."""
    p = resolve_path(path)
    data = p.read_bytes()
    found = []
    if encoding in ("ascii", "both"):
        found += [(m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_length, data)]
    if encoding in ("utf16", "both"):
        found += [(m.start(), m.group().decode("utf-16le"))
                  for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length, data)]
    found.sort()
    if pattern:
        rx = re.compile(pattern, re.I)
        found = [s for s in found if rx.search(s[1])]
    return {
        "count": len(found),
        "strings": [f"{off:#x}: {s[:300]}" for off, s in found[:limit]],
        "flags": find_flags("\n".join(s for _, s in found)),
        "truncated": len(found) > limit,
    }


def hexdump(path: str, offset: int = 0, length: int = 512) -> dict:
    """xxd-style hex dump of part of a file."""
    p = resolve_path(path)
    with open(p, "rb") as f:
        f.seek(offset)
        data = f.read(min(length, 16384))
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{offset + i:08x}: {hx:<47}  {asc}")
    return {"dump": "\n".join(lines)}


def carve(path: str, offset: int, length: int = 0, output_name: str = "") -> dict:
    """Copy bytes [offset, offset+length) of a file into the workspace (length 0 = to EOF)."""
    p = resolve_path(path)
    with open(p, "rb") as f:
        f.seek(offset)
        data = f.read(length or -1)
    out = output_path("carved", output_name or f"{p.stem}_{offset:#x}.bin")
    out.write_bytes(data)
    return {"written": str(out), "length": len(data), "detected_type": _identify(data[:512])}


def extract_embedded(path: str) -> dict:
    """binwalk-style: write every embedded file signature (from its offset up to the next
    signature or the format's end) into the workspace, plus any appended trailer."""
    p = resolve_path(path)
    data = p.read_bytes()
    hits = _scan_signatures(data)
    written = []
    for i, h in enumerate(hits):
        start = h["offset"]
        stop = hits[i + 1]["offset"] if i + 1 < len(hits) else len(data)
        end = _format_end(data[start:stop], h["type"])
        chunk = data[start : start + end] if end else data[start:stop]
        out = output_path(f"extracted/{p.stem}", f"{start:#x}.{h['ext']}")
        out.write_bytes(chunk)
        written.append({"offset": h["hex_offset"], "type": h["type"], "path": str(out), "length": len(chunk)})
        if h["type"].startswith("ZIP"):
            try:
                with zipfile.ZipFile(out) as zf:
                    written[-1]["zip_entries"] = zf.namelist()[:50]
            except zipfile.BadZipFile:
                pass
    return {"extracted": written, "note": "" if written else "No embedded signatures found."}


# --------------------------------------------------------------------------- images

def _png_chunks(data: bytes) -> list[dict]:
    chunks, pos = [], 8
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos : pos + 8])
        body = data[pos + 8 : pos + 8 + length]
        crc = data[pos + 8 + length : pos + 12 + length]
        ok = len(crc) == 4 and zlib.crc32(ctype + body) == struct.unpack(">I", crc)[0]
        chunks.append({"offset": pos, "type": ctype.decode("latin-1"), "length": length, "crc_ok": ok, "body": body})
        pos += 12 + length
        if ctype == b"IEND":
            break
    return chunks


def image_analyze(path: str) -> dict:
    """Image metadata and structure: dimensions, mode, EXIF, PNG chunks (with CRC checks and
    text chunks), JPEG comments, data after the image end, and a quick LSB flag check."""
    from PIL import ExifTags, Image

    p = resolve_path(path)
    data = p.read_bytes()
    out: dict = {"path": str(p)}
    try:
        img = Image.open(p)
        out.update(format=img.format, size=img.size, mode=img.mode,
                   info={k: str(v)[:500] for k, v in img.info.items() if k not in ("icc_profile", "exif")})
        exif = img.getexif()
        if exif:
            out["exif"] = {ExifTags.TAGS.get(k, k): str(v)[:300] for k, v in exif.items()}
            gps = exif.get_ifd(0x8825)
            if gps:
                out["exif_gps"] = {ExifTags.GPSTAGS.get(k, k): str(v) for k, v in gps.items()}
    except Exception as exc:
        out["pillow_error"] = f"{exc} (file may be corrupted; header or CRC may have been tampered with)"

    if data.startswith(b"\x89PNG"):
        chunks = _png_chunks(data)
        out["png_chunks"] = [{k: v for k, v in c.items() if k != "body"} for c in chunks]
        texts = []
        for c in chunks:
            if c["type"] == "tEXt":
                texts.append(c["body"].replace(b"\x00", b": ").decode("latin-1"))
            elif c["type"] == "zTXt":
                key, _, rest = c["body"].partition(b"\x00")
                texts.append(key.decode("latin-1") + ": " + to_text(zlib.decompress(rest[1:])))
            elif c["type"] == "iTXt":
                texts.append(to_text(c["body"]))
        if texts:
            out["png_text"] = texts
        bad = [c["type"] for c in chunks if not c["crc_ok"]]
        if bad:
            out["png_crc_errors"] = bad
            if "IHDR" in bad:
                out["hint"] = "IHDR CRC mismatch: the width/height were probably edited. Run png_fix_dimensions."
        if chunks and chunks[0]["type"] == "IHDR":
            w, h = struct.unpack(">II", chunks[0]["body"][:8])
            out["ihdr"] = {"width": w, "height": h, "bit_depth": chunks[0]["body"][8],
                           "color_type": chunks[0]["body"][9]}
    if data.startswith(b"\xff\xd8"):
        out["jpeg_comments"] = [to_text(m.group(1)[2:])[:500]
                                for m in re.finditer(rb"\xff\xfe(..[^\xff]*)", data, re.S)][:10]

    kind = _identify(data[:512])
    end = _format_end(data, kind)
    if end and end < len(data):
        out["appended_data"] = {"offset": end, "length": len(data) - end, "preview": preview(data[end : end + 2000], 600)}
    out["flags"] = find_flags(data)
    try:
        quick = stego_lsb_scan(path, max_bytes=2048)
        if quick["hits"]:
            out["lsb_hits"] = quick["hits"][:3]
    except Exception:
        pass
    return out


def png_fix_dimensions(path: str, max_dimension: int = 4000) -> dict:
    """Brute-force the PNG width/height that matches the stored IHDR CRC and write a fixed copy."""
    p = resolve_path(path)
    data = bytearray(p.read_bytes())
    if not data.startswith(b"\x89PNG"):
        raise ValueError("Not a PNG")
    ihdr = data[12:29]
    rest = bytes(ihdr[12:17])
    target = struct.unpack(">I", data[29:33])[0]
    w0, h0 = struct.unpack(">II", ihdr[4:12])
    if zlib.crc32(bytes(ihdr)) == target:
        return {"note": "IHDR CRC already matches; dimensions are untouched", "width": w0, "height": h0}

    def check(w, h):
        return zlib.crc32(b"IHDR" + struct.pack(">II", w, h) + rest) == target

    found = None
    # Usually only one dimension was changed; try those first.
    for h in range(1, max_dimension * 2):
        if check(w0, h):
            found = (w0, h)
            break
    if not found:
        for w in range(1, max_dimension * 2):
            if check(w, h0):
                found = (w, h0)
                break
    if not found:
        found = next(((w, h) for w in range(1, max_dimension + 1) for h in range(1, max_dimension + 1)
                      if check(w, h)), None)
    if not found:
        return {"fixed": False, "note": "No dimensions up to max_dimension match the CRC"}
    data[16:24] = struct.pack(">II", *found)
    out = output_path("fixed", f"{p.stem}_fixed.png")
    out.write_bytes(data)
    return {"fixed": True, "original": [w0, h0], "width": found[0], "height": found[1], "written": str(out)}


def _lsb_bytes(img, channels: str, bits: list[int], msb_first: bool, max_bytes: int,
               column_order: bool = False) -> bytes:
    rgba = img.convert("RGBA")
    w, h = rgba.size
    px = rgba.load()
    idx = ["RGBA".index(c) for c in channels]
    out = bytearray()
    acc = nbits = 0
    coords = ((x, y) for x in range(w) for y in range(h)) if column_order else ((x, y) for y in range(h) for x in range(w))
    for x, y in coords:
        pixel = px[x, y]
        for ci in idx:
            for b in bits:
                bit = (pixel[ci] >> b) & 1
                acc = (acc << 1) | bit if msb_first else acc | (bit << nbits)
                nbits += 1
                if nbits == 8:
                    out.append(acc)
                    acc = nbits = 0
                    if len(out) >= max_bytes:
                        return bytes(out)
    return bytes(out)


def lsb_extract(path: str, channels: str = "RGB", bits: list[int] | None = None, msb_first: bool = True,
                column_order: bool = False, max_bytes: int = 200_000, save: bool = True) -> dict:
    """Extract least-significant-bit data from an image. channels is any of R,G,B,A in order
    (e.g. "RGB", "BGR", "R"); bits are bit planes (0 = LSB). Saves the raw stream to the workspace."""
    from PIL import Image

    p = resolve_path(path)
    data = _lsb_bytes(Image.open(p), channels.upper(), bits or [0], msb_first, max_bytes, column_order)
    out = {"preview": preview(data, 1500), "flags": find_flags(data), "detected_type": _identify(data[:512])}
    # Many tools prefix the payload with a 32-bit length.
    if len(data) > 4:
        n = struct.unpack(">I", data[:4])[0]
        if 0 < n < len(data) - 4:
            out["if_length_prefixed"] = preview(data[4 : 4 + n], 500)
    if save:
        dest = output_path("lsb", f"{p.stem}_{channels}_{''.join(map(str, bits or [0]))}.bin")
        dest.write_bytes(data)
        out["written"] = str(dest)
    return out


def stego_lsb_scan(path: str, max_bytes: int = 4096) -> dict:
    """Try common LSB layouts (channel orders, bit planes 0-2, bit order, row/column order)
    and report any that give a flag, a known file header, or mostly printable text."""
    from PIL import Image

    img = Image.open(resolve_path(path))
    has_alpha = "A" in img.getbands()
    channel_sets = ["RGB", "BGR", "R", "G", "B"] + (["RGBA", "A"] if has_alpha else [])
    hits = []
    for channels in channel_sets:
        for bits in ([0], [1], [2], [0, 1]):
            for msb in (True, False):
                for col in (False, True):
                    data = _lsb_bytes(img, channels, bits, msb, max_bytes, col)
                    flags = find_flags(data)
                    kind = _identify(data[:512])
                    ratio = printable_ratio(data[:256])
                    if flags or kind != "unknown" or ratio > 0.92:
                        hits.append({"channels": channels, "bits": bits, "msb_first": msb,
                                     "column_order": col, "flags": flags, "detected_type": kind,
                                     "printable_ratio": round(ratio, 2), "preview": clip(to_text(data[:200]), 200)})
    hits.sort(key=lambda h: (not h["flags"], h["detected_type"] == "unknown", -h["printable_ratio"]))
    return {"hits": hits[:15],
            "note": "Use lsb_extract with a hit's settings for the full stream." if hits else
                    "No LSB payload found. Try zsteg/stegseek/steghide via run_tool, or check bit planes visually."}


def image_bit_planes(path: str, channels: str = "RGB", planes: list[int] | None = None) -> dict:
    """Save black/white images of individual bit planes (like stegsolve) to the workspace,
    so hidden text drawn into low bit planes can be viewed."""
    from PIL import Image

    p = resolve_path(path)
    img = Image.open(p).convert("RGBA")
    written = []
    for c in channels.upper():
        band = img.getchannel(c)
        for plane in planes or [0, 1, 2]:
            out = band.point(lambda v, b=plane: 255 if (v >> b) & 1 else 0)
            dest = output_path(f"planes/{p.stem}", f"{c}{plane}.png")
            out.save(dest)
            written.append(str(dest))
    return {"written": written, "note": "Open these PNGs to look for text or QR codes."}


# --------------------------------------------------------------------------- archives

def zip_inspect(path: str) -> dict:
    """List a ZIP's entries with sizes, CRCs, compression and encryption, plus the archive comment."""
    p = resolve_path(path)
    with zipfile.ZipFile(p) as zf:
        entries = [{"name": i.filename, "size": i.file_size, "compressed": i.compress_size,
                    "crc": f"{i.CRC:08x}", "encrypted": bool(i.flag_bits & 1),
                    "aes": i.compress_type == 99, "comment": to_text(i.comment)} for i in zf.infolist()]
        out = {"entries": entries[:500], "comment": to_text(zf.comment)}
    if any(e["encrypted"] for e in entries):
        out["hint"] = ("Encrypted: try zip_crack. Small files (<=6 bytes) can be recovered by CRC brute force; "
                       "a known file inside allows a bkcrack plaintext attack.")
    out["flags"] = find_flags(out["comment"] + " ".join(e["name"] + e["comment"] for e in entries))
    return out


def zip_crack(path: str, wordlist: str = "", words: list[str] | None = None, extract: bool = True) -> dict:
    """Dictionary attack a ZipCrypto password and extract the archive to the workspace on success.
    (AES-encrypted zips need john/zip2john via run_tool.)"""
    from .crypto import iter_words, wordlist_path

    p = resolve_path(path)
    with zipfile.ZipFile(p) as zf:
        target = min((i for i in zf.infolist() if i.flag_bits & 1 and not i.is_dir()),
                     key=lambda i: i.compress_size, default=None)
        if target is None:
            return {"note": "Archive is not encrypted"}
        if target.compress_type == 99:
            return {"note": "AES encryption is not supported here; use zip2john + john via run_tool"}
        tried = 0
        for word in iter_words(wordlist, words):
            tried += 1
            try:
                zf.read(target, pwd=word.encode("latin-1", "replace"))
            except Exception:
                continue
            result = {"cracked": True, "password": word, "tried": tried}
            if extract:
                dest = output_path("unzipped", p.stem)
                zf.extractall(dest, pwd=word.encode("latin-1", "replace"))
                result["extracted_to"] = str(dest)
                result["files"] = zf.namelist()[:100]
            return result
    used = wordlist_path(wordlist)
    return {"cracked": False, "tried": tried, "wordlist": str(used) if used else "built-in list only"}


# --------------------------------------------------------------------------- network captures

def _load_pcap(p: Path, max_packets: int):
    from scapy.all import PcapReader  # slow import; keep it lazy

    pkts = []
    with PcapReader(str(p)) as reader:
        for pkt in reader:
            pkts.append(pkt)
            if len(pkts) >= max_packets:
                break
    return pkts


def _stream_key(pkt):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if ip is None or l4 is None:
        return None
    a, b = (ip.src, l4.sport), (ip.dst, l4.dport)
    return (l4.name,) + tuple(sorted([a, b]))


def pcap_summary(path: str, max_packets: int = 200_000) -> dict:
    """Overview of a pcap/pcapng: protocols, conversations, DNS names, HTTP requests,
    cleartext credentials (FTP/Telnet/HTTP Basic/POP/IMAP), and flags in any payload."""
    import base64

    from scapy.layers.dns import DNSQR
    from scapy.packet import Raw

    p = resolve_path(path)
    pkts = _load_pcap(p, max_packets)
    protocols = Counter()
    convs = Counter()
    dns, http, creds = [], [], []
    payload_blob = bytearray()
    for pkt in pkts:
        protocols[pkt.lastlayer().name] += 1
        key = _stream_key(pkt)
        if key:
            convs[f"{key[0]} {key[1][0]}:{key[1][1]} <-> {key[2][0]}:{key[2][1]}"] += 1
        if pkt.haslayer(DNSQR):
            name = pkt[DNSQR].qname.decode(errors="replace")
            if name not in dns:
                dns.append(name)
        if pkt.haslayer(Raw):
            load = bytes(pkt[Raw].load)
            if len(payload_blob) < 50_000_000:
                payload_blob += load + b"\n"
            first = load.split(b"\r\n", 1)[0]
            if re.match(rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ", first):
                host = re.search(rb"\r\nHost: ([^\r\n]+)", load)
                http.append(to_text(first)[:200] + (f"  [Host: {to_text(host.group(1))}]" if host else ""))
            for m in re.finditer(rb"(?im)^(USER|PASS|LOGIN|AUTH)\s+([^\r\n]+)", load):
                creds.append(to_text(m.group(0))[:200])
            for m in re.finditer(rb"Authorization: Basic ([A-Za-z0-9+/=]+)", load):
                try:
                    creds.append("HTTP Basic: " + base64.b64decode(m.group(1)).decode(errors="replace"))
                except Exception:
                    pass
    return {
        "packets": len(pkts),
        "protocols": protocols.most_common(20),
        "top_conversations": convs.most_common(20),
        "dns_queries": dns[:100],
        "http_requests": http[:100],
        "credentials": list(dict.fromkeys(creds))[:50],
        "flags": find_flags(bytes(payload_blob)),
        "next_steps": "pcap_streams lists/dumps TCP and UDP streams; DNS names or ICMP payloads may hide exfiltrated data.",
    }


def pcap_streams(path: str, stream_index: int = -1, search: str = "", max_packets: int = 200_000,
                 save: bool = False) -> dict:
    """List reassembled TCP/UDP streams (like Wireshark's Follow Stream), or dump one by index.
    `search` is a regex that filters streams by payload content. save=True writes each
    direction's bytes to the workspace (useful for files transferred over HTTP/FTP)."""
    from scapy.layers.inet import TCP
    from scapy.packet import Raw

    p = resolve_path(path)
    streams: dict = defaultdict(list)
    order = []
    for pkt in _load_pcap(p, max_packets):
        key = _stream_key(pkt)
        if not key or not pkt.haslayer(Raw):
            continue
        if key not in streams:
            order.append(key)
        seq = pkt[TCP].seq if pkt.haslayer(TCP) else len(streams[key])
        streams[key].append((pkt.time, seq, _direction(pkt), bytes(pkt[Raw].load)))

    def assemble(key):
        seen, parts = set(), []
        for _, seq, direction, load in sorted(streams[key], key=lambda x: x[0]):
            if (direction, seq, len(load)) in seen:  # drop retransmissions
                continue
            seen.add((direction, seq, len(load)))
            parts.append((direction, load))
        return parts

    rx = re.compile(search.encode(), re.I) if search else None
    if stream_index < 0:
        listing = []
        for i, key in enumerate(order):
            data = b"".join(load for _, load in assemble(key))
            if rx and not rx.search(data):
                continue
            listing.append({"index": i, "stream": f"{key[0]} {key[1][0]}:{key[1][1]} <-> {key[2][0]}:{key[2][1]}",
                            "bytes": len(data), "start": clip(to_text(data[:120]), 120), "flags": find_flags(data)})
        return {"streams": listing[:300], "total": len(order)}

    key = order[stream_index]
    parts = assemble(key)
    transcript = "".join(f"\n--- {d} ---\n{to_text(load)}" for d, load in parts)
    out = {"stream": str(key), "transcript": clip(transcript), "flags": find_flags(transcript)}
    if save:
        by_dir = defaultdict(bytearray)
        for d, load in parts:
            by_dir[d] += load
        written = []
        for d, data in by_dir.items():
            dest = output_path(f"streams/{p.stem}", f"{stream_index}_{re.sub(r'[^0-9A-Za-z.]+', '_', d)}.bin")
            dest.write_bytes(data)
            written.append(str(dest))
        out["written"] = written
    return out


def _direction(pkt):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    return f"{ip.src}:{l4.sport} -> {ip.dst}:{l4.dport}"


TOOLS = [
    file_triage, extract_strings, hexdump, carve, extract_embedded, image_analyze,
    png_fix_dimensions, lsb_extract, stego_lsb_scan, image_bit_planes, zip_inspect, zip_crack,
    pcap_summary, pcap_streams,
]
