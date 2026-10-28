import asyncio
import base64
import hashlib
import io
import zipfile

import pytest
from PIL import Image

from conftest import build_elf, png_bytes
from ctf_mcp import crypto, execution, forensics, reversing, web
from ctf_mcp.common import find_flags

FLAG = "flag{mcp_works}"


# --------------------------------------------------------------------------- crypto

def test_auto_decode_peels_layers():
    blob = base64.b64encode(FLAG.encode().hex().encode()).decode()
    out = crypto.auto_decode(blob)
    assert FLAG in out["flags"]
    assert out["results"][0]["chain"] == ["base64", "hex"]


def test_auto_decode_finds_rot13_inside_base32():
    blob = base64.b32encode(crypto.caesar(FLAG, 13).encode()).decode()
    assert FLAG in crypto.auto_decode(blob)["flags"]


def test_transform_chain():
    out = crypto.transform(FLAG, ["to_base64", "reverse", "reverse", "from_base64", "rot13", "rot13"])
    assert out["flags"] == [FLAG]


def test_vigenere_roundtrip_and_crack():
    plain = ("It was the best of times it was the worst of times it was the age of wisdom it was the "
             "age of foolishness it was the epoch of belief it was the epoch of incredulity " + FLAG)
    enc = crypto.vigenere(plain, "herd", decrypt=False)["result"]
    assert crypto.vigenere(enc, "herd")["result"] == plain
    best = crypto.vigenere_crack(enc)["candidates"][0]
    assert best["key"] == "herd"


def test_xor_known_plaintext_and_single_byte():
    secret = crypto.xor_bytes(f"some padding text then {FLAG}".encode(), b"key")
    out = crypto.xor_crack(secret.hex(), known_plaintext="some p")
    assert FLAG in out["known_plaintext"][0]["flags"]
    single = crypto.xor_bytes(b"The quick brown fox " + FLAG.encode(), b"\x42")
    assert crypto.xor_crack(single.hex())["single_byte"][0]["key"] == "0x42"


def test_hash_identify_and_crack():
    h = hashlib.md5(b"thunderingherd").hexdigest()
    assert any("MD5" in c for c in crypto.hash_identify(h)["candidates"])
    out = crypto.hash_crack(h, words=["nope", "thunderingherd"])
    assert out["cracked"] and out["password"] == "thunderingherd"


def test_rsa_small_e_and_factoring():
    m = int.from_bytes(FLAG.encode(), "big")
    p, q = 1000000007, 1000000009  # close primes: Fermat finds them
    n = p * q
    small = int.from_bytes(b"hi!", "big")
    c = pow(small, 65537, n)
    out = crypto.rsa_solve(str(n), "65537", str(c), use_factordb=False)
    assert out["plaintext"]["text"] == "hi!"

    big_n = (2**521 - 1) * (2**607 - 1)
    out = crypto.rsa_solve(str(big_n), "3", str(pow(m, 3, big_n)), use_factordb=False)
    assert FLAG in out["flags"]


def test_rsa_common_modulus():
    from Crypto.Util.number import getPrime

    p, q = getPrime(256), getPrime(256)
    n = p * q
    m = int.from_bytes(FLAG.encode(), "big")
    out = crypto.rsa_common_modulus(str(n), "17", str(pow(m, 17, n)), "65537", str(pow(m, 65537, n)))
    assert FLAG in out["flags"]


# --------------------------------------------------------------------------- forensics

def test_file_triage_finds_appended_zip(isolated_workspace):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("flag.txt", FLAG)
    path = isolated_workspace / "cat.png"
    path.write_bytes(png_bytes(2, 2, [(1, 2, 3)] * 4) + buf.getvalue())
    out = forensics.file_triage(str(path))
    assert out["detected_type"] == "PNG image"
    assert out["appended_data"]["offset"] > 0
    assert any(s["type"].startswith("ZIP") for s in out["embedded_signatures"])
    extracted = forensics.extract_embedded(str(path))["extracted"]
    assert "flag.txt" in extracted[0]["zip_entries"]


def test_png_fix_dimensions(isolated_workspace):
    data = bytearray(png_bytes(4, 3, [(0, 0, 0)] * 12))
    data[20:24] = (1).to_bytes(4, "big")  # height 3 -> 1, CRC left stale
    path = isolated_workspace / "short.png"
    path.write_bytes(data)
    assert "IHDR" in forensics.image_analyze(str(path))["png_crc_errors"]
    out = forensics.png_fix_dimensions(str(path))
    assert (out["width"], out["height"]) == (4, 3)


def test_lsb_roundtrip(isolated_workspace):
    payload = FLAG.encode() + b"\x00" * 4
    bits = [int(b) for byte in payload for b in f"{byte:08b}"]
    w = h = 16
    pixels = []
    for i in range(w * h):
        rgb = []
        for c in range(3):
            k = i * 3 + c
            rgb.append(0x80 | (bits[k] if k < len(bits) else 0))
        pixels.append(tuple(rgb))
    img = Image.new("RGB", (w, h))
    img.putdata(pixels)
    path = isolated_workspace / "lsb.png"
    img.save(path)
    assert FLAG in forensics.lsb_extract(str(path))["flags"]
    hits = forensics.stego_lsb_scan(str(path))["hits"]
    assert hits and FLAG in hits[0]["flags"]


def test_pcap_summary_and_streams(isolated_workspace):
    from scapy.all import IP, TCP, Raw, wrpcap

    pkts = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=4444, dport=21, seq=1) / Raw(b"USER herd\r\n"),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=4444, dport=21, seq=12) / Raw(b"PASS " + FLAG.encode() + b"\r\n")]
    path = isolated_workspace / "ftp.pcap"
    wrpcap(str(path), pkts)
    summary = forensics.pcap_summary(str(path))
    assert FLAG in summary["flags"]
    assert any("USER herd" in c for c in summary["credentials"])
    streams = forensics.pcap_streams(str(path))
    assert streams["total"] == 1
    assert FLAG in forensics.pcap_streams(str(path), stream_index=0)["transcript"]


# --------------------------------------------------------------------------- reversing

@pytest.fixture
def elf_path(isolated_workspace):
    path = isolated_workspace / "chall"
    path.write_bytes(build_elf())
    return str(path)


def test_binary_info_checksec(elf_path):
    out = reversing.binary_info(elf_path)
    assert out["arch"] == "x64"
    assert out["checksec"]["nx"] and not out["checksec"]["pie"] and not out["checksec"]["canary"]
    assert "win" in out["win_like_functions"]
    assert FLAG.replace("mcp_works", "elf_test") in out["flags"]


def test_disassemble_and_gadgets(elf_path):
    dis = reversing.disassemble(elf_path, function="main")["disassembly"]
    assert "call" in dis and "<win>" in dis
    gadgets = reversing.find_gadgets(elf_path, query="pop rdi")["gadgets"]
    assert gadgets and gadgets[0].startswith("0x40020a")


def test_cyclic_matches_pwntools():
    pat = reversing.cyclic(1000)["pattern"]
    assert pat.startswith("aaaabaaacaaadaaa")
    assert reversing.cyclic_find("0x6161616c")["offset"] == 44  # 'laaa'
    assert reversing.cyclic_find("faab")["offset"] == pat.find("faab")
    assert reversing.pack("0xdeadbeef", 32)["hex"] == "efbeadde"
    assert reversing.unpack("efbeadde", 32)["value"] == "0xdeadbeef"


# --------------------------------------------------------------------------- web / exec

def test_scope_enforcement(monkeypatch):
    assert "not set" in web.check_scope("anything.example")
    monkeypatch.setenv("CTF_SCOPE", "*.ctf.marshall.edu,10.10.0.0/16,chal.example.com")
    assert web.check_scope("web1.ctf.marshall.edu") == ""
    assert web.check_scope("10.10.4.20") == ""
    assert web.check_scope("chal.example.com") == ""
    with pytest.raises(PermissionError):
        web.check_scope("scoreboard.example.com")
    with pytest.raises(PermissionError):
        web.http_request("http://8.8.8.8/")


def test_jwt_crack_and_forge():
    token = web.jwt_forge({"user": "guest"}, secret="herd")["token"]
    assert web.jwt_decode(token)["payload"]["user"] == "guest"
    assert web.jwt_crack(token, words=["x", "herd"])["secret"] == "herd"
    none_token = web.jwt_forge({"user": "admin"}, alg="none")["token"]
    assert none_token.endswith(".") and web.jwt_decode(none_token)["payload"]["user"] == "admin"


def test_run_python_and_tool_allowlist(monkeypatch):
    out = execution.run_python(f"print('{FLAG}')")
    assert out["flags"] == [FLAG]
    with pytest.raises(PermissionError):
        execution.run_tool(["rm", "-rf", "/"])
    monkeypatch.setenv("CTF_MCP_DISABLE_EXEC", "1")
    with pytest.raises(PermissionError):
        execution.run_python("print(1)")


def test_custom_flag_regex(monkeypatch):
    monkeypatch.setenv("CTF_FLAG_REGEX", r"MUCTF\{[^}]+\}")
    assert find_flags("flag{no} MUCTF{yes}") == ["MUCTF{yes}"]


def test_server_registers_all_tools():
    from ctf_mcp.server import mcp

    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {"auto_decode", "file_triage", "disassemble", "http_request", "run_python"} <= names
    assert len(names) == sum(len(m.TOOLS) for m in (crypto, forensics, reversing, web, execution))
