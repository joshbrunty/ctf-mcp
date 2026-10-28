"""Crypto and encoding tools: auto-decoding, classical ciphers, XOR, hashes and RSA."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import html
import os
import re
import time
import urllib.parse
import zlib
from collections import Counter
from math import gcd
from pathlib import Path

from .common import clip, find_flags, load_input, preview, printable_ratio, resolve_path, to_text

# --------------------------------------------------------------------------- encodings

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
    "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
    "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
    "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0",
    ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-....-": "-", "-..-.": "/", ".--.-.": "@", "-.--.": "(", "-.--.-": ")",
    "..--.-": "_", "---...": ":", "-...-": "=", ".-.-.": "+", ".----.": "'", ".-..-.": '"',
}


def b58decode(s: str) -> bytes:
    s = s.strip()
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def _strict_b64(s: str) -> bytes:
    t = re.sub(r"\s", "", s)
    if len(t) < 4 or not re.fullmatch(r"[A-Za-z0-9+/\-_]+={0,2}", t):
        raise ValueError
    t = t.replace("-", "+").replace("_", "/").rstrip("=")
    return base64.b64decode(t + "=" * (-len(t) % 4), validate=True)


def _strict_b32(s: str) -> bytes:
    t = re.sub(r"\s", "", s).upper()
    if len(t) < 8 or not re.fullmatch(r"[A-Z2-7]+=*", t):
        raise ValueError
    t = t.rstrip("=")
    return base64.b32decode(t + "=" * (-len(t) % 8))


def _strict_hex(s: str) -> bytes:
    t = re.sub(r"0[xX]|\\x|[\s:,]", "", s)
    if len(t) < 2 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        raise ValueError
    return bytes.fromhex(t)


def _strict_binary(s: str) -> bytes:
    t = re.sub(r"\s", "", s)
    if len(t) < 8 or len(t) % 8 or not re.fullmatch(r"[01]+", t):
        raise ValueError
    return bytes(int(t[i : i + 8], 2) for i in range(0, len(t), 8))


def _strict_decimal(s: str) -> bytes:
    parts = re.split(r"[\s,]+", s.strip())
    if len(parts) < 2 or not all(p.isdigit() and int(p) < 256 for p in parts):
        raise ValueError
    return bytes(int(p) for p in parts)


def _strict_octal(s: str) -> bytes:
    parts = re.split(r"[\s,]+", s.strip())
    if len(parts) < 2 or not all(re.fullmatch(r"[0-7]{2,3}", p) and int(p, 8) < 256 for p in parts):
        raise ValueError
    return bytes(int(p, 8) for p in parts)


def _strict_b58(s: str) -> bytes:
    t = s.strip()
    if len(t) < 4 or not all(c in B58 for c in t):
        raise ValueError
    return b58decode(t)


def _strict_b85(s: str) -> bytes:
    t = s.strip()
    if len(t) < 5:
        raise ValueError
    return base64.b85decode(t)


def _strict_a85(s: str) -> bytes:
    t = s.strip()
    if len(t) < 5:
        raise ValueError
    return base64.a85decode(t, adobe=t.startswith("<~"))


def _strict_url(s: str) -> bytes:
    if not re.search(r"%[0-9a-fA-F]{2}", s):
        raise ValueError
    return urllib.parse.unquote_to_bytes(s)


def _strict_html(s: str) -> bytes:
    if not re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-z]+);", s):
        raise ValueError
    return html.unescape(s).encode("utf-8")


def _strict_morse(s: str) -> bytes:
    t = s.strip()
    if not re.fullmatch(r"[.\-/\s|]+", t) or not re.search(r"[.\-]", t):
        raise ValueError
    words = re.split(r"\s*[/|]\s*|\s{3,}", t)
    return " ".join("".join(MORSE[c] for c in w.split()) for w in words).encode()


# Decoders that reject input that is clearly not in their format; used by auto_decode.
STRICT_DECODERS = {
    "base64": _strict_b64,
    "base32": _strict_b32,
    "hex": _strict_hex,
    "binary": _strict_binary,
    "decimal": _strict_decimal,
    "octal": _strict_octal,
    "base58": _strict_b58,
    "base85": _strict_b85,
    "ascii85": _strict_a85,
    "url": _strict_url,
    "html_entities": _strict_html,
    "morse": _strict_morse,
}


def caesar(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def rot47(text: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def atbash(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _text_op(fn):
    return lambda b: fn(b.decode("latin-1")).encode("latin-1")


def _operation(op: str):
    name, _, arg = op.partition(":")
    name = name.strip().lower()
    simple = {
        "from_base64": lambda b: _strict_b64(b.decode()),
        "to_base64": base64.b64encode,
        "from_base32": lambda b: _strict_b32(b.decode()),
        "to_base32": base64.b32encode,
        "from_base58": lambda b: b58decode(b.decode()),
        "to_base58": lambda b: b58encode(b).encode(),
        "from_base85": lambda b: base64.b85decode(b.strip()),
        "to_base85": base64.b85encode,
        "from_ascii85": lambda b: base64.a85decode(b.strip(), adobe=b.strip().startswith(b"<~")),
        "from_hex": lambda b: _strict_hex(b.decode()),
        "to_hex": lambda b: b.hex().encode(),
        "from_binary": lambda b: _strict_binary(b.decode()),
        "to_binary": lambda b: " ".join(f"{x:08b}" for x in b).encode(),
        "from_decimal": lambda b: _strict_decimal(b.decode()),
        "from_octal": lambda b: _strict_octal(b.decode()),
        "from_morse": lambda b: _strict_morse(b.decode()),
        "url_decode": urllib.parse.unquote_to_bytes,
        "url_encode": lambda b: urllib.parse.quote_from_bytes(b).encode(),
        "html_unescape": lambda b: html.unescape(b.decode()).encode(),
        "rot13": _text_op(lambda s: caesar(s, 13)),
        "rot47": _text_op(rot47),
        "atbash": _text_op(atbash),
        "reverse": lambda b: b[::-1],
        "upper": bytes.upper,
        "lower": bytes.lower,
        "zlib_decompress": zlib.decompress,
        "gzip_decompress": gzip.decompress,
        "raw_inflate": lambda b: zlib.decompress(b, -15),
    }
    if name in simple:
        return simple[name]
    if name == "rot":
        return _text_op(lambda s: caesar(s, int(arg)))
    if name == "xor":
        key = bytes.fromhex(arg) if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", arg) else arg.encode()
        return lambda b: xor_bytes(b, key)
    raise ValueError(f"Unknown operation {op!r}")


def transform(data: str, operations: list[str], data_format: str = "text") -> dict:
    """Apply a chain of operations to data, CyberChef style.

    Operations: from_base64, to_base64, from_base32, to_base32, from_base58, to_base58,
    from_base85, to_base85, from_ascii85, from_hex, to_hex, from_binary, to_binary,
    from_decimal, from_octal, from_morse, url_decode, url_encode, html_unescape, rot13,
    rot47, rot:N, atbash, reverse, upper, lower, xor:<hexkey or text key>,
    zlib_decompress, gzip_decompress, raw_inflate.
    data_format: text, hex, base64, int or file (data is then a path).
    """
    b = load_input(data, data_format)
    steps = []
    for op in operations:
        b = _operation(op)(b)
        steps.append({"operation": op, "length": len(b)})
    return {"steps": steps, "result": preview(b, 8000), "flags": find_flags(b)}


def _looks_like_flag(flags: list[str]) -> bool:
    """The default regex matches any word{...}, so a rotated flag ("synt{...}") still matches.
    For letter substitutions only trust prefixes that read like a flag, unless the event's
    own CTF_FLAG_REGEX is set."""
    if os.environ.get("CTF_FLAG_REGEX"):
        return bool(flags)
    return any(re.match(r"(?i)\w*(flag|ctf|key)", f) for f in flags)


def auto_decode(data: str, max_depth: int = 8) -> dict:
    """Recursively peel layered encodings (base64/32/58/85, hex, binary, decimal, octal,
    URL, HTML entities, morse) and try rot13/rot47/atbash/reverse/Caesar on every layer.
    Results that contain a flag are listed first. Use this first on any odd-looking blob."""
    start = data.strip()
    seen = {start}
    results = []
    frontier = [(start, [])]
    for _ in range(max_depth):
        nxt = []
        for text, chain in frontier:
            for name, fn in STRICT_DECODERS.items():
                try:
                    out = fn(text)
                except Exception:
                    continue
                if not out or printable_ratio(out) < 0.85:
                    continue
                s = out.decode("latin-1")
                if s in seen:
                    continue
                seen.add(s)
                results.append({"chain": chain + [name], "output": s, "flags": find_flags(s)})
                nxt.append((s, chain + [name]))
        frontier = nxt[:60]
        if not frontier:
            break

    # Letter substitutions always "succeed", so only keep them when they reveal a flag.
    for text, chain in [(start, [])] + [(r["output"], r["chain"]) for r in results[:200]]:
        if _looks_like_flag(find_flags(text)):
            continue
        candidates = [("rot47", rot47(text)), ("atbash", atbash(text)), ("reverse", text[::-1])]
        candidates += [(f"rot:{k}", caesar(text, k)) for k in range(1, 26)]
        for name, out in candidates:
            flags = find_flags(out)
            if _looks_like_flag(flags) and out not in seen:
                seen.add(out)
                results.append({"chain": chain + [name], "output": out, "flags": flags})

    results.sort(key=lambda r: (not _looks_like_flag(r["flags"]), not r["flags"], len(r["chain"])))
    for r in results:
        r["output"] = clip(r["output"], 1000)
    return {
        "flags": sorted({f for r in results for f in r["flags"]}),
        "results": results[:20],
        "note": "No decodings found; try transform, xor_crack or a cipher tool." if not results else "",
    }


# --------------------------------------------------------------------------- classical ciphers

ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228, "g": 2.015,
    "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749,
    "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056, "u": 2.758,
    "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974, "z": 0.074,
}


def english_score(b: bytes) -> float:
    """Higher is more English-like. Penalises unprintable bytes heavily."""
    score = 0.0
    for x in b:
        c = chr(x).lower()
        if c in ENGLISH_FREQ:
            score += ENGLISH_FREQ[c]
        elif c == " ":
            score += 13
        elif x not in (0x09, 0x0A, 0x0D) and not 0x20 <= x < 0x7F:
            score -= 20
    return score / max(1, len(b))


def _chi_squared(letters: str) -> float:
    n = len(letters)
    if not n:
        return float("inf")
    counts = Counter(letters)
    return sum((counts.get(c, 0) - n * f / 100) ** 2 / (n * f / 100) for c, f in ENGLISH_FREQ.items())


def caesar_bruteforce(text: str) -> dict:
    """All 25 Caesar/ROT shifts, ranked by English likeness; shifts revealing a flag come first."""
    rows = []
    for k in range(1, 26):
        out = caesar(text, k)
        rows.append({"shift": k, "output": clip(out, 500), "flags": find_flags(out),
                     "score": round(english_score(out.encode("latin-1", "replace")), 2)})
    rows.sort(key=lambda r: (not r["flags"], -r["score"]))
    return {"results": rows}


def vigenere(text: str, key: str, decrypt: bool = True) -> dict:
    """Vigenere encrypt/decrypt. Non-letters pass through and do not advance the key."""
    shifts = [ord(c) - 97 for c in key.lower() if c.isalpha()]
    if not shifts:
        raise ValueError("Key must contain letters")
    out, i = [], 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            s = shifts[i % len(shifts)] * (-1 if decrypt else 1)
            out.append(caesar(ch, s))
            i += 1
        else:
            out.append(ch)
    result = "".join(out)
    return {"result": result, "flags": find_flags(result)}


def vigenere_crack(text: str, max_key_length: int = 20) -> dict:
    """Recover a Vigenere key from ciphertext alone (index of coincidence + chi-squared).
    Needs roughly 20x the key length in letters to be reliable."""
    letters = "".join(c for c in text.lower() if c.isascii() and c.isalpha())
    if len(letters) < 10:
        raise ValueError("Need more ciphertext letters")

    def ioc(s: str) -> float:
        n = len(s)
        return sum(v * (v - 1) for v in Counter(s).values()) / (n * (n - 1)) if n > 1 else 0.0

    # Columns need ~15 letters for a meaningful IoC; longer key lengths just overfit.
    scored = []
    for length in range(1, max(1, min(max_key_length, len(letters) // 15)) + 1):
        cols = [letters[i::length] for i in range(length)]
        scored.append((sum(ioc(c) for c in cols) / length, length))
    best = max(s for s, _ in scored)
    # Multiples of the real length score as high as the real one, so take the shortest
    # good lengths and collapse repeated keys ("herdherd" -> "herd").
    lengths = sorted(l for s, l in scored if s >= best * 0.9)[:4]

    candidates = {}
    for length in lengths:
        key = ""
        for col in (letters[i::length] for i in range(length)):
            shift = min(range(26), key=lambda k: _chi_squared(caesar(col, -k)))
            key += chr(97 + shift)
        period = next(p for p in range(1, len(key) + 1) if key == (key[:p] * len(key))[: len(key)])
        key = key[:period]
        if key in candidates:
            continue
        plain = vigenere(text, key)["result"]
        chi = _chi_squared("".join(c for c in plain.lower() if c.isascii() and c.isalpha()))
        candidates[key] = {"key": key, "key_length": len(key), "chi_squared": round(chi, 1),
                           "plaintext": clip(plain, 2000), "flags": find_flags(plain)}
    candidates = list(candidates.values())
    return {"candidates": candidates}


def frequency_analysis(text: str) -> dict:
    """Letter, bigram and byte statistics plus index of coincidence, for substitution ciphers."""
    letters = [c for c in text.lower() if c.isascii() and c.isalpha()]
    n = len(letters)
    counts = Counter(letters)
    bigrams = Counter("".join(letters[i : i + 2]) for i in range(n - 1))
    ic = sum(v * (v - 1) for v in counts.values()) / (n * (n - 1)) if n > 1 else 0
    return {
        "letters": n,
        "letter_frequency": [(c, round(v / n * 100, 2)) for c, v in counts.most_common()] if n else [],
        "top_bigrams": bigrams.most_common(15),
        "index_of_coincidence": round(ic, 4),
        "hint": "IoC near 0.066 suggests a monoalphabetic cipher (Caesar/substitution); "
                "near 0.038 suggests polyalphabetic (Vigenere) or random data. "
                "English order: etaoinshrdlcumwfgypbvkjxqz.",
    }


# --------------------------------------------------------------------------- XOR

def xor_data(data: str, key: str, data_format: str = "hex", key_format: str = "text") -> dict:
    """XOR data with a repeating key. Formats: text, hex, base64, int, file."""
    b = load_input(data, data_format)
    k = load_input(key, key_format)
    out = xor_bytes(b, k)
    return {"result": preview(out, 8000), "flags": find_flags(out)}


def _best_single_byte(b: bytes) -> tuple[int, bytes]:
    key = max(range(256), key=lambda k: english_score(bytes(x ^ k for x in b)))
    return key, bytes(x ^ key for x in b)


def xor_crack(data: str, data_format: str = "hex", known_plaintext: str = "",
              max_key_length: int = 40) -> dict:
    """Break XOR encryption. Tries single-byte keys, repeating keys (Hamming distance), and,
    if you give known_plaintext such as the flag prefix 'flag{', derives the key directly."""
    b = load_input(data, data_format)
    out: dict = {}

    if known_plaintext:
        kp = known_plaintext.encode()
        found = []
        for offset in range(0, max(1, len(b) - len(kp) + 1)):
            stream = xor_bytes(b[offset : offset + len(kp)], kp)
            for period in range(1, len(stream) + 1):
                if all(stream[i] == stream[i % period] for i in range(len(stream))):
                    break
            # Rotate so the key lines up with offset 0 of the data.
            key = bytes(stream[(i - offset) % period] for i in range(period))
            plain = xor_bytes(b, key)
            if printable_ratio(plain) > 0.9 or find_flags(plain):
                found.append({"offset": offset, "key_hex": key.hex(), "key_text": to_text(key),
                              "plaintext": clip(to_text(plain), 2000), "flags": find_flags(plain),
                              "complete_key": period < len(stream)})
            if len(found) >= 5 or offset > 4096:
                break
        out["known_plaintext"] = found or "Known plaintext did not produce readable output at any offset"

    singles = sorted(range(256), key=lambda k: -english_score(bytes(x ^ k for x in b)))[:5]
    out["single_byte"] = [{"key": f"0x{k:02x}", "plaintext": clip(to_text(bytes(x ^ k for x in b)), 500),
                           "flags": find_flags(bytes(x ^ k for x in b))} for k in singles]

    if len(b) >= 8:
        def distance(ks: int) -> float:
            blocks = [b[i * ks : (i + 1) * ks] for i in range(min(8, len(b) // ks))]
            pairs = [(blocks[i], blocks[j]) for i in range(len(blocks)) for j in range(i + 1, len(blocks))]
            if not pairs:
                return float("inf")
            d = sum(bin(x ^ y).count("1") for p, q in pairs for x, y in zip(p, q))
            return d / len(pairs) / ks

        sizes = sorted(range(2, min(max_key_length, len(b) // 2) + 1), key=distance)[:4]
        rep = []
        for ks in sizes:
            key = bytes(_best_single_byte(b[i::ks])[0] for i in range(ks))
            plain = xor_bytes(b, key)
            rep.append({"key_length": ks, "key_hex": key.hex(), "key_text": to_text(key),
                        "plaintext": clip(to_text(plain), 1000), "flags": find_flags(plain),
                        "score": round(english_score(plain), 2)})
        out["repeating_key"] = sorted(rep, key=lambda r: (not r["flags"], -r["score"]))
    return out


# --------------------------------------------------------------------------- hashes

HASH_PATTERNS = [
    (r"^\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}$", "bcrypt (hashcat 3200)"),
    (r"^\$1\$", "md5crypt (hashcat 500)"),
    (r"^\$5\$", "sha256crypt (hashcat 7400)"),
    (r"^\$6\$", "sha512crypt (hashcat 1800)"),
    (r"^\$apr1\$", "Apache apr1 MD5 (hashcat 1600)"),
    (r"^\$argon2", "Argon2"),
    (r"^\$y\$", "yescrypt"),
    (r"^\$P\$|^\$H\$", "phpass / WordPress (hashcat 400)"),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "LM:NTLM pair"),
    (r"^\{SHA\}", "LDAP SHA1 base64"),
]
HEX_LENGTHS = {
    8: ["CRC32", "Adler32"], 16: ["MySQL323", "half MD5"],
    32: ["MD5 (hashcat 0)", "NTLM (hashcat 1000)", "MD4", "LM"],
    40: ["SHA1 (hashcat 100)", "RIPEMD-160", "MySQL5 (without *)"],
    56: ["SHA224", "SHA3-224"], 64: ["SHA256 (hashcat 1400)", "SHA3-256", "BLAKE2s"],
    96: ["SHA384", "SHA3-384"], 128: ["SHA512 (hashcat 1700)", "SHA3-512", "BLAKE2b", "Whirlpool"],
}


def hash_identify(hash_value: str) -> dict:
    """Guess the algorithm of a hash from its format and length, with hashcat modes."""
    h = hash_value.strip()
    guesses = [name for pat, name in HASH_PATTERNS if re.search(pat, h)]
    if re.fullmatch(r"\*[A-F0-9]{40}", h):
        guesses.append("MySQL5 (hashcat 300)")
    if re.fullmatch(r"[a-fA-F0-9]+", h):
        guesses += HEX_LENGTHS.get(len(h), [f"unknown {len(h)}-hex-char hash"])
    return {"hash": h, "length": len(h), "candidates": guesses or ["unknown format"]}


COMMON_PASSWORDS = (
    "password 123456 12345678 qwerty abc123 letmein admin welcome monkey dragon master "
    "iloveyou sunshine princess football baseball shadow superman trustno1 secret password1 "
    "hello test guest root toor changeme 1234 12345 123456789 111111 000000 flag ctf "
    "marshall thundering herd marco hacker pass love god"
).split()

DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/opt/homebrew/share/wordlists/rockyou.txt",
    "~/wordlists/rockyou.txt",
    "~/ctf-workspace/rockyou.txt",
]


def wordlist_path(explicit: str = "") -> Path | None:
    for candidate in [explicit, os.environ.get("CTF_WORDLIST", "")] + DEFAULT_WORDLISTS:
        if candidate and Path(candidate).expanduser().is_file():
            return Path(candidate).expanduser()
    return None


def iter_words(wordlist: str = "", extra: list[str] | None = None):
    yield from extra or []
    yield from COMMON_PASSWORDS
    path = wordlist_path(wordlist)
    if path:
        with open(path, "rb") as f:
            for line in f:
                yield line.rstrip(b"\r\n").decode("latin-1")


def _hashers():
    algos = {name: (lambda n: lambda w: hashlib.new(n, w).hexdigest())(name)
             for name in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512")}
    try:
        hashlib.new("md4", b"")
        algos["ntlm"] = lambda w: hashlib.new("md4", w.decode("latin-1").encode("utf-16le")).hexdigest()
    except ValueError:
        pass
    return algos


def hash_crack(hash_value: str, wordlist: str = "", algorithm: str = "", words: list[str] | None = None,
               time_limit: int = 120) -> dict:
    """Dictionary attack an unsalted hex hash (md5, sha1, sha2, sha3, ntlm). Uses `wordlist`,
    then $CTF_WORDLIST, then rockyou.txt in common locations, plus a built-in list.
    For salted/crypt hashes use run_tool with john or hashcat."""
    target = hash_value.strip().lower()
    algos = _hashers()
    if algorithm:
        algos = {algorithm: algos[algorithm]}
    else:
        algos = {n: f for n, f in algos.items() if len(f(b"")) == len(target)}
    if not algos:
        raise ValueError("No supported algorithm matches this hash length")
    deadline = time.monotonic() + time_limit
    tried = 0
    for word in iter_words(wordlist, words):
        w = word.encode("latin-1", "replace")
        for name, fn in algos.items():
            if fn(w) == target:
                return {"cracked": True, "algorithm": name, "password": word, "tried": tried}
        tried += 1
        if tried % 50_000 == 0 and time.monotonic() > deadline:
            return {"cracked": False, "tried": tried, "note": f"Stopped after {time_limit}s"}
    used = wordlist_path(wordlist)
    return {"cracked": False, "tried": tried, "algorithms": list(algos),
            "wordlist": str(used) if used else "built-in list only (set CTF_WORDLIST to rockyou.txt)"}


# --------------------------------------------------------------------------- RSA

def _int(x) -> int | None:
    if x is None or x == "":
        return None
    s = str(x).strip().replace(" ", "")
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def iroot(k: int, n: int) -> tuple[int, bool]:
    """Integer k-th root of n and whether it is exact."""
    if n < 2:
        return n, True
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            break
        x = y
    return x, x ** k == n


def long_to_bytes(n: int) -> bytes:
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _small_primes(limit: int) -> list[int]:
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    return [i for i, v in enumerate(sieve) if v]


def _fermat(n: int, iterations: int = 200_000) -> int | None:
    a, exact = iroot(2, n)
    if exact:
        return a
    a += 1
    for _ in range(iterations):
        b, exact = iroot(2, a * a - n)
        if exact:
            return a - b
        a += 1
    return None


def _pollard_p1(n: int, bound: int = 100_000) -> int | None:
    a = 2
    for p in _small_primes(bound):
        pk = p
        while pk * p <= bound:
            pk *= p
        a = pow(a, pk, n)
    g = gcd(a - 1, n)
    return g if 1 < g < n else None


def _wiener(e: int, n: int) -> int | None:
    # Continued fraction convergents of e/n give k/d when d < n^0.25 / 3.
    num, den = e, n
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    h0, h1, k0, k1 = 0, 1, 1, 0
    for q in cf:
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        k, d = h1, k1
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            r, exact = iroot(2, disc)
            if exact and (s + r) % 2 == 0:
                return d
    return None


def _factordb(n: int) -> list[int] | None:
    import httpx

    r = httpx.get("http://factordb.com/api", params={"query": str(n)}, timeout=15)
    data = r.json()
    if data.get("status") not in ("FF",):
        return None
    factors = []
    for f, mult in data["factors"]:
        factors += [int(f)] * int(mult)
    return factors


def _factor(n: int, log: list[str], use_factordb: bool) -> list[int] | None:
    if is_probable_prime(n):
        log.append("n is prime: phi = n - 1")
        return [n]
    factors, rest = [], n
    for p in _small_primes(1_000_000):
        while rest % p == 0:
            factors.append(p)
            rest //= p
    if factors:
        log.append(f"Trial division found small factors {factors}")
    if rest == 1:
        return factors
    if is_probable_prime(rest):
        return factors + [rest]
    for name, fn in (("Fermat (p and q close together)", _fermat), ("Pollard p-1", _pollard_p1)):
        p = fn(rest)
        if p and 1 < p < rest:
            log.append(f"{name} succeeded")
            return factors + sorted([p, rest // p])
    if use_factordb:
        try:
            fdb = _factordb(rest)
            if fdb:
                log.append("factordb.com had the full factorisation")
                return factors + fdb
            log.append("factordb.com does not know the factors")
        except Exception as exc:  # network is optional
            log.append(f"factordb lookup failed: {exc}")
    return None


def _phi(factors: list[int]) -> int:
    phi = 1
    for p, k in Counter(factors).items():
        phi *= (p - 1) * p ** (k - 1)
    return phi


def rsa_solve(n: str, e: str = "65537", c: str = "", p: str = "", q: str = "", d: str = "",
              phi: str = "", use_factordb: bool | None = None) -> dict:
    """Recover RSA plaintext. Pass numbers as decimal or 0x-hex strings. Tries, in order:
    given p/q/d/phi, small-exponent cube root (incl. c + k*n), trial division and multi-prime,
    Fermat, Pollard p-1, Wiener (large e), then factordb.com (unless disabled by env/hosted)."""
    from .config import factordb_default

    if use_factordb is None:
        use_factordb = factordb_default()
    N, E, C = _int(n), _int(e), _int(c)
    P, Q, D, PHI = _int(p), _int(q), _int(d), _int(phi)
    log: list[str] = []
    result: dict = {"log": log}

    def finish(m: int, how: str) -> dict:
        pt = long_to_bytes(m)
        result.update(method=how, m=str(m), plaintext=preview(pt, 4000), flags=find_flags(pt))
        return result

    if C is not None and D is not None:
        return finish(pow(C, D, N), "given d")

    if C is not None and E <= 17 and not (P or Q or PHI):
        for k in range(0, 5000):
            root, exact = iroot(E, C + k * N)
            if exact:
                return finish(root, f"small e={E}: m = iroot(c + {k}*n, e)")
        log.append("Small-e root attack failed")

    if PHI is None:
        if P and not Q:
            Q = N // P
        if Q and not P:
            P = N // Q
        factors = [P, Q] if P and Q else None
        if factors is None:
            d_w = _wiener(E, N) if E > 65537 else None
            if d_w:
                log.append("Wiener attack recovered d")
                result["d"] = str(d_w)
                if C is not None:
                    return finish(pow(C, d_w, N), "Wiener (small d)")
                return result
            factors = _factor(N, log, use_factordb)
        if not factors:
            result["error"] = ("Could not factor n. Ideas: shared primes across several keys "
                               "(gcd), Hastad broadcast, common modulus, or partial key leakage.")
            return result
        result["factors"] = [str(f) for f in factors]
        PHI = _phi(factors)

    if gcd(E, PHI) != 1:
        result["error"] = f"gcd(e, phi) = {gcd(E, PHI)} != 1; e has no inverse (try e-th roots mod p)"
        return result
    D = pow(E, -1, PHI)
    result["d"] = str(D)
    if C is None:
        return result
    return finish(pow(C, D, N), "factored n")


def rsa_hastad(n_values: list[str], c_values: list[str], e: str = "3") -> dict:
    """Hastad broadcast attack: the same message encrypted with small e under e different moduli."""
    ns = [_int(x) for x in n_values]
    cs = [_int(x) for x in c_values]
    E = _int(e)
    total = 1
    for x in ns:
        total *= x
    acc = 0
    for ni, ci in zip(ns, cs):
        m = total // ni
        acc += ci * m * pow(m, -1, ni)
    root, exact = iroot(E, acc % total)
    pt = long_to_bytes(root)
    return {"exact_root": exact, "plaintext": preview(pt, 4000), "flags": find_flags(pt)}


def rsa_common_modulus(n: str, e1: str, c1: str, e2: str, c2: str) -> dict:
    """Same message and modulus encrypted under two coprime exponents."""
    N, E1, C1, E2, C2 = map(_int, (n, e1, c1, e2, c2))

    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y

    g, a, b = egcd(E1, E2)
    if g != 1:
        raise ValueError("e1 and e2 must be coprime")
    m = pow(C1, a, N) * pow(C2, b, N) % N
    pt = long_to_bytes(m)
    return {"plaintext": preview(pt, 4000), "flags": find_flags(pt)}


def rsa_shared_prime(n_values: list[str]) -> dict:
    """Find moduli that share a prime factor (pairwise gcd)."""
    ns = [_int(x) for x in n_values]
    hits = []
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = gcd(ns[i], ns[j])
            if 1 < g < max(ns[i], ns[j]):
                hits.append({"pair": [i, j], "shared_prime": str(g),
                             "q_i": str(ns[i] // g), "q_j": str(ns[j] // g)})
    return {"shared": hits}


def rsa_parse_key(key: str) -> dict:
    """Extract n, e (and d, p, q for private keys) from a PEM/DER key, given as text or a path."""
    from Crypto.PublicKey import RSA

    try:
        raw = resolve_path(key).read_bytes()
    except (FileNotFoundError, OSError):
        raw = key.encode()
    k = RSA.import_key(raw)
    out = {"bits": k.size_in_bits(), "n": str(k.n), "e": str(k.e), "private": k.has_private()}
    if k.has_private():
        out.update(d=str(k.d), p=str(k.p), q=str(k.q))
    return out


TOOLS = [
    auto_decode, transform, caesar_bruteforce, vigenere, vigenere_crack, frequency_analysis,
    xor_data, xor_crack, hash_identify, hash_crack, rsa_solve, rsa_hastad,
    rsa_common_modulus, rsa_shared_prime, rsa_parse_key,
]
