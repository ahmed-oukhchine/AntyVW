import hashlib
import math
import re
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REG_RE = re.compile(r"HKEY_[A-Z_]+\\[^\s'\"<>]+", re.IGNORECASE)
FILEPATH_RE = re.compile(r"[A-Za-z]:\\[^\s'\"<>]+|%[A-Za-z0-9_]+%\\[^\s'\"<>]+")


def sha256_file(path: Path, bufsize: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(bufsize), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: Path, bufsize: int = 65536) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(bufsize), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    # simple ASCII
    res = set()
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                res.add("".join(cur))
            cur = []
    if len(cur) >= min_len:
        res.add("".join(cur))
    return sorted(res)


def extract_iocs(texts: list[str]) -> dict:
    urls, ips, reg, files = set(), set(), set(), set()
    for t in texts:
        urls.update(URL_RE.findall(t))
        ips.update(IP_RE.findall(t))
        reg.update(REG_RE.findall(t))
        files.update(FILEPATH_RE.findall(t))
    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "registry_keys": sorted(reg),
        "files": sorted(files),
    }
