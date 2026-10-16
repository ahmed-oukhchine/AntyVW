import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.antyvw.scanner import StaticScanner  # noqa: E402
from src.antyvw.utils import extract_iocs, extract_strings, shannon_entropy  # noqa: E402

SAMPLES = ROOT / "samples"


def make_tmp(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_entropy_random_is_high():
    import os

    rnd = os.urandom(4096)
    ent = shannon_entropy(rnd)
    assert ent > 7.0, f"random entropy too low: {ent}"


def test_entropy_constant_is_zero():
    assert shannon_entropy(b"\x00" * 1024) == 0.0


def test_entropy_text_is_low():
    assert shannon_entropy(b"A" * 1000) < 1.0


def test_extract_strings():
    data = b"hello world\x00\x01\x02ABCD\x00"
    out = extract_strings(data, min_len=4)
    assert "hello world" in out
    assert "ABCD" in out


def test_extract_iocs():
    texts = [
        "visit http://evil.example/payload.exe",
        "connect to 10.0.0.5 now",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "dropped to C:\\Users\\a\\Temp\\bad.exe",
    ]
    i = extract_iocs(texts)
    assert i["urls"] == ["http://evil.example/payload.exe"]
    assert i["ips"] == ["10.0.0.5"]
    assert i["registry_keys"]
    assert i["files"]


def test_clean_file(workfile=ROOT / "samples" / "_t_clean.bin"):
    make_tmp(workfile, b"just some ordinary text without anything suspicious at all")
    s = StaticScanner()
    r = s.scan_file(workfile)
    assert r.verdict == "CLEAN", r.verdict
    assert r.risk_score == 0
    assert r.sha256
    assert r.md5
    workfile.unlink()


def test_suspicious_file(workfile=ROOT / "samples" / "_t_susp.bin"):
    make_tmp(
        workfile,
        b"CreateRemoteThread\x00WriteProcessMemory\x00VirtualAllocEx\x00OpenProcess\x00NtUnmapViewOfSection\x00",
    )
    s = StaticScanner()
    r = s.scan_file(workfile)
    assert r.verdict in ("SUSPICIOUS", "LIKELY_MALICIOUS"), r.verdict
    assert r.risk_score > 0
    assert "CreateRemoteThread" in r.indicators.suspicious_imports
    workfile.unlink()


def test_fake_mz_is_flagged_as_pe_error(workfile=ROOT / "samples" / "_t_mz.bin"):
    make_tmp(workfile, b"MZ" + b"\x00" * 64)
    s = StaticScanner()
    r = s.scan_file(workfile)
    assert r.is_pe is True
    assert any(f.category == "PE" for f in r.findings)
    workfile.unlink()


def test_non_pe_not_crash(workfile=ROOT / "samples" / "_t_plain.bin"):
    make_tmp(workfile, b"\x00\x01\x02\x03plain")
    s = StaticScanner()
    r = s.scan_file(workfile)
    assert r.is_pe is False
    assert r.verdict == "CLEAN"
    workfile.unlink()


def test_yara_backend_available():
    from src.antyvw.yara_scanner import YaraEngine

    eng = YaraEngine()
    assert eng.backend in ("python", "cli", "none")
    if eng.backend != "none":
        f = ROOT / "samples" / "_t_yara.bin"
        make_tmp(f, b"powershell.exe\x00bitsadmin\x00certutil.exe\x00")
        matches = eng.scan_file(f)
        assert "Suspicious_Strings" in matches, matches
        f.unlink()


def test_report_structure():
    from src.antyvw.report import generate_report

    make_tmp(ROOT / "samples" / "_t_rep.bin", b"hello")
    s = StaticScanner()
    r = s.scan_file(ROOT / "samples" / "_t_rep.bin")
    rep = generate_report(r)
    assert rep["file"]["sha256"] == r.sha256
    assert "verdict" in rep and "findings" in rep and "indicators" in rep
    (ROOT / "samples" / "_t_rep.bin").unlink()


if __name__ == "__main__":
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"PASS {t.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
