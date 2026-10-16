import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES_DIR = ROOT / "rules"

BUILTIN_RULES = r"""
rule Suspicious_Strings {
    meta:
        description = "Common suspicious strings"
        severity = "medium"
    strings:
        $cmd1 = "cmd.exe" nocase
        $ps1  = "powershell.exe" nocase
        $bits = "bitsadmin" nocase
        $curl = "curl.exe" nocase
        $wget = "wget.exe" nocase
        $cert = "certutil.exe" nocase
        $mshta = "mshta.exe" nocase
        $regsvr = "regsvr32.exe" nocase
        $rundll = "rundll32.exe" nocase
        $wscript = "wscript.exe" nocase
        $cscript = "cscript.exe" nocase
        $schtasks = "schtasks.exe" nocase
        $vbs = ".vbs" nocase
        $bat = ".bat" nocase
        $ps1ext = ".ps1" nocase
    condition:
        any of them
}

rule Potential_Download_Exec {
    meta:
        description = "Download/execute indicators"
        severity = "high"
    strings:
        $s1 = "URLDownloadToFile" nocase
        $s2 = "WinHttpDownloadData" nocase
        $s3 = "ShellExecute" nocase
        $s4 = "CreateProcess" nocase
        $s5 = "VirtualAlloc" nocase
    condition:
        4 of them
}

rule Keylogger_Indications {
    meta:
        description = "Keylogger-like APIs"
        severity = "high"
    strings:
        $k1 = "GetAsyncKeyState"
        $k2 = "SetWindowsHookEx"
        $k3 = "keybd_event"
    condition:
        any of them
}

rule Process_Injection_Ind {
    meta:
        description = "Process injection indicators"
        severity = "high"
    strings:
        $p1 = "CreateRemoteThread"
        $p2 = "OpenProcess"
        $p3 = "WriteProcessMemory"
        $p4 = "VirtualAllocEx"
        $p5 = "NtUnmapViewOfSection"
    condition:
        3 of them
}

rule Ransomware_Note_Ind {
    meta:
        description = "Ransom note / crypto indicators"
        severity = "high"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = "ransom" nocase
        $r5 = "CryptEncrypt" nocase
    condition:
        3 of them
}

rule Persistence_Ind {
    meta:
        description = "Persistence-related strings"
        severity = "medium"
    strings:
        $a1 = "CurrentVersion\\Run" nocase
        $a2 = "schtasks /create" nocase
        $a3 = "New-Service" nocase
        $a4 = "sc create" nocase
        $a5 = "registry" nocase
    condition:
        2 of them
}
"""


def _user_rules_text(rules_dir: Path) -> str:
    if not rules_dir.is_dir():
        return ""
    chunks = []
    for ext in ("*.yar", "*.yara"):
        for f in sorted(rules_dir.glob(ext)):
            try:
                chunks.append(f"// === {f.name} ===\n" + f.read_text(encoding="utf-8"))
            except Exception:
                continue
    return "\n\n".join(chunks)


def build_combined_rules(rules_dir: Path | None = None) -> str:
    rd = rules_dir or DEFAULT_RULES_DIR
    user = _user_rules_text(rd)
    if user:
        return BUILTIN_RULES + "\n\n" + user
    return BUILTIN_RULES


def get_rules_path(rules_dir: Path | None = None) -> Path:
    rd = rules_dir or DEFAULT_RULES_DIR
    text = build_combined_rules(rd)
    # stable filename per rules-dir so caching is predictable
    name = "antyvw_rules.yar"
    p = Path(tempfile.gettempdir()) / name
    try:
        existing = p.read_text(encoding="utf-8") if p.exists() else None
    except Exception:
        existing = None
    if existing != text:
        p.write_text(text, encoding="utf-8")
    return p
