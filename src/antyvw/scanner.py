import datetime
from pathlib import Path

try:
    import magic
except Exception:
    magic = None

try:
    import pefile
except Exception:
    pefile = None

from src.antyvw.heuristics import SUSPICIOUS_APIS
from src.antyvw.types import (
    Finding,
    PEInfo,
    ScanResult,
)
from src.antyvw.utils import (
    extract_iocs,
    extract_strings,
    md5_file,
    sha256_file,
    shannon_entropy,
)
from src.antyvw.yara_scanner import YaraEngine


class StaticScanner:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self.yara = YaraEngine(rules_dir)

    def _detect_mime(self, path: Path) -> str | None:
        if magic is None:
            return None
        try:
            m = magic.Magic(mime=True)
            return m.from_file(str(path))
        except Exception:
            return None

    def _scan_yara(self, path: Path) -> list[str]:
        return self.yara.scan_file(path)

    def scan_file(self, path: Path) -> ScanResult:
        data = path.read_bytes()
        file_size = len(data)
        sha256 = sha256_file(path)
        md5h = md5_file(path)
        mime = self._detect_mime(path)

        res = ScanResult(
            path=path,
            sha256=sha256,
            md5=md5h,
            file_size=file_size,
            mime_type=mime,
        )

        res.entropy = round(shannon_entropy(data), 3)

        strings_all = extract_strings(data)
        iocs = extract_iocs(strings_all)
        res.indicators.urls = iocs["urls"]
        res.indicators.ips = iocs["ips"]
        res.indicators.registry_keys = iocs["registry_keys"]
        res.indicators.files = iocs["files"]

        # String-based suspicious API scan (works for any file type)
        string_api_hits = sorted({s for s in strings_all if s in SUSPICIOUS_APIS})
        if string_api_hits:
            res.indicators.suspicious_imports = string_api_hits
            severity = "HIGH" if len(string_api_hits) >= 4 else "MEDIUM"
            res.findings.append(
                Finding(
                    severity=severity,
                    category="Suspicious Strings",
                    details=f"API/CMD indicators in strings: {', '.join(string_api_hits[:15])}",
                )
            )

        yms = self._scan_yara(path)
        res.indicators.yara_matches = yms
        if yms:
            res.findings.append(
                Finding(
                    severity="HIGH",
                    category="YARA",
                    details=f"Matched rules: {', '.join(yms)}",
                )
            )

        # PE
        is_pe = False
        try:
            if len(data) >= 2 and data[:2] == b"MZ":
                is_pe = True
        except Exception:
            is_pe = False
        res.is_pe = is_pe

        if is_pe and pefile is not None:
            try:
                pe = pefile.PE(data=data)
                peinfo = PEInfo()
                try:
                    mach = pe.FILE_HEADER.Machine
                    peinfo.machine = hex(mach)
                except Exception:
                    peinfo.machine = None
                peinfo.num_sections = pe.FILE_HEADER.NumberOfSections
                peinfo.entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                peinfo.image_base = pe.OPTIONAL_HEADER.ImageBase
                peinfo.is_dll = (pe.FILE_HEADER.Characteristics & 0x2000) != 0
                try:
                    peinfo.is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B
                except Exception:
                    peinfo.is_64bit = False
                try:
                    ts = pe.FILE_HEADER.TimeDateStamp
                    peinfo.compile_time = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                except Exception:
                    peinfo.compile_time = None
                try:
                    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                    ]
                    peinfo.has_signature = sec_dir.Size > 0
                except Exception:
                    peinfo.has_signature = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")

                secs = []
                max_ent = 0.0
                for s in pe.sections:
                    name = s.Name.decode(errors="ignore").strip("\x00")
                    raw = s.get_data() if hasattr(s, "get_data") else b""
                    ent = round(shannon_entropy(raw), 3)
                    if ent > max_ent:
                        max_ent = ent
                    vsize = getattr(s, "Misc_VirtualSize", 0)
                    rsize = s.SizeOfRawData
                    chars = getattr(s, "Characteristics", 0)
                    rwx = False
                    try:
                        rwx = (chars & 0x20000000) != 0 and (chars & 0x40000000) != 0  # EXEC+WRITE rough
                    except Exception:
                        rwx = False
                    secs.append(
                        {
                            "name": name or "",
                            "virtual_size": vsize,
                            "raw_size": rsize,
                            "entropy": ent,
                            "rwx": rwx,
                            "characteristics": hex(chars),
                        }
                    )
                    if ent >= 7.5:
                        res.findings.append(
                            Finding(
                                severity="MEDIUM",
                                category="Entropy",
                                details=f"Section '{name or 'unknown'}' has very high entropy ({ent})",
                            )
                        )
                peinfo.sections = secs
                res.max_section_entropy = round(max_ent, 3)
                if res.max_section_entropy >= 7.8:
                    res.findings.append(
                        Finding(
                            severity="HIGH",
                            category="Entropy",
                            details=f"Very high max section entropy ({res.max_section_entropy}) (possible packing)",
                        )
                    )

                imports_flat = []
                sus_imports = []
                try:
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll = entry.dll.decode(errors="ignore").lower()
                        for imp in entry.imports:
                            nm = imp.name.decode(errors="ignore") if imp.name else f"ord{imp.ordinal}"
                            imports_flat.append(f"{dll}!{nm}")
                            if nm in SUSPICIOUS_APIS:
                                sus_imports.append(nm)
                except Exception:
                    pass
                peinfo.imports = imports_flat[:200]
                peinfo.suspicious_imports = sorted(set(sus_imports))
                res.indicators.suspicious_imports = sorted(
                    set(res.indicators.suspicious_imports) | set(peinfo.suspicious_imports)
                )
                if peinfo.suspicious_imports:
                    res.findings.append(
                        Finding(
                            severity="MEDIUM",
                            category="Imports",
                            details=f"Suspicious APIs: {', '.join(peinfo.suspicious_imports[:15])}",
                        )
                    )

                if peinfo.entry_point_rva == 0:
                    res.findings.append(
                        Finding(
                            severity="LOW",
                            category="PE",
                            details="EntryPoint is 0 (unusual for EXE)",
                        )
                    )
                weird_names = [
                    s["name"]
                    for s in secs
                    if s["name"]
                    and not s["name"].isalnum()
                    and s["name"]
                    not in (
                        ".text",
                        ".data",
                        ".rdata",
                        ".rsrc",
                        ".reloc",
                        ".idata",
                        ".edata",
                        ".pdata",
                        ".bss",
                        ".tls",
                    )
                ]
                if weird_names:
                    res.findings.append(
                        Finding(
                            severity="LOW",
                            category="PE",
                            details=f"Unusual section names: {', '.join(sorted(set(weird_names)))}",
                        )
                    )

                res.pe_info = peinfo
            except Exception as e:
                res.findings.append(Finding(severity="LOW", category="PE", details=f"PE parse error: {e}"))

        # Scoring
        score = 0
        for f in res.findings:
            if f.severity == "HIGH":
                score += 25
            elif f.severity == "MEDIUM":
                score += 10
            elif f.severity == "LOW":
                score += 3
        if score > 100:
            score = 100
        res.risk_score = score
        if score == 0:
            res.verdict = "CLEAN"
        elif score >= 70:
            res.verdict = "LIKELY_MALICIOUS"
        else:
            res.verdict = "SUSPICIOUS"
        return res
