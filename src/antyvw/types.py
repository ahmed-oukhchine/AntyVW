from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    severity: str  # LOW/MEDIUM/HIGH
    category: str
    details: str


@dataclass
class PEInfo:
    machine: str | None = None
    num_sections: int = 0
    entry_point_rva: int = 0
    image_base: int = 0
    compile_time: datetime | None = None
    is_dll: bool = False
    is_64bit: bool = False
    has_signature: bool = False
    sections: list[dict[str, Any]] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    suspicious_imports: list[str] = field(default_factory=list)


@dataclass
class Indicators:
    suspicious_imports: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    yara_matches: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    path: Path
    sha256: str
    md5: str
    file_size: int
    mime_type: str | None = None
    is_pe: bool = False
    pe_info: PEInfo | None = None
    entropy: float = 0.0
    max_section_entropy: float = 0.0
    indicators: Indicators = field(default_factory=Indicators)
    findings: list[Finding] = field(default_factory=list)
    verdict: str = "UNKNOWN"  # CLEAN/SUSPICIOUS/LIKELY_MALICIOUS/UNKNOWN
    risk_score: int = 0
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
