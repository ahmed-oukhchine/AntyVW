from src.antyvw.types import ScanResult


def generate_report(result: ScanResult) -> dict:
    return {
        "file": {
            "path": str(result.path),
            "size": result.file_size,
            "sha256": result.sha256,
            "md5": result.md5,
            "mime_type": result.mime_type,
            "is_pe": result.is_pe,
        },
        "scanned_at": result.scanned_at.isoformat(),
        "entropy": result.entropy,
        "max_section_entropy": result.max_section_entropy,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "findings": [
            {"severity": f.severity, "category": f.category, "details": f.details} for f in result.findings
        ],
        "indicators": {
            "suspicious_imports": result.indicators.suspicious_imports,
            "urls": result.indicators.urls,
            "ips": result.indicators.ips,
            "registry_keys": result.indicators.registry_keys,
            "files": result.indicators.files,
            "yara_matches": result.indicators.yara_matches,
        },
        "pe_info": None
        if not result.pe_info
        else {
            "machine": result.pe_info.machine,
            "num_sections": result.pe_info.num_sections,
            "entry_point_rva": result.pe_info.entry_point_rva,
            "image_base": result.pe_info.image_base,
            "compile_time": result.pe_info.compile_time.isoformat() if result.pe_info.compile_time else None,
            "is_dll": result.pe_info.is_dll,
            "is_64bit": result.pe_info.is_64bit,
            "has_signature": result.pe_info.has_signature,
            "sections": result.pe_info.sections,
            "suspicious_imports": result.pe_info.suspicious_imports,
            "imports_sample": result.pe_info.imports[:50],
        },
    }
