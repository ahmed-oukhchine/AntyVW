import shutil
import subprocess
from pathlib import Path

from src.antyvw.yara_rules import get_rules_path

try:
    import yara as _yara
except Exception:
    _yara = None


class YaraEngine:
    """Uses yara-python if available, else falls back to the `yara` CLI."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_path = get_rules_path(rules_dir)
        self.backend = "none"
        self._rules = None
        self._cli = shutil.which("yara")

        if _yara is not None:
            try:
                self._rules = _yara.compile(filepath=str(self.rules_path))
                self.backend = "python"
            except Exception:
                self._rules = None
        if self.backend == "none" and self._cli:
            self.backend = "cli"

    def scan_file(self, path: Path) -> list[str]:
        if self.backend == "python" and self._rules is not None:
            try:
                matches = self._rules.match(str(path))
                return [m.rule for m in matches]
            except Exception:
                return []
        if self.backend == "cli" and self._cli:
            try:
                proc = subprocess.run(
                    [self._cli, str(self.rules_path), str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                results = []
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line:
                        # format: RuleName filepath
                        results.append(line.split(" ")[0])
                return results
            except Exception:
                return []
        return []
