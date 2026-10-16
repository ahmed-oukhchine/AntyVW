# AntyVW

A minimal, **static-only** malware detector for Windows PE files. It never
executes samples. It computes hashes, parses PE metadata, measures entropy,
flags suspicious APIs/strings, extracts IOCs, and runs YARA rules.

## Features

| Module | What it does |
|---|---|
| Hashing | SHA256 + MD5 |
| File typing | MIME type detection (`python-magic`) |
| Strings | ASCII string extraction (min length 6) |
| IOC extraction | URLs, IPs, registry keys, file paths |
| Suspicious APIs | Match against a curated API/keyword list (works on any file type) |
| PE analysis | Machine, sections, entrypoint, image base, compile time, DLL/64-bit, section entropy, RWX sections, imports, Authenticode presence |
| Entropy | Shannon entropy (whole file + per section) to spot packing/encryption |
| YARA | Built-in rules + your own rules in `rules/` (via `yara-python` or the `yara` CLI) |
| Scoring | Weighted 0–100 risk score + verdict |
| Output | Rich terminal report + JSON |

## Safety

- **Static only** — no execution, no network calls.
- Only analyze files you own or that are legal to analyze.
- Do not upload samples to third-party services.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`python-magic` needs `libmagic`:

- Fedora: `sudo dnf install file-devel`
- Debian/Ubuntu: `sudo apt install libmagic1`

### Optional: enable YARA

Either install the Python bindings:

```bash
pip install yara-python
```

or the YARA CLI:

```bash
sudo dnf install yara      # or: sudo apt install yara
```

Without either, AntyVW still runs but skips YARA matching.

## Install the `antyvw` command

The project ships a launcher script named `antyvw`. Symlink it into a directory
that is on your `PATH` (e.g. `~/.local/bin`) so you can run it from anywhere:

```bash
ln -sf "$(pwd)/antyvw" ~/.local/bin/antyvw
antyvw            # shows the banner + command menu
```

If `~/.local/bin` is not on your `PATH`, add it:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

## Usage

Run `antyvw` with no arguments (or `antyvw -h`) to see the full menu and
available commands.

```bash
# Show the menu / all commands
antyvw

# Scan a single file (both forms work: -scan or scan)
antyvw -scan suspicious.exe
antyvw scan suspicious.exe

# Write a JSON report
antyvw scan suspicious.exe --json reports/scan.json

# Scan a directory (recursive), show only non-clean files
antyvw scan ./downloads -r -q

# Use a custom rules folder
antyvw scan sample.bin --rules-dir ./my_rules

# Show YARA backend status
antyvw status
```

If you prefer not to install the launcher, you can always run it directly:

```bash
python -m src.main scan suspicious.exe
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All scanned files CLEAN |
| 1 | Usage/IO error (no files) |
| 2 | At least one SUSPICIOUS or LIKELY_MALICIOUS result (scripting-friendly) |

## How scoring works

Each finding adds to a 0–100 risk score:

- HIGH severity: +25
- MEDIUM severity: +10
- LOW severity: +3

Verdict thresholds:

- `0` → CLEAN
- `1–69` → SUSPICIOUS
- `>= 70` → LIKELY_MALICIOUS

> The score is a heuristic convenience, not a verdict of fact. Signed,
> legitimate binaries can still be flagged (e.g. debugger/injection APIs).

## Custom YARA rules

Drop `*.yar` / `*.yara` files into `rules/` (or pass `--rules-dir`). They are
combined with the built-in rules automatically. See `rules/custom.yar` for
examples.

## Project layout

```
antyvw                    # launcher script (symlink into ~/.local/bin)
src/
  main.py                 # CLI (click + rich) + banner/menu
  antyvw/
    scanner.py            # orchestration / PE logic
    heuristics.py         # suspicious API list
    utils.py              # hashing, entropy, strings, IOC regex
    yara_scanner.py       # yara-python / yara CLI backend
    yara_rules.py         # built-in rules + rules-dir loader
    report.py             # JSON report shape
    types.py              # dataclasses
rules/
  custom.yar              # your rules here
tests/
  test_scanner.py         # pytest or `python tests/test_scanner.py`
```

## Development

```bash
pip install pytest ruff
ruff check src tests
ruff format src tests
python -m pytest -q
```

## Known limitations

- Windows-only PE focus; ELF/Office/PDF/scripts are only checked for strings/YARA.
- `has_signature` reports presence of an Authenticode blob, not validity.
- No unpacking, no emulation, no sandboxing (by design — static only).
- Heuristic scoring will produce false positives on some legitimate software.

## Possible next steps

- ELF analysis via `lief`
- Office macro / PDF analysis (`oletools`, `pdfid`)
- Hash reputation lookup (VirusTotal / MalwareBazaar) — opt-in, offline default
- Packer detection & UPX unpacking
- ML classifier (EMBER-style features)
