#!/usr/bin/env python3
import json
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src import __version__
from src.antyvw.report import generate_report
from src.antyvw.scanner import StaticScanner

console = Console()

VERDICT_COLORS = {
    "CLEAN": "green",
    "SUSPICIOUS": "yellow",
    "LIKELY_MALICIOUS": "red",
    "UNKNOWN": "white",
}

SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "reports"}

_FONT = {
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚══╝"],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "Y": ["██╗   ██╗", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚██╔╝  ", "   ██║   ", "   ╚═╝   "],
    "V": ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚══╝  "],
    "W": ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
}


def _banner_text(word: str = "ANTYVW") -> Text:
    lines = []
    for row in range(6):
        lines.append("  ".join(_FONT.get(ch, " " * 8)[row] for ch in word))
    text = Text()
    for i, line in enumerate(lines):
        style = "bold cyan" if i < 3 else "bold blue"
        text.append(line + "\n", style=style)
    return text


def show_menu(ctx=None):
    console.print(_banner_text())
    console.print(
        f"  [bold]AntyVW[/bold] [dim]v{__version__}[/dim]  —  [white]Static Malware Detector[/white]\n"
    )

    commands = [
        ("scan", "Scan a file or directory for malicious indicators"),
        ("status", "Show environment and YARA backend status"),
    ]
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2, 0, 2))
    t.add_column("cmd", style="bold green", no_wrap=True)
    t.add_column("desc", style="white")
    for name, desc in commands:
        t.add_row(f"  {name}", desc)
    console.print(t)

    console.print("  [bold]Global options[/bold]")
    console.print("    [green]-h, --help[/green]       Show this menu")
    console.print("    [green]-v, --version[/green]    Show version\n")

    console.print("  [bold]Examples[/bold]")
    console.print("    [cyan]antyvw -scan sample.exe[/cyan]")
    console.print("    [cyan]antyvw scan ./downloads -r -q[/cyan]")
    console.print("    [cyan]antyvw scan sample.exe --json report.json[/cyan]")
    console.print("    [cyan]antyvw status[/cyan]\n")
    console.print("  [dim]Run 'antyvw <command> -h' for command-specific help.[/dim]")


class AntyVWGroup(click.Group):
    """Click group that accepts both 'scan' and '-scan' style commands."""

    _ALIASES = {
        "-scan": "scan",
        "--scan": "scan",
        "scan": "scan",
        "-status": "status",
        "--status": "status",
        "status": "status",
        "-h": "--help",
        "--h": "--help",
        "-help": "--help",
        "-v": "--version",
        "-version": "--version",
        "--v": "--version",
    }

    def main(self, args=None, prog_name=None, complete_var=None, standalone_mode=True, **extra):
        if args is None:
            args = sys.argv[1:]
        if args:
            args = list(args)
            first = args[0].lower()
            if first in self._ALIASES:
                args[0] = self._ALIASES[first]
        if args and args[0] in ("-h", "--help"):
            show_menu(None)
            return
        return super().main(args, prog_name, complete_var, standalone_mode, **extra)


@click.group(
    cls=AntyVWGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, "-v", "--version", prog_name="AntyVW")
@click.pass_context
def cli(ctx):
    """AntyVW - static malware detector."""
    if ctx.invoked_subcommand is None:
        show_menu(ctx)
        ctx.exit(0)


def print_single(result):
    vcol = VERDICT_COLORS.get(result.verdict, "white")
    console.print(
        Panel.fit(
            f"[bold]File:[/bold] {result.path}\n"
            f"[bold]Verdict:[/bold] [{vcol}]{result.verdict}[/]\n"
            f"[bold]Risk Score:[/bold] {result.risk_score}/100\n"
            f"[bold]SHA256:[/bold] {result.sha256}",
            title="Scan Result",
        )
    )

    if result.findings:
        table = Table(title="Findings", box=box.SIMPLE)
        table.add_column("Severity", style="bold")
        table.add_column("Category")
        table.add_column("Details")
        for f in result.findings:
            sev_col = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            table.add_row(f"[{sev_col}]{f.severity}[/]", f.category, f.details)
        console.print(table)

    ind = result.indicators
    rows = [
        ("Suspicious Imports", ind.suspicious_imports),
        ("URLs", ind.urls),
        ("IPs", ind.ips),
        ("Registry", ind.registry_keys),
        ("File Paths", ind.files),
        ("YARA", ind.yara_matches),
    ]
    rows = [(k, v) for k, v in rows if v]
    if rows:
        t = Table(title="Indicators", box=box.SIMPLE)
        t.add_column("Type")
        t.add_column("Values")
        for k, v in rows:
            t.add_row(k, ", ".join(v[:20]))
        console.print(t)

    if result.pe_info:
        p = result.pe_info
        t2 = Table(title="PE Info", box=box.SIMPLE)
        t2.add_column("Field")
        t2.add_column("Value")
        t2.add_row("Machine", str(p.machine))
        t2.add_row("Sections", str(p.num_sections))
        t2.add_row("Entrypoint (RVA)", hex(p.entry_point_rva))
        t2.add_row("Image Base", hex(p.image_base))
        t2.add_row("Compile Time (UTC)", str(p.compile_time))
        t2.add_row("Is DLL", str(p.is_dll))
        t2.add_row("Is 64-bit", str(p.is_64bit))
        t2.add_row("Signed", "[green]Yes[/green]" if p.has_signature else "No")
        console.print(t2)

        if p.sections:
            t3 = Table(title="Sections", box=box.SIMPLE)
            t3.add_column("Name")
            t3.add_column("VSize")
            t3.add_column("RawSize")
            t3.add_column("Entropy")
            t3.add_column("RWX")
            for s in p.sections:
                ent_col = "red" if s["entropy"] >= 7.5 else ("yellow" if s["entropy"] >= 7.0 else "white")
                t3.add_row(
                    s["name"],
                    str(s["virtual_size"]),
                    str(s["raw_size"]),
                    f"[{ent_col}]{s['entropy']}[/]",
                    "[red]Yes[/]" if s["rwx"] else "No",
                )
            console.print(t3)


def collect_files(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    files = []
    if recursive:
        for p in sorted(path.rglob("*")):
            if p.is_file() and not any(part in SKIP_DIRS for part in p.parts):
                files.append(p)
    else:
        for p in sorted(path.iterdir()):
            if p.is_file():
                files.append(p)
    return files


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_out", type=click.Path(path_type=Path), help="Write JSON report to file")
@click.option("-r", "--recursive", is_flag=True, help="Scan directories recursively")
@click.option("-q", "--quiet", is_flag=True, help="Only show non-clean results")
@click.option(
    "--rules-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Directory of custom YARA rules (*.yar/*.yara)",
)
def scan(path: Path, json_out: Path | None, recursive: bool, quiet: bool, rules_dir: Path | None):
    """Scan a file, or a directory (use -r to recurse)."""
    files = collect_files(path, recursive)
    if not files:
        console.print("[yellow]No files to scan.[/yellow]")
        raise SystemExit(1)

    scanner = StaticScanner(rules_dir=rules_dir)
    results = []

    if len(files) == 1:
        res = scanner.scan_file(files[0])
        results.append(res)
        print_single(res)
    else:
        t = Table(title=f"Batch Scan ({len(files)} files)", box=box.SIMPLE)
        t.add_column("Risk", justify="right")
        t.add_column("Verdict")
        t.add_column("File")
        t.add_column("Findings")

        for f in files:
            try:
                res = scanner.scan_file(f)
            except Exception as e:
                console.print(f"[red]Error scanning {f}: {e}[/red]")
                continue
            results.append(res)
            if quiet and res.verdict == "CLEAN":
                continue
            vcol = VERDICT_COLORS.get(res.verdict, "white")
            top = (
                max(
                    [x.severity for x in res.findings],
                    key=lambda s: {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(s, 0),
                )
                if res.findings
                else "-"
            )
            topcol = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(top, "white")
            t.add_row(
                str(res.risk_score),
                f"[{vcol}]{res.verdict}[/]",
                str(res.path),
                f"[{topcol}]{top}[/] ({len(res.findings)})",
            )
        console.print(t)

        counts = {}
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        console.print(f"[bold]Summary:[/bold] {summary}")

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = [generate_report(r) for r in results]
        if len(payload) == 1:
            payload = payload[0]
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        console.print(f"[green]JSON report written:[/green] {json_out}")

    if any(r.verdict in ("LIKELY_MALICIOUS", "SUSPICIOUS") for r in results):
        raise SystemExit(2)


@cli.command()
def status():
    """Show environment / YARA backend status."""
    from src.antyvw.yara_rules import DEFAULT_RULES_DIR
    from src.antyvw.yara_scanner import YaraEngine

    eng = YaraEngine()
    backend = {"python": "yara-python (active)", "cli": "yara CLI (active)", "none": "not available"}[
        eng.backend
    ]
    color = "green" if eng.backend != "none" else "red"
    t = Table(title="AntyVW Status", box=box.SIMPLE)
    t.add_column("Component")
    t.add_column("Status")
    t.add_row("YARA backend", f"[{color}]{backend}[/]")
    t.add_row("Rules file", str(eng.rules_path))
    t.add_row("Custom rules dir", str(DEFAULT_RULES_DIR))
    console.print(t)
    if eng.backend == "none":
        console.print(
            "[yellow]YARA not found.[/yellow] Install with: "
            "[bold]pip install yara-python[/bold] or [bold]dnf install yara[/bold]"
        )


if __name__ == "__main__":
    cli()
