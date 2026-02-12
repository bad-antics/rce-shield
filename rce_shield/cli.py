"""
RCE Shield CLI — Command-line interface for the gaming security scanner.
"""

import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from rce_shield import __version__
from rce_shield.core.scanner import ScanEngine, Finding, Severity
from rce_shield.core.reporter import ReportGenerator
from rce_shield.scanners.launchers import LauncherScanner
from rce_shield.scanners.anticheat import AntiCheatScanner
from rce_shield.scanners.mods import ModScanner
from rce_shield.scanners.network import NetworkScanner
from rce_shield.scanners.overlays import OverlayScanner
from rce_shield.scanners.peripherals import PeripheralScanner

console = Console()

BANNER = r"""
[bold magenta]
  ____   ____ _____   ____  _     _      _     _
 |  _ \ / ___| ____| / ___|| |__ (_) ___| | __| |
 | |_) | |   |  _|   \___ \| '_ \| |/ _ \ |/ _` |
 |  _ <| |___| |___   ___) | | | | |  __/ | (_| |
 |_| \_\\____|_____| |____/|_| |_|_|\___|_|\__,_|
[/bold magenta]
[dim]  Remote Code Execution Hardening for PC Gamers[/dim]
[dim]  Version {version} — NullSec[/dim]
"""


def print_banner():
    console.print(BANNER.format(version=__version__))


@click.group()
@click.version_option(version=__version__)
def main():
    """🛡️ RCE Shield — Protect your gaming PC from remote code execution."""
    pass


@main.command()
@click.option("--full", is_flag=True, help="Run all scan modules")
@click.option("--launchers", is_flag=True, help="Scan game launchers (Steam, Epic, etc.)")
@click.option("--anticheat", is_flag=True, help="Audit anti-cheat drivers")
@click.option("--mods", is_flag=True, help="Scan mods and plugins for malware")
@click.option("--network", is_flag=True, help="Audit gaming network exposure")
@click.option("--overlays", is_flag=True, help="Check overlay and hook security")
@click.option("--peripherals", is_flag=True, help="Audit peripheral software")
@click.option("--output", "-o", type=click.Path(), help="Output report file path")
@click.option("--format", "fmt", type=click.Choice(["terminal", "html", "json", "csv"]),
              default="terminal", help="Output format")
def scan(full, launchers, anticheat, mods, network, overlays, peripherals, output, fmt):
    """🔍 Scan your system for RCE vulnerabilities."""
    print_banner()

    # Default to full if nothing specified
    if not any([full, launchers, anticheat, mods, network, overlays, peripherals]):
        full = True

    engine = ScanEngine()
    all_findings: list[Finding] = []

    scanner_map = {
        "launchers": ("🎮 Game Launchers", LauncherScanner),
        "anticheat": ("🛡️ Anti-Cheat Systems", AntiCheatScanner),
        "mods": ("🔌 Mods & Plugins", ModScanner),
        "network": ("📡 Network Exposure", NetworkScanner),
        "overlays": ("🖥️ Overlays & Hooks", OverlayScanner),
        "peripherals": ("⌨️ Peripheral Software", PeripheralScanner),
    }

    modules_to_run = []
    if full:
        modules_to_run = list(scanner_map.keys())
    else:
        for key, flag in [
            ("launchers", launchers), ("anticheat", anticheat),
            ("mods", mods), ("network", network),
            ("overlays", overlays), ("peripherals", peripherals),
        ]:
            if flag:
                modules_to_run.append(key)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        overall = progress.add_task("Overall Progress", total=len(modules_to_run))

        for module_key in modules_to_run:
            label, scanner_cls = scanner_map[module_key]
            progress.update(overall, description=f"Scanning {label}...")

            scanner = scanner_cls()
            findings = scanner.scan()
            all_findings.extend(findings)

            progress.update(overall, advance=1)

    # Display results
    _display_summary(all_findings)

    if fmt == "terminal":
        _display_findings_table(all_findings)
    else:
        reporter = ReportGenerator(all_findings)
        out_path = output or f"rce_shield_report.{fmt}"

        if fmt == "html":
            reporter.generate_html(out_path)
        elif fmt == "json":
            reporter.generate_json(out_path)
        elif fmt == "csv":
            reporter.generate_csv(out_path)

        console.print(f"\n[green]✓[/green] Report saved: [bold]{out_path}[/bold]")


def _display_summary(findings: list[Finding]):
    """Display the scan summary with severity breakdown."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    table = Table(title="🔍 Scan Summary", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count", justify="center", width=8)
    table.add_column("Bar", width=30)

    max_count = max(counts.values()) if counts.values() else 1
    colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "dim",
    }

    for sev in Severity:
        count = counts[sev]
        bar_len = int((count / max_count) * 25) if max_count > 0 else 0
        bar = "█" * bar_len + "░" * (25 - bar_len)
        color = colors[sev]
        table.add_row(
            f"[{color}]{sev.value}[/{color}]",
            str(count),
            f"[{color}]{bar}[/{color}]",
        )

    console.print()
    console.print(table)

    total = len(findings)
    risk_score = (
        counts[Severity.CRITICAL] * 40
        + counts[Severity.HIGH] * 25
        + counts[Severity.MEDIUM] * 10
        + counts[Severity.LOW] * 3
    )

    risk_label = "LOW"
    risk_color = "green"
    if risk_score > 150:
        risk_label, risk_color = "CRITICAL", "red"
    elif risk_score > 80:
        risk_label, risk_color = "HIGH", "orange3"
    elif risk_score > 30:
        risk_label, risk_color = "MEDIUM", "yellow"

    console.print(
        Panel(
            f"[bold {risk_color}]{risk_label}[/bold {risk_color}]\n"
            f"[dim]Risk Score: {risk_score} | Findings: {total}[/dim]",
            title="Overall Risk Assessment",
            border_style=risk_color,
            expand=False,
            padding=(1, 4),
        )
    )


def _display_findings_table(findings: list[Finding]):
    """Display detailed findings in a table."""
    if not findings:
        console.print("\n[green]✓ No vulnerabilities found![/green]")
        return

    table = Table(
        title="🔍 Detailed Findings",
        box=box.ROUNDED,
        show_lines=True,
        row_styles=["", "dim"],
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Category", width=14)
    table.add_column("Target", width=20)
    table.add_column("Finding", width=40)
    table.add_column("Remediation", width=30)

    colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "dim",
    }

    for i, f in enumerate(sorted(findings, key=lambda x: x.severity.sort_key()), 1):
        color = colors[f.severity]
        table.add_row(
            str(i),
            f"[{color}]{f.severity.value}[/{color}]",
            f.category,
            f.target,
            f.description,
            f.remediation,
        )

    console.print()
    console.print(table)


@main.command()
@click.option("--auto", is_flag=True, help="Auto-fix all fixable issues")
@click.option("--dry-run", is_flag=True, help="Show what would be fixed without changing anything")
@click.option("--backup/--no-backup", default=True, help="Create backups before fixing")
def fix(auto, dry_run, backup):
    """🔧 Auto-remediate detected vulnerabilities."""
    print_banner()
    console.print("[yellow]Fix mode coming in v1.1.0[/yellow]")
    console.print("For now, follow the remediation steps in the scan report.")


@main.command()
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--json", "json_", is_flag=True, help="Generate JSON report")
@click.option("--csv", "csv_", is_flag=True, help="Generate CSV report")
@click.option("--output", "-o", type=click.Path(), default="rce_shield_report",
              help="Output filename (without extension)")
def report(html, json_, csv_, output):
    """📊 Generate a security report from the last scan."""
    print_banner()
    console.print("[yellow]Report generation from cached scans coming in v1.1.0[/yellow]")
    console.print("Use [bold]rce-shield scan --format html -o report.html[/bold] instead.")


@main.command()
@click.option("--daemon", is_flag=True, help="Run as background service")
def monitor(daemon):
    """👁️ Real-time monitoring for suspicious activity."""
    print_banner()

    from rce_shield.core.monitor import RealtimeMonitor

    mon = RealtimeMonitor()
    console.print("[bold cyan]Starting real-time monitoring...[/bold cyan]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        mon.start(daemon=daemon)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")


if __name__ == "__main__":
    main()
