"""
Real-time filesystem and process monitor for gaming security.
"""

import os
import sys
import time
import platform
from pathlib import Path
from datetime import datetime

import psutil
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box

console = Console()

# Known suspicious process names and patterns
SUSPICIOUS_PROCESSES = {
    "mimikatz", "lazagne", "procdump", "rubeus", "sharphound",
    "cobalt", "meterpreter", "empire", "covenant",
}

# Known safe gaming processes (whitelist)
GAMING_PROCESSES = {
    "steam", "steamwebhelper", "epicgameslauncher", "easyanticheat",
    "battleye", "vgc", "faceitclient", "discord", "obs64",
    "nvidia", "razer", "icue", "lghub",
}

# Directories to watch for suspicious DLL drops
WATCH_DIRS_WINDOWS = [
    Path(os.environ.get("APPDATA", "")) / "Steam",
    Path(os.environ.get("LOCALAPPDATA", "")) / "EpicGamesLauncher",
    Path(os.environ.get("APPDATA", "")) / "discord",
    Path(os.environ.get("TEMP", "")),
]

WATCH_DIRS_LINUX = [
    Path.home() / ".steam",
    Path.home() / ".local/share/Steam",
    Path.home() / ".config/discord",
    Path("/tmp"),
]


class RealtimeMonitor:
    """Monitor system for suspicious gaming-related activity."""

    def __init__(self):
        self.alerts: list[dict] = []
        self.is_windows = platform.system() == "Windows"
        self.baseline_pids: set[int] = set()

    def _snapshot_processes(self) -> set[int]:
        return {p.pid for p in psutil.process_iter(["pid"])}

    def _check_new_processes(self):
        """Detect new processes since last check."""
        current = self._snapshot_processes()
        new_pids = current - self.baseline_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name().lower()
                cmdline = " ".join(proc.cmdline()).lower()

                # Check for suspicious processes
                for susp in SUSPICIOUS_PROCESSES:
                    if susp in name or susp in cmdline:
                        self._alert(
                            "CRITICAL",
                            f"Suspicious process detected: {proc.name()} (PID: {pid})",
                            f"Command: {' '.join(proc.cmdline()[:5])}",
                        )

                # Check for unexpected DLL injection tools
                if any(x in name for x in ["inject", "hook", "dll"]):
                    if not any(g in name for g in GAMING_PROCESSES):
                        self._alert(
                            "HIGH",
                            f"Potential DLL injector: {proc.name()} (PID: {pid})",
                            f"Parent: {proc.parent().name() if proc.parent() else 'unknown'}",
                        )

                # Check for processes with unusual privileges
                if self.is_windows:
                    try:
                        if proc.username() and "SYSTEM" in proc.username():
                            if not any(g in name for g in GAMING_PROCESSES | {"svchost", "csrss", "lsass"}):
                                self._alert(
                                    "MEDIUM",
                                    f"SYSTEM-level process: {proc.name()} (PID: {pid})",
                                    f"User: {proc.username()}",
                                )
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self.baseline_pids = current

    def _check_network_connections(self):
        """Monitor for suspicious network activity from gaming processes."""
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status == "LISTEN" and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name().lower()
                        port = conn.laddr.port

                        # Known dangerous ports
                        if port in {4444, 5555, 8888, 9999, 1337, 31337}:
                            self._alert(
                                "CRITICAL",
                                f"Suspicious listener on port {port}: {proc.name()}",
                                f"PID: {conn.pid}, Address: {conn.laddr}",
                            )

                        # Unexpected listeners from game processes
                        if any(g in name for g in {"steam", "epic", "discord"}):
                            if port not in {80, 443, 8080, 27015, 27036, 6463, 6464}:
                                self._alert(
                                    "LOW",
                                    f"Gaming process listening on unusual port: {proc.name()}:{port}",
                                    f"PID: {conn.pid}",
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except psutil.AccessDenied:
            pass

    def _alert(self, severity: str, message: str, detail: str = ""):
        self.alerts.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "severity": severity,
            "message": message,
            "detail": detail,
        })
        # Keep last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

    def _build_dashboard(self) -> Table:
        """Build the live monitoring dashboard."""
        table = Table(
            title="🛡️ RCE Shield — Real-Time Monitor",
            box=box.ROUNDED,
            show_lines=True,
            caption=f"Monitoring {len(self.baseline_pids)} processes | {datetime.now().strftime('%H:%M:%S')}",
        )
        table.add_column("Time", width=10)
        table.add_column("Severity", width=10)
        table.add_column("Alert", width=50)
        table.add_column("Detail", width=30)

        colors = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "dim",
        }

        for alert in self.alerts[-20:]:
            color = colors.get(alert["severity"], "white")
            table.add_row(
                alert["time"],
                f"[{color}]{alert['severity']}[/{color}]",
                alert["message"],
                alert["detail"],
            )

        if not self.alerts:
            table.add_row("", "", "[dim]No alerts — system looks clean[/dim]", "")

        return table

    def start(self, daemon: bool = False):
        """Start the real-time monitor."""
        self.baseline_pids = self._snapshot_processes()
        self._alert("INFO", "Monitor started", f"Tracking {len(self.baseline_pids)} processes")

        with Live(self._build_dashboard(), refresh_per_second=1, console=console) as live:
            while True:
                self._check_new_processes()
                self._check_network_connections()
                live.update(self._build_dashboard())
                time.sleep(3)
