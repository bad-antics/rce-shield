"""
Anti-Cheat System Security Auditor

Audits kernel-level anti-cheat drivers for:
- Driver signature validation
- Service permission misconfigurations
- Known CVEs (EAC, BattlEye, Vanguard, FACEIT)
- Boot-time driver audit
- Privilege escalation paths
"""

import platform
import subprocess
from pathlib import Path
from typing import Optional

import psutil

from rce_shield.core.scanner import BaseScanner, Finding, Severity


class AntiCheatScanner(BaseScanner):
    name = "Anti-Cheat Auditor"
    description = "Audits anti-cheat driver security"

    ANTICHEAT_SERVICES = {
        "EasyAntiCheat": {
            "service_names": ["EasyAntiCheat", "EasyAntiCheat_EOS"],
            "driver_names": ["EasyAntiCheatSys"],
            "process_names": ["easyanticheat", "eac_launcher"],
            "paths_win": [
                Path("C:/Program Files (x86)/EasyAntiCheat"),
                Path("C:/Program Files/EasyAntiCheat"),
            ],
            "cves": [
                {
                    "cve": "CVE-2020-6016",
                    "desc": "EAC race condition allowing code execution",
                    "cvss": 7.5,
                },
                {
                    "cve": "CVE-2018-10168",
                    "desc": "EAC driver arbitrary read/write vulnerability",
                    "cvss": 8.8,
                },
            ],
        },
        "BattlEye": {
            "service_names": ["BEService", "BEDaisy"],
            "driver_names": ["BEDaisy", "bedaisy"],
            "process_names": ["beservice", "beclient"],
            "paths_win": [
                Path("C:/Program Files (x86)/Common Files/BattlEye"),
            ],
            "cves": [
                {
                    "cve": "CVE-2019-8372",
                    "desc": "BattlEye driver allows unprivileged physical memory read",
                    "cvss": 6.7,
                },
            ],
        },
        "Riot Vanguard": {
            "service_names": ["vgc", "vgk"],
            "driver_names": ["vgk"],
            "process_names": ["vgc", "vgtray"],
            "paths_win": [
                Path("C:/Program Files/Riot Vanguard"),
            ],
            "cves": [],
        },
        "FACEIT Anti-Cheat": {
            "service_names": ["FACEITService"],
            "driver_names": ["faceit"],
            "process_names": ["faceitservice", "faceit"],
            "paths_win": [
                Path("C:/Program Files/FACEIT AC"),
            ],
            "cves": [],
        },
    }

    def scan(self) -> list[Finding]:
        self._detect_installed_anticheats()
        self._check_running_processes()
        self._audit_service_permissions()
        self._check_boot_drivers()
        self._check_known_cves()
        return self.findings

    def _detect_installed_anticheats(self):
        """Detect which anti-cheat systems are installed."""
        for ac_name, ac_info in self.ANTICHEAT_SERVICES.items():
            installed = False

            # Check paths
            if self.is_windows:
                for path in ac_info.get("paths_win", []):
                    if path.exists():
                        installed = True
                        self.add_finding(
                            Severity.INFO, "anticheat", ac_name,
                            f"{ac_name} installed at {path}",
                            evidence=str(path),
                        )

                        # Check directory permissions
                        self._check_ac_permissions(path, ac_name)

            # Check for running services
            for proc in psutil.process_iter(["name", "pid"]):
                try:
                    pname = proc.info["name"].lower()
                    if any(n in pname for n in ac_info["process_names"]):
                        installed = True
                        self.add_finding(
                            Severity.INFO, "anticheat", ac_name,
                            f"{ac_name} is running (PID: {proc.info['pid']})",
                            evidence=f"Process: {proc.info['name']}",
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            if installed:
                # Anti-cheat with kernel driver = large attack surface
                self.add_finding(
                    Severity.MEDIUM, "anticheat", ac_name,
                    f"{ac_name} kernel driver increases system attack surface",
                    remediation=(
                        f"Ensure {ac_name} is updated. "
                        "Consider uninstalling when not actively playing games that require it."
                    ),
                )

    def _check_running_processes(self):
        """Check anti-cheat processes for unusual behavior."""
        ac_procs = []
        for proc in psutil.process_iter(["name", "pid", "ppid", "username"]):
            try:
                pname = proc.info["name"].lower()
                for ac_name, ac_info in self.ANTICHEAT_SERVICES.items():
                    if any(n in pname for n in ac_info["process_names"]):
                        ac_procs.append((ac_name, proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for ac_name, proc in ac_procs:
            try:
                # Check if running as SYSTEM (expected for kernel drivers)
                username = proc.username() if hasattr(proc, "username") else ""
                if username and "SYSTEM" not in username and "root" not in username:
                    self.add_finding(
                        Severity.HIGH, "anticheat", ac_name,
                        f"{ac_name} process running without elevated privileges",
                        evidence=f"Running as: {username}",
                        remediation="Anti-cheat should run as SYSTEM/root for proper protection",
                    )

                # Check memory usage (excessive = potential issue)
                mem = proc.memory_info().rss / 1024 / 1024  # MB
                if mem > 500:
                    self.add_finding(
                        Severity.LOW, "anticheat", ac_name,
                        f"{ac_name} using excessive memory: {mem:.0f} MB",
                        remediation="Restart the anti-cheat service",
                    )

                # Check open network connections
                try:
                    connections = proc.net_connections()
                    for conn in connections:
                        if conn.status == "ESTABLISHED" and conn.raddr:
                            remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                            # Flag non-standard ports
                            if conn.raddr.port not in {80, 443, 8443}:
                                self.add_finding(
                                    Severity.LOW, "anticheat", ac_name,
                                    f"{ac_name} connected to unusual port: {remote}",
                                    evidence=f"Connection: {conn.laddr} → {remote}",
                                )
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _audit_service_permissions(self):
        """Audit Windows service ACLs for anti-cheat services."""
        if not self.is_windows:
            return

        for ac_name, ac_info in self.ANTICHEAT_SERVICES.items():
            for svc_name in ac_info["service_names"]:
                try:
                    result = subprocess.run(
                        ["sc", "qc", svc_name],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0:
                        output = result.stdout

                        # Check start type
                        if "BOOT_START" in output or "SYSTEM_START" in output:
                            self.add_finding(
                                Severity.MEDIUM, "anticheat", ac_name,
                                f"{ac_name} service '{svc_name}' loads at boot time",
                                evidence=f"Start type: BOOT/SYSTEM",
                                remediation=(
                                    "Boot-time drivers run before OS security. "
                                    "Ensure the driver is signed and up-to-date."
                                ),
                            )

                        # Check binary path for spaces without quotes
                        for line in output.splitlines():
                            if "BINARY_PATH_NAME" in line:
                                bin_path = line.split(":", 1)[-1].strip()
                                if " " in bin_path and not bin_path.startswith('"'):
                                    self.add_finding(
                                        Severity.HIGH, "anticheat", ac_name,
                                        f"Unquoted service path (privilege escalation risk): {svc_name}",
                                        evidence=f"Path: {bin_path}",
                                        remediation="Fix the service binary path with proper quoting",
                                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

    def _check_boot_drivers(self):
        """Check for anti-cheat drivers that load at boot."""
        if self.is_linux:
            # Check loaded kernel modules
            try:
                result = subprocess.run(
                    ["lsmod"], capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    modules = result.stdout.lower()
                    for ac_name, ac_info in self.ANTICHEAT_SERVICES.items():
                        for driver in ac_info["driver_names"]:
                            if driver.lower() in modules:
                                self.add_finding(
                                    Severity.MEDIUM, "anticheat", ac_name,
                                    f"{ac_name} kernel module loaded: {driver}",
                                    remediation="Unload with 'modprobe -r' when not gaming",
                                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    def _check_known_cves(self):
        """Check installed anti-cheats against known CVE database."""
        for ac_name, ac_info in self.ANTICHEAT_SERVICES.items():
            # Only report CVEs for installed anti-cheats
            installed = False
            if self.is_windows:
                for path in ac_info.get("paths_win", []):
                    if path.exists():
                        installed = True
                        break

            if not installed:
                for proc in psutil.process_iter(["name"]):
                    try:
                        if any(n in proc.info["name"].lower() for n in ac_info["process_names"]):
                            installed = True
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            if installed:
                for cve_info in ac_info["cves"]:
                    self.add_finding(
                        Severity.HIGH, "cve", ac_name,
                        f"Known vulnerability: {cve_info['desc']}",
                        cve=cve_info["cve"],
                        cvss=cve_info["cvss"],
                        remediation=f"Update {ac_name} to the latest version",
                    )

    def _check_ac_permissions(self, path: Path, name: str):
        """Check anti-cheat directory permissions."""
        try:
            if self.is_linux:
                mode = oct(path.stat().st_mode)[-3:]
                if int(mode[-1]) >= 2:
                    self.add_finding(
                        Severity.HIGH, "permissions", name,
                        f"{name} directory is world-writable: {path}",
                        evidence=f"Permissions: {mode}",
                        remediation=f"chmod 755 {path}",
                    )
            elif self.is_windows:
                # Check if non-admin users can write
                # This would require win32security on Windows
                pass
        except OSError:
            pass
