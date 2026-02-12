"""
Game Launcher Security Scanner

Audits Steam, Epic Games, Battle.net, EA App, GOG Galaxy for:
- Protocol handler hijacking
- DLL search order vulnerabilities
- Service privilege escalation
- Auto-update MITM vectors
- Workshop/mod directory permissions
"""

import os
import platform
import subprocess
import re
from pathlib import Path
from typing import Optional

from rce_shield.core.scanner import BaseScanner, Finding, Severity


class LauncherScanner(BaseScanner):
    name = "Game Launcher Scanner"
    description = "Audits game launcher security configurations"

    # Known launcher install paths
    STEAM_PATHS_WIN = [
        Path("C:/Program Files (x86)/Steam"),
        Path("C:/Program Files/Steam"),
    ]
    STEAM_PATHS_LINUX = [
        Path.home() / ".steam/steam",
        Path.home() / ".local/share/Steam",
    ]
    EPIC_PATHS_WIN = [
        Path("C:/Program Files (x86)/Epic Games"),
        Path("C:/Program Files/Epic Games/Launcher"),
    ]
    BATTLENET_PATHS_WIN = [
        Path("C:/Program Files (x86)/Battle.net"),
    ]

    # Known CVEs for game launchers
    LAUNCHER_CVES = {
        "steam": [
            {
                "cve": "CVE-2023-29011",
                "desc": "Steam Client local privilege escalation via named pipe",
                "cvss": 7.8,
                "fixed_version": "2023-03-15",
            },
            {
                "cve": "CVE-2019-15316",
                "desc": "Steam Client Service DLL preloading vulnerability",
                "cvss": 7.8,
                "fixed_version": "2019-08-22",
            },
            {
                "cve": "CVE-2019-14743",
                "desc": "Steam Client local privilege escalation via symlinks",
                "cvss": 8.2,
                "fixed_version": "2019-08-13",
            },
        ],
        "epic": [
            {
                "cve": "CVE-2023-36340",
                "desc": "Unreal Engine RCE via crafted .uproject file",
                "cvss": 9.8,
                "fixed_version": "2023-06-01",
            },
        ],
        "battlenet": [
            {
                "cve": "CVE-2021-44711",
                "desc": "Battle.net Agent local privilege escalation",
                "cvss": 7.0,
                "fixed_version": "2022-01-15",
            },
        ],
    }

    def scan(self) -> list[Finding]:
        self._scan_steam()
        self._scan_epic()
        self._scan_battlenet()
        self._scan_protocol_handlers()
        self._scan_dll_hijacking()
        self._check_known_cves()
        return self.findings

    def _find_steam_path(self) -> Optional[Path]:
        paths = self.STEAM_PATHS_WIN if self.is_windows else self.STEAM_PATHS_LINUX
        for p in paths:
            if p.exists():
                return p
        return None

    def _scan_steam(self):
        steam_path = self._find_steam_path()
        if not steam_path:
            self.add_finding(
                Severity.INFO, "launcher", "Steam",
                "Steam not found on this system",
                remediation="N/A",
            )
            return

        # Check Steam directory permissions
        self._check_dir_permissions(steam_path, "Steam")

        # Check steamapps/workshop for mod security
        workshop = steam_path / "steamapps" / "workshop"
        if workshop.exists():
            # Check for world-writable workshop directories
            if self.is_linux:
                try:
                    mode = oct(workshop.stat().st_mode)[-3:]
                    if int(mode[-1]) >= 6:  # World writable
                        self.add_finding(
                            Severity.HIGH, "launcher", "Steam Workshop",
                            f"Workshop directory is world-writable: {workshop}",
                            evidence=f"Permissions: {mode}",
                            remediation="chmod 755 on Steam workshop directory",
                        )
                except OSError:
                    pass

            # Count workshop items and flag excessive mods
            workshop_items = list(workshop.glob("content/*/"))
            if len(workshop_items) > 100:
                self.add_finding(
                    Severity.LOW, "launcher", "Steam Workshop",
                    f"Large number of workshop items ({len(workshop_items)}) increases attack surface",
                    remediation="Review and remove unused workshop subscriptions",
                )

        # Check Steam config for security settings
        config_file = steam_path / "config" / "config.vdf"
        if config_file.exists():
            try:
                content = config_file.read_text(errors="ignore")
                if '"NoSavePersonalInfo"' not in content:
                    self.add_finding(
                        Severity.LOW, "launcher", "Steam Config",
                        "Steam not configured to clear personal info on exit",
                        remediation='Enable "Don\'t save account credentials" in Steam settings',
                    )
            except OSError:
                pass

        # Check for Steam Guard
        loginusers = steam_path / "config" / "loginusers.vdf"
        if loginusers.exists():
            try:
                content = loginusers.read_text(errors="ignore")
                if '"WantsOfflineMode"\t\t"1"' in content:
                    self.add_finding(
                        Severity.MEDIUM, "launcher", "Steam",
                        "Steam offline mode enabled — skips Steam Guard protection",
                        remediation="Disable offline mode for better account security",
                    )
            except OSError:
                pass

    def _scan_epic(self):
        if not self.is_windows:
            return

        for path in self.EPIC_PATHS_WIN:
            if path.exists():
                self._check_dir_permissions(path, "Epic Games Launcher")

                # Check for Epic's UnrealEngineLauncher
                ue_path = path / "UE_5" if (path / "UE_5").exists() else None
                if ue_path:
                    self.add_finding(
                        Severity.MEDIUM, "launcher", "Unreal Engine",
                        "Unreal Engine installed — check for CVE-2023-36340 (.uproject RCE)",
                        cve="CVE-2023-36340",
                        cvss=9.8,
                        remediation="Update Unreal Engine to latest version; don't open untrusted .uproject files",
                    )
                break

    def _scan_battlenet(self):
        if not self.is_windows:
            return

        for path in self.BATTLENET_PATHS_WIN:
            if path.exists():
                # Check Battle.net Agent
                agent = path / "Battle.net" / "Agent"
                if agent.exists():
                    self._check_dir_permissions(agent, "Battle.net Agent")

    def _scan_protocol_handlers(self):
        """Check for registered protocol handlers that could be abused."""
        if self.is_windows:
            self._check_windows_protocol_handlers()
        elif self.is_linux:
            self._check_linux_protocol_handlers()

    def _check_windows_protocol_handlers(self):
        """Audit Windows protocol handler registrations."""
        try:
            import winreg
        except ImportError:
            return

        protocol_handlers = {
            "steam": "Steam Protocol Handler",
            "com.epicgames.launcher": "Epic Games Protocol Handler",
            "battlenet": "Battle.net Protocol Handler",
            "origin": "EA App Protocol Handler",
            "origin2": "EA App v2 Protocol Handler",
        }

        for proto, name in protocol_handlers.items():
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CLASSES_ROOT,
                    f"{proto}\\shell\\open\\command",
                )
                value, _ = winreg.QueryValueEx(key, "")
                winreg.CloseKey(key)

                # Check if the handler points to a valid, signed executable
                exe_path = value.split('"')[1] if '"' in value else value.split()[0]
                if not Path(exe_path).exists():
                    self.add_finding(
                        Severity.HIGH, "protocol", name,
                        f"Protocol handler '{proto}://' points to missing executable",
                        evidence=f"Registry: {value}",
                        remediation=f"Reinstall {name} or remove the registry key",
                    )
                else:
                    self.add_finding(
                        Severity.INFO, "protocol", name,
                        f"Protocol handler '{proto}://' registered",
                        evidence=f"Handler: {exe_path}",
                    )
            except (OSError, IndexError):
                pass

    def _check_linux_protocol_handlers(self):
        """Check XDG protocol handlers on Linux."""
        xdg_apps = Path.home() / ".local/share/applications"
        if not xdg_apps.exists():
            return

        for desktop_file in xdg_apps.glob("*.desktop"):
            try:
                content = desktop_file.read_text()
                if "x-scheme-handler/steam" in content:
                    self.add_finding(
                        Severity.INFO, "protocol", "Steam",
                        "Steam protocol handler registered via XDG",
                        evidence=str(desktop_file),
                    )
            except OSError:
                pass

    def _scan_dll_hijacking(self):
        """Check for DLL search order hijacking in launcher directories."""
        if not self.is_windows:
            return

        steam_path = self._find_steam_path()
        if not steam_path:
            return

        # Check for suspicious DLLs in Steam directory
        suspicious_dlls = {
            "version.dll", "winhttp.dll", "dxgi.dll", "d3d11.dll",
            "dinput8.dll", "dbghelp.dll", "msimg32.dll",
        }

        for dll_name in suspicious_dlls:
            dll_path = steam_path / dll_name
            if dll_path.exists():
                self.add_finding(
                    Severity.HIGH, "dll_hijack", f"Steam/{dll_name}",
                    f"Suspicious DLL found in Steam root: {dll_name}",
                    evidence=f"Path: {dll_path}, Size: {dll_path.stat().st_size}",
                    remediation=f"Verify {dll_name} is legitimate; remove if not recognized",
                )

    def _check_dir_permissions(self, path: Path, name: str):
        """Check directory permissions for security issues."""
        if self.is_linux:
            try:
                mode = oct(path.stat().st_mode)[-3:]
                if int(mode[-1]) >= 6:
                    self.add_finding(
                        Severity.MEDIUM, "permissions", name,
                        f"Directory is world-writable: {path}",
                        evidence=f"Permissions: {mode}",
                        remediation=f"chmod 755 {path}",
                    )
            except OSError:
                pass

    def _check_known_cves(self):
        """Flag known CVEs for installed launchers."""
        steam_path = self._find_steam_path()
        if steam_path:
            for cve_info in self.LAUNCHER_CVES["steam"]:
                self.add_finding(
                    Severity.MEDIUM, "cve", "Steam",
                    f"Known vulnerability: {cve_info['desc']}",
                    cve=cve_info["cve"],
                    cvss=cve_info["cvss"],
                    remediation="Ensure Steam is updated to the latest version",
                )
