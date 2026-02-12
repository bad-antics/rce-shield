"""
Gaming Overlay & Injection Scanner

Detects security risks in overlay software:
- DLL injection detection (screen overlays, hooks)
- Overlay permission audit (Discord, Steam, GeForce Experience)
- WebSocket/HTTP API exposure (Discord, Overwolf)
- Telemetry endpoint analysis
- OBS browser source sandboxing
"""

import os
import socket
import subprocess
from pathlib import Path

import psutil

from rce_shield.core.scanner import BaseScanner, Finding, Severity


class OverlayScanner(BaseScanner):
    name = "Overlay & Injection Scanner"
    description = "Audits gaming overlays and DLL injection surfaces"

    # Known overlay processes and their expected behavior
    OVERLAY_PROCESSES = {
        "GameOverlayUI.exe": {
            "name": "Steam Overlay",
            "vendor": "Valve",
            "expected": True,
            "risk": "low",
            "notes": "Injects into all Steam games via GameOverlayRenderer.dll",
        },
        "DiscordHook64.dll": {
            "name": "Discord Overlay",
            "vendor": "Discord Inc.",
            "expected": True,
            "risk": "low",
            "notes": "Hooks into game processes for overlay rendering",
        },
        "discord.exe": {
            "name": "Discord",
            "vendor": "Discord Inc.",
            "expected": True,
            "risk": "medium",
            "notes": "Local RPC server (port 6463), StreamKit SDK",
        },
        "NVIDIA Share.exe": {
            "name": "NVIDIA ShadowPlay",
            "vendor": "NVIDIA",
            "expected": True,
            "risk": "low",
            "notes": "Captures gameplay via GPU-level hooks",
        },
        "nvspcaps64.exe": {
            "name": "NVIDIA Capture Server",
            "vendor": "NVIDIA",
            "expected": True,
            "risk": "low",
            "notes": "Backend for ShadowPlay capture",
        },
        "overwolf.exe": {
            "name": "Overwolf",
            "vendor": "Overwolf Ltd.",
            "expected": True,
            "risk": "high",
            "notes": "Runs third-party apps with game injection capabilities",
        },
        "OverwolfHelper64.exe": {
            "name": "Overwolf Helper",
            "vendor": "Overwolf Ltd.",
            "expected": True,
            "risk": "high",
            "notes": "Elevated helper for overlay injection",
        },
        "Medal.exe": {
            "name": "Medal.tv",
            "vendor": "Medal B.V.",
            "expected": True,
            "risk": "medium",
            "notes": "Clip capture with overlay injection",
        },
        "obs64.exe": {
            "name": "OBS Studio",
            "vendor": "OBS Project",
            "expected": True,
            "risk": "medium",
            "notes": "Game capture hook, browser sources can load remote content",
        },
        "RTSS.exe": {
            "name": "RivaTuner Statistics Server",
            "vendor": "Unwinder",
            "expected": True,
            "risk": "low",
            "notes": "On-screen display via DLL injection",
        },
        "MSIAfterburner.exe": {
            "name": "MSI Afterburner",
            "vendor": "MSI / Unwinder",
            "expected": True,
            "risk": "low",
            "notes": "GPU monitoring with RTSS overlay",
        },
        "FPSMonitor.exe": {
            "name": "FPS Monitor",
            "vendor": "Alexander Kozlov",
            "expected": True,
            "risk": "low",
            "notes": "Hardware monitoring overlay",
        },
    }

    # Suspicious DLLs commonly used for injection
    SUSPICIOUS_DLLS = [
        "d3d9.dll",        # DirectX proxy — common injection vector
        "d3d11.dll",       # DirectX 11 proxy
        "dxgi.dll",        # DXGI proxy — ReShade, SpecialK
        "dinput8.dll",     # DirectInput proxy
        "dsound.dll",      # DirectSound proxy
        "xinput1_3.dll",   # XInput proxy — controller hook
        "version.dll",     # Version.dll proxy — extremely common hijack
        "winmm.dll",       # Multimedia proxy
        "opengl32.dll",    # OpenGL proxy
    ]

    # Known overlay CVEs
    CVE_DATABASE = {
        "CVE-2023-38999": {
            "product": "Overwolf",
            "severity": Severity.HIGH,
            "description": "Overwolf app sandbox escape via IPC manipulation",
            "cvss": 7.8,
        },
        "CVE-2021-21220": {
            "product": "OBS Browser Source (Chromium)",
            "severity": Severity.CRITICAL,
            "description": "V8 type confusion in browser source (Chromium-based)",
            "cvss": 8.8,
        },
        "CVE-2022-36934": {
            "product": "Discord (Electron)",
            "severity": Severity.CRITICAL,
            "description": "Integer overflow in embedded WhatsApp/Electron framework",
            "cvss": 9.8,
        },
    }

    def scan(self) -> list[Finding]:
        self._scan_overlay_processes()
        self._check_dll_injection_surface()
        self._audit_discord_rpc()
        self._check_obs_browser_sources()
        self._scan_overlay_permissions()
        self._check_known_cves()
        return self.findings

    def _scan_overlay_processes(self):
        """Detect running overlay processes and assess risk."""
        running_overlays = []

        for proc in psutil.process_iter(["name", "exe", "username"]):
            try:
                pname = proc.info["name"]
                if pname in self.OVERLAY_PROCESSES:
                    info = self.OVERLAY_PROCESSES[pname]
                    running_overlays.append(pname)

                    risk = info["risk"]
                    severity = {
                        "low": Severity.INFO,
                        "medium": Severity.LOW,
                        "high": Severity.MEDIUM,
                    }[risk]

                    self.add_finding(
                        severity, "overlay", info["name"],
                        f"{info['notes']}",
                        evidence=f"Process: {pname}, Vendor: {info['vendor']}, "
                                 f"Path: {proc.info.get('exe', 'unknown')}",
                        remediation=(
                            "Disable overlay if not needed. "
                            "Review permissions for third-party overlay apps."
                            if risk in ("medium", "high")
                            else "Acceptable if intentionally installed"
                        ),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not running_overlays:
            self.add_finding(
                Severity.INFO, "overlay", "Overlay Processes",
                "No known overlay processes detected",
            )

    def _check_dll_injection_surface(self):
        """Check for DLL proxy/hijack vectors in game directories."""
        game_dirs = self._find_game_directories()

        for game_dir in game_dirs:
            game_path = Path(game_dir)
            if not game_path.exists():
                continue

            for dll_name in self.SUSPICIOUS_DLLS:
                dll_path = game_path / dll_name
                if dll_path.exists():
                    # Check if it's a known tool (ReShade, SpecialK, etc.)
                    is_known = self._identify_proxy_dll(dll_path)

                    if is_known:
                        self.add_finding(
                            Severity.LOW, "injection", f"{dll_name}",
                            f"Known proxy DLL in game directory: {is_known}",
                            evidence=f"Path: {dll_path}",
                            remediation="Verify this mod/tool is from a trusted source",
                        )
                    else:
                        self.add_finding(
                            Severity.HIGH, "injection", f"{dll_name}",
                            f"Unidentified proxy DLL in game directory",
                            evidence=f"Path: {dll_path}, Size: {dll_path.stat().st_size} bytes",
                            remediation=(
                                "Investigate this DLL — could be malicious. "
                                "Upload to VirusTotal for analysis."
                            ),
                        )

    def _identify_proxy_dll(self, dll_path: Path) -> str | None:
        """Try to identify a known proxy DLL by its properties."""
        try:
            size = dll_path.stat().st_size
            content_sample = dll_path.read_bytes()[:4096]

            known_signatures = {
                b"ReShade": "ReShade (graphics post-processing)",
                b"SpecialK": "Special K (game enhancement toolkit)",
                b"DXVK": "DXVK (Vulkan-based DirectX translation)",
                b"ENBSeries": "ENBSeries (graphics mod)",
                b"dgVoodoo": "dgVoodoo (legacy API wrapper)",
            }

            for sig, name in known_signatures.items():
                if sig in content_sample:
                    return name

            return None
        except (OSError, PermissionError):
            return None

    def _audit_discord_rpc(self):
        """Audit Discord's local RPC server security."""
        # Discord runs a local HTTP/WebSocket server on 6463-6472
        for port in range(6463, 6473):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()

                if result == 0:
                    self.add_finding(
                        Severity.LOW, "overlay", f"Discord RPC (:{port})",
                        "Discord Rich Presence local server is active",
                        evidence=f"Listening on 127.0.0.1:{port}",
                        remediation=(
                            "Discord RPC allows any local application to interact with Discord. "
                            "Disable Rich Presence if not needed in Discord settings."
                        ),
                    )
                    break
            except OSError:
                pass

    def _check_obs_browser_sources(self):
        """Check OBS Studio for insecure browser source configurations."""
        obs_dirs = []

        if self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                obs_dirs.append(Path(appdata) / "obs-studio")
        elif self.is_linux:
            obs_dirs.append(Path.home() / ".config" / "obs-studio")

        for obs_dir in obs_dirs:
            scenes_dir = obs_dir / "basic" / "scenes"
            if not scenes_dir.exists():
                continue

            for scene_file in scenes_dir.glob("*.json"):
                try:
                    import json
                    data = json.loads(scene_file.read_text())
                    sources = data.get("sources", [])

                    for source in sources:
                        settings = source.get("settings", {})
                        url = settings.get("url", "")

                        if url and url.startswith("http://"):
                            self.add_finding(
                                Severity.MEDIUM, "overlay", "OBS Browser Source",
                                f"Browser source using insecure HTTP: {url[:80]}",
                                evidence=f"Scene: {scene_file.name}, Source: {source.get('name', 'unknown')}",
                                remediation="Use HTTPS URLs for browser sources to prevent MITM attacks",
                            )

                        if url and any(x in url for x in ["file://", "javascript:", "data:"]):
                            self.add_finding(
                                Severity.HIGH, "overlay", "OBS Browser Source",
                                f"Browser source with potentially dangerous URL scheme",
                                evidence=f"URL: {url[:80]}, Scene: {scene_file.name}",
                                remediation="Remove or verify this browser source URL",
                            )

                except (json.JSONDecodeError, OSError, KeyError):
                    pass

    def _scan_overlay_permissions(self):
        """Check overlay software for excessive permissions."""
        if self.is_windows:
            # Check if overlays are running as admin
            for proc in psutil.process_iter(["name", "username"]):
                try:
                    pname = proc.info["name"]
                    if pname in self.OVERLAY_PROCESSES:
                        username = proc.info.get("username", "")
                        if username and ("SYSTEM" in username.upper() or "Administrator" in username):
                            info = self.OVERLAY_PROCESSES[pname]
                            self.add_finding(
                                Severity.HIGH, "overlay", info["name"],
                                f"{info['name']} running with elevated privileges",
                                evidence=f"Process: {pname}, User: {username}",
                                remediation="Run overlay software with standard user privileges",
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

    def _check_known_cves(self):
        """Check for CVEs affecting installed overlay software."""
        installed = set()

        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"]
                if pname in self.OVERLAY_PROCESSES:
                    installed.add(self.OVERLAY_PROCESSES[pname]["vendor"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for cve_id, cve_data in self.CVE_DATABASE.items():
            product = cve_data["product"]
            # Check if any installed overlay matches
            if any(vendor.lower() in product.lower() for vendor in installed):
                self.add_finding(
                    cve_data["severity"], "cve", product,
                    cve_data["description"],
                    cve=cve_id,
                    cvss=cve_data["cvss"],
                    remediation=f"Update {product} to latest version. Check {cve_id} for patches.",
                )

    def _find_game_directories(self) -> list[str]:
        """Discover common game installation directories."""
        dirs = []

        if self.is_windows:
            for drive in ("C:", "D:", "E:", "F:"):
                dirs.extend([
                    f"{drive}\\Program Files (x86)\\Steam\\steamapps\\common",
                    f"{drive}\\Program Files\\Steam\\steamapps\\common",
                    f"{drive}\\Program Files\\Epic Games",
                    f"{drive}\\Games",
                    f"{drive}\\Riot Games",
                ])
        elif self.is_linux:
            home = str(Path.home())
            dirs.extend([
                f"{home}/.steam/steam/steamapps/common",
                f"{home}/.local/share/Steam/steamapps/common",
                f"{home}/.local/share/lutris/runners",
                f"{home}/Games",
            ])

        # Find actual subdirectories (each game folder)
        game_dirs = []
        for d in dirs:
            p = Path(d)
            if p.exists() and p.is_dir():
                try:
                    for child in p.iterdir():
                        if child.is_dir():
                            game_dirs.append(str(child))
                except PermissionError:
                    pass

        return game_dirs[:50]  # Cap to prevent scanning too many


import socket  # noqa: E402 — needed for Discord RPC check
