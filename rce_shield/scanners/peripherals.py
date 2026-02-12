"""
Gaming Peripheral Software Scanner

Audits peripheral drivers and software for security risks:
- Auto-update integrity verification (Razer Synapse, iCUE, Logitech G Hub)
- Service privilege escalation audit
- Macro engine sandboxing assessment
- Cloud sync credential security
- USB HID attack surface analysis
"""

import os
import subprocess
from pathlib import Path

import psutil

from rce_shield.core.scanner import BaseScanner, Finding, Severity


class PeripheralScanner(BaseScanner):
    name = "Peripheral Software Scanner"
    description = "Audits gaming peripheral drivers and software"

    # Known peripheral software and associated risks
    PERIPHERAL_SOFTWARE = {
        # Razer
        "Razer Synapse 3.exe": {
            "name": "Razer Synapse 3",
            "vendor": "Razer Inc.",
            "services": ["Razer Synapse Service", "RzActionSvc"],
            "risk_notes": "CVE-2021-44226: Local privilege escalation via installer",
            "paths_windows": [
                r"C:\Program Files (x86)\Razer\Synapse3",
                r"C:\Program Files\Razer\Synapse3",
            ],
            "paths_linux": [],
        },
        "RazerCentralService.exe": {
            "name": "Razer Central",
            "vendor": "Razer Inc.",
            "services": ["Razer Central Service"],
            "risk_notes": "Background auto-updater with SYSTEM privileges",
            "paths_windows": [r"C:\Program Files (x86)\Razer\RazerCentral"],
            "paths_linux": [],
        },
        # Corsair
        "iCUE.exe": {
            "name": "Corsair iCUE",
            "vendor": "Corsair",
            "services": ["CorsairService", "CorsairLLAService"],
            "risk_notes": "Multiple services run as SYSTEM; auto-update mechanism",
            "paths_windows": [r"C:\Program Files\Corsair\CORSAIR iCUE 4 Software"],
            "paths_linux": [],
        },
        # Logitech
        "lghub.exe": {
            "name": "Logitech G Hub",
            "vendor": "Logitech",
            "services": ["LGHUBUpdaterService"],
            "risk_notes": "CVE-2022-XXXXX: Updater service DLL side-loading",
            "paths_windows": [r"C:\Program Files\LGHUB"],
            "paths_linux": [],
        },
        # SteelSeries
        "SteelSeriesGG.exe": {
            "name": "SteelSeries GG",
            "vendor": "SteelSeries",
            "services": ["SteelSeriesGG"],
            "risk_notes": "Electron-based app with local server for Sonar audio",
            "paths_windows": [r"C:\Program Files\SteelSeries\GG"],
            "paths_linux": [],
        },
        # HyperX / HP
        "NGENUITYSetup.exe": {
            "name": "HyperX NGENUITY",
            "vendor": "HP / HyperX",
            "services": [],
            "risk_notes": "Microsoft Store app; sandboxed but stores cloud profiles",
            "paths_windows": [],
            "paths_linux": [],
        },
        # NZXT
        "NZXT CAM.exe": {
            "name": "NZXT CAM",
            "vendor": "NZXT",
            "services": ["NzxtCamService"],
            "risk_notes": "System monitoring with kernel-level access for fan/pump control",
            "paths_windows": [r"C:\Program Files\NZXT\CAM"],
            "paths_linux": [],
        },
        # Elgato
        "StreamDeck.exe": {
            "name": "Elgato Stream Deck",
            "vendor": "Corsair / Elgato",
            "services": [],
            "risk_notes": "Plugin system allows arbitrary code execution via actions",
            "paths_windows": [r"C:\Program Files\Elgato\StreamDeck"],
            "paths_linux": [],
        },
        # Wooting
        "Wootility.exe": {
            "name": "Wooting Wootility",
            "vendor": "Wooting",
            "services": [],
            "risk_notes": "Firmware update capability; WebHID-based",
            "paths_windows": [],
            "paths_linux": [],
        },
    }

    # Known CVEs for peripheral software
    CVE_DATABASE = {
        "CVE-2021-44226": {
            "product": "Razer Synapse",
            "severity": Severity.HIGH,
            "description": (
                "Razer Synapse installer allows local privilege escalation. "
                "Plugging in any Razer device triggers SYSTEM-level installer."
            ),
            "cvss": 7.8,
        },
        "CVE-2022-42292": {
            "product": "NVIDIA GeForce Experience",
            "severity": Severity.HIGH,
            "description": "GeForce Experience code execution vulnerability via GameStream",
            "cvss": 7.5,
        },
        "CVE-2023-25515": {
            "product": "NVIDIA GPU Display Driver",
            "severity": Severity.HIGH,
            "description": "NVIDIA display driver out-of-bounds read in kernel mode layer",
            "cvss": 7.1,
        },
        "CVE-2021-44228": {
            "product": "Log4j (Minecraft, Overwolf, etc.)",
            "severity": Severity.CRITICAL,
            "description": "Log4Shell: Remote code execution via JNDI injection in logging framework",
            "cvss": 10.0,
        },
    }

    def scan(self) -> list[Finding]:
        self._scan_peripheral_processes()
        self._audit_service_privileges()
        self._check_auto_updaters()
        self._scan_macro_engines()
        self._check_usb_attack_surface()
        self._check_known_cves()
        return self.findings

    def _scan_peripheral_processes(self):
        """Detect running peripheral software."""
        found_any = False

        for proc in psutil.process_iter(["name", "exe", "username", "pid"]):
            try:
                pname = proc.info["name"]
                if pname in self.PERIPHERAL_SOFTWARE:
                    info = self.PERIPHERAL_SOFTWARE[pname]
                    found_any = True

                    username = proc.info.get("username", "unknown")
                    is_elevated = (
                        self.is_windows
                        and username
                        and ("SYSTEM" in username.upper() or "Administrator" in username)
                    )

                    severity = Severity.MEDIUM if is_elevated else Severity.INFO

                    self.add_finding(
                        severity, "peripheral", info["name"],
                        f"{info['risk_notes']}",
                        evidence=(
                            f"Process: {pname}, PID: {proc.info['pid']}, "
                            f"User: {username}, Path: {proc.info.get('exe', 'unknown')}"
                        ),
                        remediation=(
                            "Review if this software is needed. "
                            "Consider closing when not actively configuring peripherals."
                            if is_elevated
                            else "Ensure software is up to date"
                        ),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not found_any:
            self.add_finding(
                Severity.INFO, "peripheral", "Peripheral Software",
                "No known peripheral management software detected running",
            )

    def _audit_service_privileges(self):
        """Audit Windows services installed by peripheral software."""
        if not self.is_windows:
            return

        try:
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return

            # Collect all service names
            service_names = []
            for line in result.stdout.split("\n"):
                if "SERVICE_NAME:" in line:
                    service_names.append(line.split(":")[-1].strip())

            # Check each peripheral's expected services
            for proc_name, info in self.PERIPHERAL_SOFTWARE.items():
                for svc_name in info["services"]:
                    if svc_name in service_names:
                        # Query service config
                        svc_result = subprocess.run(
                            ["sc", "qc", svc_name],
                            capture_output=True, text=True, timeout=5,
                        )
                        if svc_result.returncode == 0:
                            output = svc_result.stdout
                            if "LocalSystem" in output:
                                self.add_finding(
                                    Severity.MEDIUM, "peripheral",
                                    f"{info['name']} Service",
                                    f"Service '{svc_name}' runs as LocalSystem (highest privilege)",
                                    evidence=output.strip()[:300],
                                    remediation=(
                                        f"Consider running {svc_name} as a limited service account "
                                        f"if the vendor supports it"
                                    ),
                                )

                            # Check for unquoted service path
                            for line in output.split("\n"):
                                if "BINARY_PATH_NAME" in line:
                                    bin_path = line.split(":", 1)[-1].strip()
                                    if " " in bin_path and not bin_path.startswith('"'):
                                        self.add_finding(
                                            Severity.HIGH, "peripheral",
                                            f"{info['name']} Service",
                                            f"Unquoted service path: {bin_path}",
                                            evidence=f"Service: {svc_name}",
                                            remediation=(
                                                "Unquoted service paths enable privilege escalation. "
                                                "Contact vendor to fix the service registration."
                                            ),
                                        )

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _check_auto_updaters(self):
        """Check peripheral software auto-update security."""
        # Look for updater processes and services
        updater_patterns = [
            "Updater", "Update", "AutoUpdate", "SelfUpdate",
            "Installer", "Setup",
        ]

        for proc in psutil.process_iter(["name", "exe", "username"]):
            try:
                pname = proc.info["name"] or ""
                pexe = proc.info.get("exe") or ""

                # Check if this looks like a peripheral updater
                is_updater = any(pat.lower() in pname.lower() for pat in updater_patterns)
                is_peripheral = any(
                    vendor.lower() in pexe.lower()
                    for info in self.PERIPHERAL_SOFTWARE.values()
                    for vendor in [info["vendor"]]
                )

                if is_updater and is_peripheral:
                    username = proc.info.get("username", "unknown")
                    is_elevated = (
                        self.is_windows and username
                        and "SYSTEM" in username.upper()
                    )

                    self.add_finding(
                        Severity.MEDIUM if is_elevated else Severity.LOW,
                        "updater", pname,
                        f"Auto-updater running {'with SYSTEM privileges' if is_elevated else 'normally'}",
                        evidence=f"Path: {pexe}, User: {username}",
                        remediation=(
                            "Auto-updaters with SYSTEM privileges are a privilege escalation vector. "
                            "Verify updater integrity and consider manual updates."
                        ),
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_macro_engines(self):
        """Assess macro engine security for keyboards/mice."""
        # Check for Lua/Python macro engines
        macro_dirs = []

        if self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            if appdata:
                macro_dirs.extend([
                    Path(appdata) / "Razer" / "Synapse3" / "Macros",
                    Path(appdata) / "LGHUB" / "scripts",
                    Path(appdata) / "Corsair" / "CUE" / "Macros",
                ])
            if localappdata:
                macro_dirs.append(
                    Path(localappdata) / "Elgato" / "StreamDeck" / "Plugins"
                )

        for macro_dir in macro_dirs:
            if not macro_dir.exists():
                continue

            try:
                macro_files = list(macro_dir.rglob("*"))
                script_files = [
                    f for f in macro_files
                    if f.suffix.lower() in (".lua", ".py", ".js", ".ps1", ".bat", ".sh", ".vbs")
                ]

                if script_files:
                    self.add_finding(
                        Severity.MEDIUM, "macro", f"Macro Scripts ({macro_dir.parent.name})",
                        f"Found {len(script_files)} executable macro scripts",
                        evidence=", ".join(f.name for f in script_files[:5]),
                        remediation=(
                            "Review macro scripts for malicious content. "
                            "Macro engines can execute arbitrary code with user privileges."
                        ),
                    )

                    # Check for suspicious patterns in scripts
                    for script in script_files[:20]:
                        try:
                            content = script.read_text(errors="ignore")
                            suspicious = []

                            patterns = {
                                "network access": ["http://", "https://", "socket.", "urllib", "requests."],
                                "process execution": ["os.system", "subprocess", "exec(", "eval(", "shell("],
                                "file system": ["os.remove", "shutil.rmtree", "rm -rf"],
                                "credential access": ["password", "credential", "token", "api_key"],
                                "registry": ["winreg", "reg.exe", "HKLM", "HKCU"],
                            }

                            for category, keywords in patterns.items():
                                if any(kw in content for kw in keywords):
                                    suspicious.append(category)

                            if suspicious:
                                self.add_finding(
                                    Severity.HIGH, "macro", script.name,
                                    f"Macro script contains suspicious patterns: {', '.join(suspicious)}",
                                    evidence=f"Path: {script}",
                                    remediation="Review this script manually for malicious behavior",
                                )

                        except (OSError, UnicodeDecodeError):
                            pass

            except PermissionError:
                pass

    def _check_usb_attack_surface(self):
        """Check for USB HID attack surface."""
        if self.is_linux:
            # Check if USB device authorization is enabled
            usb_auth_path = Path("/sys/bus/usb/drivers_autoprobe")
            try:
                if usb_auth_path.exists():
                    val = usb_auth_path.read_text().strip()
                    if val == "1":
                        self.add_finding(
                            Severity.LOW, "usb", "USB Auto-Probe",
                            "USB devices are automatically probed and enabled",
                            evidence="drivers_autoprobe = 1",
                            remediation=(
                                "Consider USBGuard to whitelist trusted USB devices "
                                "and block rogue HID devices (USB Rubber Ducky attacks)"
                            ),
                        )
            except (OSError, PermissionError):
                pass

            # Check for USBGuard
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "usbguard"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout.strip() != "active":
                    self.add_finding(
                        Severity.LOW, "usb", "USBGuard",
                        "USBGuard is not active — no protection against rogue USB devices",
                        remediation="Install USBGuard: sudo apt install usbguard",
                    )
                else:
                    self.add_finding(
                        Severity.INFO, "usb", "USBGuard",
                        "USBGuard is active (good)",
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        elif self.is_windows:
            # Check USB device installation policy
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
                )
                try:
                    deny_all, _ = winreg.QueryValueEx(key, "DenyDeviceIDs")
                except FileNotFoundError:
                    self.add_finding(
                        Severity.LOW, "usb", "USB Device Policy",
                        "No USB device installation restrictions configured",
                        remediation=(
                            "Configure Group Policy to restrict USB device classes "
                            "to prevent BadUSB / Rubber Ducky attacks"
                        ),
                    )
                finally:
                    winreg.CloseKey(key)
            except (ImportError, OSError):
                pass

    def _check_known_cves(self):
        """Check for CVEs affecting installed peripheral software."""
        installed_vendors = set()

        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"]
                if pname in self.PERIPHERAL_SOFTWARE:
                    installed_vendors.add(
                        self.PERIPHERAL_SOFTWARE[pname]["vendor"].lower()
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for cve_id, cve_data in self.CVE_DATABASE.items():
            product = cve_data["product"]
            if any(v in product.lower() for v in installed_vendors):
                self.add_finding(
                    cve_data["severity"], "cve", product,
                    cve_data["description"],
                    cve=cve_id,
                    cvss=cve_data["cvss"],
                    remediation=f"Update {product} to latest version. See {cve_id}.",
                )
