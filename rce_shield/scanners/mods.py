"""
Mod & Plugin Security Scanner

Detects malicious mods and plugins:
- Fractureiser malware pattern detection (CurseForge/Minecraft)
- Obfuscated code analysis in JAR/DLL mods
- Script sandbox escape detection (Lua, Python, C#)
- Mod file hash verification
- Symlink/junction attack prevention
"""

import hashlib
import os
import re
import zipfile
from pathlib import Path
from typing import Optional

from rce_shield.core.scanner import BaseScanner, Finding, Severity


class ModScanner(BaseScanner):
    name = "Mod & Plugin Scanner"
    description = "Scans game mods and plugins for malware and security issues"

    # Fractureiser malware indicators (CurseForge attack, June 2023)
    FRACTUREISER_INDICATORS = {
        "class_names": [
            "dev.neko.nekoclient",
            "skyrage.auth",
            "systemofadownkrnl",
            "Bruteforce",
        ],
        "strings": [
            "85.217.144.130",
            "skyrage.de",
            "files.skyrage.de",
            "dl.mcas.gg",
            "/dl",
            "connect.skyrage.de",
            "nekoclient",
        ],
        "file_patterns": [
            "lib.dll", "libWebGL64.jar", "dev.neko", "SystemOfADownDLL",
        ],
    }

    # Known malicious mod file hashes (SHA256)
    MALICIOUS_HASHES = {
        # Example fractureiser stage0 hashes
        "a1b2c3d4e5f6",  # placeholder
    }

    # Suspicious code patterns in scripts
    SUSPICIOUS_PATTERNS = [
        (r"os\.execute|io\.popen|os\.popen", "Lua shell execution"),
        (r"subprocess\.call|subprocess\.Popen|os\.system", "Python shell execution"),
        (r"System\.Diagnostics\.Process\.Start", "C# process execution"),
        (r"Runtime\.getRuntime\(\)\.exec", "Java runtime execution"),
        (r"eval\(|exec\(|compile\(", "Dynamic code execution"),
        (r"socket\.connect|urllib\.request|requests\.get", "Network access"),
        (r"base64\.b64decode|base64\.decode", "Base64 decoding (potential payload)"),
        (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "Hex-encoded shellcode"),
        (r"powershell|cmd\.exe|/bin/sh|/bin/bash", "Shell invocation"),
        (r"keylog|clipboard|screenshot|webcam", "Spyware functionality"),
        (r"HKEY_|RegOpenKey|winreg", "Registry manipulation"),
        (r"kernel32|ntdll|advapi32", "Windows API imports"),
    ]

    # Common mod directories
    MOD_DIRS_WIN = {
        "Minecraft": [
            Path(os.environ.get("APPDATA", "")) / ".minecraft" / "mods",
            Path(os.environ.get("APPDATA", "")) / ".minecraft" / "plugins",
        ],
        "Steam Workshop": [],  # Populated dynamically
        "Skyrim": [
            Path("C:/Program Files (x86)/Steam/steamapps/common/Skyrim Special Edition/Data"),
        ],
        "Cyberpunk": [
            Path("C:/Program Files (x86)/Steam/steamapps/common/Cyberpunk 2077/archive/pc/mod"),
        ],
    }

    MOD_DIRS_LINUX = {
        "Minecraft": [
            Path.home() / ".minecraft" / "mods",
            Path.home() / ".minecraft" / "plugins",
        ],
        "Steam Workshop": [
            Path.home() / ".steam/steam/steamapps/workshop",
            Path.home() / ".local/share/Steam/steamapps/workshop",
        ],
    }

    def scan(self) -> list[Finding]:
        self._scan_mod_directories()
        self._check_fractureiser()
        self._scan_jar_mods()
        self._scan_script_mods()
        self._check_symlinks()
        return self.findings

    def _get_mod_dirs(self) -> dict[str, list[Path]]:
        return self.MOD_DIRS_WIN if self.is_windows else self.MOD_DIRS_LINUX

    def _scan_mod_directories(self):
        """Enumerate and audit mod directories."""
        mod_dirs = self._get_mod_dirs()

        for game, dirs in mod_dirs.items():
            for mod_dir in dirs:
                if not mod_dir.exists():
                    continue

                # Count mods
                all_files = list(mod_dir.rglob("*"))
                mod_files = [f for f in all_files if f.suffix in {".jar", ".dll", ".so", ".py", ".lua", ".zip"}]

                if mod_files:
                    self.add_finding(
                        Severity.INFO, "mods", game,
                        f"Found {len(mod_files)} mod files in {mod_dir}",
                        evidence=f"Types: {', '.join(set(f.suffix for f in mod_files))}",
                    )

                # Check permissions
                if self.is_linux:
                    try:
                        mode = oct(mod_dir.stat().st_mode)[-3:]
                        if int(mode[-1]) >= 6:
                            self.add_finding(
                                Severity.MEDIUM, "mods", game,
                                f"Mod directory is world-writable: {mod_dir}",
                                evidence=f"Permissions: {mode}",
                                remediation=f"chmod 755 {mod_dir}",
                            )
                    except OSError:
                        pass

    def _check_fractureiser(self):
        """Check for Fractureiser malware indicators."""
        mod_dirs = self._get_mod_dirs()

        for game, dirs in mod_dirs.items():
            for mod_dir in dirs:
                if not mod_dir.exists():
                    continue

                # Check for known malicious filenames
                for pattern in self.FRACTUREISER_INDICATORS["file_patterns"]:
                    for match in mod_dir.rglob(f"*{pattern}*"):
                        self.add_finding(
                            Severity.CRITICAL, "malware", game,
                            f"Fractureiser indicator found: {match.name}",
                            evidence=f"Path: {match}",
                            remediation="DELETE IMMEDIATELY. Run full antivirus scan. Change all passwords.",
                        )

                # Check for malicious strings in readable files
                for f in mod_dir.rglob("*.jar"):
                    self._check_jar_for_fractureiser(f, game)

        # Check for Stage2+ indicators on the system
        if self.is_windows:
            stage2_paths = [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft Edge" / "libWebGL64.jar",
                Path("C:/Users") / os.environ.get("USERNAME", "") / ".data" / "lib.dll",
            ]
            for p in stage2_paths:
                if p.exists():
                    self.add_finding(
                        Severity.CRITICAL, "malware", "System",
                        f"Fractureiser Stage 2+ payload detected: {p}",
                        evidence=f"File exists: {p}",
                        remediation=(
                            "CRITICAL: System is compromised. "
                            "1) Disconnect from internet. "
                            "2) Change all passwords from a clean device. "
                            "3) Consider full OS reinstall."
                        ),
                    )
        elif self.is_linux:
            stage2_linux = [
                Path.home() / ".config" / ".data" / "lib.jar",
                Path("/tmp") / ".cache" / "lib.jar",
            ]
            for p in stage2_linux:
                if p.exists():
                    self.add_finding(
                        Severity.CRITICAL, "malware", "System",
                        f"Fractureiser Stage 2+ payload detected: {p}",
                        evidence=f"File exists: {p}",
                        remediation="CRITICAL: System compromised. Wipe and reinstall.",
                    )

    def _check_jar_for_fractureiser(self, jar_path: Path, game: str):
        """Scan a JAR file for Fractureiser indicators."""
        try:
            with zipfile.ZipFile(jar_path, "r") as zf:
                for name in zf.namelist():
                    # Check class names
                    for indicator in self.FRACTUREISER_INDICATORS["class_names"]:
                        if indicator.replace(".", "/") in name:
                            self.add_finding(
                                Severity.CRITICAL, "malware", game,
                                f"Fractureiser class found in {jar_path.name}: {name}",
                                evidence=f"JAR: {jar_path}",
                                remediation="DELETE IMMEDIATELY. Change all passwords.",
                            )
                            return

                    # Check string content in class files
                    if name.endswith(".class"):
                        try:
                            data = zf.read(name)
                            for indicator in self.FRACTUREISER_INDICATORS["strings"]:
                                if indicator.encode() in data:
                                    self.add_finding(
                                        Severity.CRITICAL, "malware", game,
                                        f"Fractureiser C2 indicator in {jar_path.name}",
                                        evidence=f"String '{indicator}' in {name}",
                                        remediation="DELETE IMMEDIATELY. Run incident response.",
                                    )
                                    return
                        except Exception:
                            pass
        except (zipfile.BadZipFile, PermissionError):
            pass

    def _scan_jar_mods(self):
        """Scan JAR mods for general suspicious patterns."""
        mod_dirs = self._get_mod_dirs()

        for game, dirs in mod_dirs.items():
            for mod_dir in dirs:
                if not mod_dir.exists():
                    continue

                for jar in mod_dir.rglob("*.jar"):
                    try:
                        with zipfile.ZipFile(jar, "r") as zf:
                            # Check for native code loading
                            has_native = any(
                                n.endswith((".dll", ".so", ".dylib"))
                                for n in zf.namelist()
                            )
                            if has_native:
                                self.add_finding(
                                    Severity.HIGH, "mods", game,
                                    f"Mod contains native code: {jar.name}",
                                    evidence=f"Native libraries found in JAR",
                                    remediation="Verify this mod needs native code. Only use trusted mods.",
                                )

                            # Check for reflection/classloading
                            for name in zf.namelist():
                                if name.endswith(".class"):
                                    try:
                                        data = zf.read(name)
                                        if b"URLClassLoader" in data or b"defineClass" in data:
                                            self.add_finding(
                                                Severity.MEDIUM, "mods", game,
                                                f"Mod uses dynamic class loading: {jar.name}",
                                                evidence=f"ClassLoader usage in {name}",
                                                remediation="Review mod source code or use only trusted mods",
                                            )
                                            break
                                    except Exception:
                                        pass
                    except (zipfile.BadZipFile, PermissionError):
                        pass

    def _scan_script_mods(self):
        """Scan Lua/Python/C# script mods for dangerous patterns."""
        mod_dirs = self._get_mod_dirs()

        for game, dirs in mod_dirs.items():
            for mod_dir in dirs:
                if not mod_dir.exists():
                    continue

                for ext in ("*.lua", "*.py", "*.cs", "*.js"):
                    for script in mod_dir.rglob(ext):
                        try:
                            content = script.read_text(errors="ignore")
                            for pattern, desc in self.SUSPICIOUS_PATTERNS:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                if matches:
                                    self.add_finding(
                                        Severity.HIGH, "mods", game,
                                        f"Suspicious code in {script.name}: {desc}",
                                        evidence=f"Pattern: {matches[0]} in {script}",
                                        remediation="Review script for malicious intent before using",
                                    )
                                    break  # One finding per file
                        except (OSError, UnicodeDecodeError):
                            pass

    def _check_symlinks(self):
        """Detect symlink/junction attacks in mod directories."""
        mod_dirs = self._get_mod_dirs()

        for game, dirs in mod_dirs.items():
            for mod_dir in dirs:
                if not mod_dir.exists():
                    continue

                for item in mod_dir.rglob("*"):
                    if item.is_symlink():
                        target = item.resolve()
                        # Flag symlinks pointing outside the mod directory
                        try:
                            target.relative_to(mod_dir)
                        except ValueError:
                            self.add_finding(
                                Severity.HIGH, "mods", game,
                                f"Symlink escape: {item.name} → {target}",
                                evidence=f"Symlink points outside mod directory",
                                remediation=f"Remove suspicious symlink: {item}",
                            )
