"""Tests for RCE Shield scanner modules."""

import pytest

from rce_shield.core import Severity
from rce_shield.scanners.launchers import LauncherScanner
from rce_shield.scanners.anticheat import AntiCheatScanner
from rce_shield.scanners.mods import ModScanner
from rce_shield.scanners.network import NetworkScanner
from rce_shield.scanners.overlays import OverlayScanner
from rce_shield.scanners.peripherals import PeripheralScanner


class TestLauncherScanner:
    def test_instantiation(self):
        scanner = LauncherScanner()
        assert scanner.name == "Game Launcher Scanner"

    def test_scan_runs(self):
        scanner = LauncherScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)
        # Should at least produce some findings (even if just info)

    def test_has_scanning_logic(self):
        scanner = LauncherScanner()
        # Verify scanner has expected methods
        assert hasattr(scanner, 'scan')
        assert hasattr(scanner, 'add_finding')
        assert callable(scanner.scan)


class TestAntiCheatScanner:
    def test_instantiation(self):
        scanner = AntiCheatScanner()
        assert scanner.name == "Anti-Cheat Auditor"

    def test_scan_runs(self):
        scanner = AntiCheatScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)


class TestModScanner:
    def test_instantiation(self):
        scanner = ModScanner()
        assert scanner.name == "Mod & Plugin Scanner"

    def test_scan_runs(self):
        scanner = ModScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)

    def test_fractureiser_indicators(self):
        scanner = ModScanner()
        # Verify malware indicators are defined
        assert hasattr(scanner, 'FRACTUREISER_INDICATORS')
        assert len(scanner.FRACTUREISER_INDICATORS) > 0


class TestNetworkScanner:
    def test_instantiation(self):
        scanner = NetworkScanner()
        assert scanner.name == "Gaming Network Scanner"

    def test_scan_runs(self):
        scanner = NetworkScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)

    def test_gaming_ports_populated(self):
        scanner = NetworkScanner()
        assert len(scanner.GAMING_PORTS) > 10
        # Common gaming ports should be present
        assert 27015 in scanner.GAMING_PORTS  # Source Engine
        assert 25565 in scanner.GAMING_PORTS  # Minecraft

    def test_critical_ports_subset(self):
        scanner = NetworkScanner()
        # All critical ports should also be in GAMING_PORTS
        for port in scanner.CRITICAL_PORTS:
            assert port in scanner.GAMING_PORTS


class TestOverlayScanner:
    def test_instantiation(self):
        scanner = OverlayScanner()
        assert scanner.name == "Overlay & Injection Scanner"

    def test_scan_runs(self):
        scanner = OverlayScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)

    def test_suspicious_dlls_populated(self):
        scanner = OverlayScanner()
        assert len(scanner.SUSPICIOUS_DLLS) > 0
        assert "d3d9.dll" in scanner.SUSPICIOUS_DLLS


class TestPeripheralScanner:
    def test_instantiation(self):
        scanner = PeripheralScanner()
        assert scanner.name == "Peripheral Software Scanner"

    def test_scan_runs(self):
        scanner = PeripheralScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)

    def test_known_software(self):
        scanner = PeripheralScanner()
        assert "iCUE.exe" in scanner.PERIPHERAL_SOFTWARE
        assert "Razer Synapse 3.exe" in scanner.PERIPHERAL_SOFTWARE


class TestAllScannersIntegration:
    """Integration test: run all scanners together."""

    def test_all_scanners_produce_list(self):
        scanners = [
            LauncherScanner(),
            AntiCheatScanner(),
            ModScanner(),
            NetworkScanner(),
            OverlayScanner(),
            PeripheralScanner(),
        ]

        for scanner in scanners:
            findings = scanner.scan()
            assert isinstance(findings, list), f"{scanner.name} did not return a list"
            for f in findings:
                assert isinstance(f.severity, Severity)
                assert isinstance(f.description, str)
                assert len(f.description) > 0
