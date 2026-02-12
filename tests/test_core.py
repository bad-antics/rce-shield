"""Tests for RCE Shield core components."""

import json
import tempfile
from pathlib import Path

import pytest

from rce_shield.core import BaseScanner, Finding, Severity, ScanEngine


# ---------------------------------------------------------------------------
# Severity Tests
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_sort_order(self):
        assert Severity.CRITICAL.sort_key() < Severity.HIGH.sort_key()
        assert Severity.HIGH.sort_key() < Severity.MEDIUM.sort_key()
        assert Severity.MEDIUM.sort_key() < Severity.LOW.sort_key()
        assert Severity.LOW.sort_key() < Severity.INFO.sort_key()

    def test_all_values(self):
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        actual = {s.value for s in Severity}
        assert actual == expected


# ---------------------------------------------------------------------------
# Finding Tests
# ---------------------------------------------------------------------------


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            severity=Severity.HIGH,
            category="test",
            target="/usr/bin/test",
            description="Test finding",
        )
        assert f.severity == Severity.HIGH
        assert f.category == "test"
        assert f.target == "/usr/bin/test"
        assert f.evidence == ""
        assert f.cve is None

    def test_finding_to_dict(self):
        f = Finding(
            severity=Severity.CRITICAL,
            category="launcher",
            target="Steam",
            description="Vulnerable Steam version",
            evidence="Version 2.0",
            remediation="Update Steam",
            cve="CVE-2023-29011",
            cvss=7.8,
        )
        d = f.to_dict()
        assert d["severity"] == "CRITICAL"
        assert d["category"] == "launcher"
        assert d["cve"] == "CVE-2023-29011"
        assert d["cvss"] == 7.8
        assert isinstance(d, dict)

    def test_finding_optional_fields(self):
        f = Finding(
            severity=Severity.INFO,
            category="info",
            target="System",
            description="All good",
        )
        d = f.to_dict()
        assert d["evidence"] == ""
        assert d["remediation"] == ""
        assert d["cve"] is None
        assert d["cvss"] is None


# ---------------------------------------------------------------------------
# BaseScanner Tests
# ---------------------------------------------------------------------------


class MockScanner(BaseScanner):
    name = "Mock Scanner"
    description = "Scanner for testing"

    def scan(self):
        self.add_finding(
            Severity.HIGH, "test", "target1", "Finding 1",
            evidence="Evidence 1",
        )
        self.add_finding(
            Severity.LOW, "test", "target2", "Finding 2",
        )
        return self.findings


class EmptyScanner(BaseScanner):
    name = "Empty Scanner"
    description = "Returns no findings"

    def scan(self):
        return self.findings


class TestBaseScanner:
    def test_scan_returns_findings(self):
        scanner = MockScanner()
        findings = scanner.scan()
        assert len(findings) == 2
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.LOW

    def test_platform_detection(self):
        scanner = MockScanner()
        # At least one platform should be True
        assert scanner.is_windows or scanner.is_linux or scanner.is_mac

    def test_add_finding_helper(self):
        scanner = MockScanner()
        scanner.add_finding(
            Severity.CRITICAL, "cat", "tgt", "desc",
            evidence="ev", remediation="fix", cve="CVE-2024-0001", cvss=9.0,
        )
        assert len(scanner.findings) == 1
        assert scanner.findings[0].cve == "CVE-2024-0001"

    def test_empty_scanner(self):
        scanner = EmptyScanner()
        findings = scanner.scan()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ScanEngine Tests
# ---------------------------------------------------------------------------


class TestScanEngine:
    def test_register_and_run(self):
        engine = ScanEngine()
        engine.register(MockScanner())
        engine.register(EmptyScanner())

        results = engine.run_all()
        assert isinstance(results, list)
        assert len(results) == 2  # MockScanner produces 2 findings

    def test_summary(self):
        engine = ScanEngine()
        engine.register(MockScanner())
        engine.run_all()

        summary = engine.get_summary()
        assert summary["total"] == 2
        assert summary["high"] == 1
        assert summary["low"] == 1

    def test_empty_engine(self):
        engine = ScanEngine()
        results = engine.run_all()
        assert results == []

        summary = engine.get_summary()
        assert summary["total"] == 0


# ---------------------------------------------------------------------------
# Reporter Tests
# ---------------------------------------------------------------------------


class TestReporter:
    def test_json_report(self):
        from rce_shield.core.reporter import ReportGenerator

        findings = [
            Finding(Severity.HIGH, "test", "target", "desc1"),
            Finding(Severity.LOW, "test", "target2", "desc2"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            gen = ReportGenerator(findings)
            gen.generate_json(str(output))

            data = json.loads(output.read_text())
            assert data["meta"]["total_findings"] == 2
            assert len(data["findings"]) == 2
            assert "generated_at" in data["meta"]

    def test_csv_report(self):
        from rce_shield.core.reporter import ReportGenerator

        findings = [
            Finding(Severity.CRITICAL, "cat", "tgt", "Critical issue"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.csv"
            gen = ReportGenerator(findings)
            gen.generate_csv(str(output))

            content = output.read_text()
            assert "Severity" in content
            assert "CRITICAL" in content

    def test_html_report(self):
        from rce_shield.core.reporter import ReportGenerator

        findings = [
            Finding(Severity.HIGH, "network", "Port 3389", "RDP exposed"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.html"
            gen = ReportGenerator(findings)
            gen.generate_html(str(output))

            content = output.read_text()
            assert "<html" in content
            assert "RCE Shield" in content
            assert "RDP exposed" in content


# ---------------------------------------------------------------------------
# Utils Tests
# ---------------------------------------------------------------------------


class TestHashing:
    def test_hash_file(self):
        from rce_shield.utils.hashing import hash_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content for hashing")
            f.flush()
            path = f.name

        try:
            h = hash_file(path, "sha256")
            assert h is not None
            assert len(h) == 64  # SHA-256 hex digest is 64 chars

            h_md5 = hash_file(path, "md5")
            assert h_md5 is not None
            assert len(h_md5) == 32
        finally:
            Path(path).unlink()

    def test_hash_nonexistent(self):
        from rce_shield.utils.hashing import hash_file
        assert hash_file("/nonexistent/path/file.bin") is None

    def test_hash_bytes(self):
        from rce_shield.utils.hashing import hash_bytes
        h = hash_bytes(b"hello world")
        assert len(h) == 64

    def test_compare_identical(self):
        from rce_shield.utils.hashing import compare_hashes

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("identical content")
            path = f.name

        try:
            assert compare_hashes(path, path) is True
        finally:
            Path(path).unlink()


class TestPlatform:
    def test_platform_info(self):
        from rce_shield.utils.platform import get_platform_info

        info = get_platform_info()
        assert info.os_name in ("linux", "windows", "darwin")
        assert len(info.python_version) > 0
        assert len(info.architecture) > 0

    def test_is_admin(self):
        from rce_shield.utils.platform import is_admin
        # Just verify it returns a bool without error
        result = is_admin()
        assert isinstance(result, bool)


class TestProcess:
    def test_safe_process_info_current(self):
        import os
        from rce_shield.utils.process import safe_process_info

        info = safe_process_info(os.getpid())
        assert info is not None
        assert info["pid"] == os.getpid()
        assert "python" in info["name"].lower()

    def test_safe_process_info_nonexistent(self):
        from rce_shield.utils.process import safe_process_info
        assert safe_process_info(999999999) is None

    def test_find_processes(self):
        from rce_shield.utils.process import find_processes_by_name

        # Python should be running (us!)
        results = find_processes_by_name("python")
        assert len(results) > 0
