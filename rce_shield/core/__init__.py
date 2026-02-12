"""
Core scanner engine — base classes and finding data models.
"""

from __future__ import annotations

import platform
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def sort_key(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


@dataclass
class Finding:
    """A single security finding from a scan."""

    severity: Severity
    category: str
    target: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cve: Optional[str] = None
    cvss: Optional[float] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "cvss": self.cvss,
            "references": self.references,
        }


class BaseScanner(ABC):
    """Abstract base class for all scan modules."""

    name: str = "BaseScanner"
    description: str = ""

    def __init__(self):
        self.findings: list[Finding] = []
        self.is_windows = platform.system() == "Windows"
        self.is_linux = platform.system() == "Linux"

    def add_finding(
        self,
        severity: Severity,
        category: str,
        target: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        cve: Optional[str] = None,
        cvss: Optional[float] = None,
    ) -> Finding:
        finding = Finding(
            severity=severity,
            category=category,
            target=target,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cve=cve,
            cvss=cvss,
        )
        self.findings.append(finding)
        return finding

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Execute the scan and return findings."""
        ...

    def is_available(self) -> bool:
        """Check if this scanner can run on the current platform."""
        return True


class ScanEngine:
    """Orchestrates multiple scanners and aggregates findings."""

    def __init__(self):
        self.scanners: list[BaseScanner] = []
        self.all_findings: list[Finding] = []

    def register(self, scanner: BaseScanner):
        self.scanners.append(scanner)

    def run_all(self) -> list[Finding]:
        for scanner in self.scanners:
            if scanner.is_available():
                findings = scanner.scan()
                self.all_findings.extend(findings)
        return self.all_findings

    def get_summary(self) -> dict:
        counts = {s: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity] += 1
        return {
            "total": len(self.all_findings),
            "critical": counts[Severity.CRITICAL],
            "high": counts[Severity.HIGH],
            "medium": counts[Severity.MEDIUM],
            "low": counts[Severity.LOW],
            "info": counts[Severity.INFO],
        }
