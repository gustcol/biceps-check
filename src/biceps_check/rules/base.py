"""
Base classes and types for security rules.

This module defines the foundational classes used by all security rules
in Biceps-Check.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from biceps_check.parser.models import BicepResource


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

    def __str__(self) -> str:
        return self.name


class RuleResult(Enum):
    """Result of a rule check."""

    PASSED = auto()
    FAILED = auto()
    SKIPPED = auto()
    ERROR = auto()

    def __str__(self) -> str:
        return self.name


@dataclass
class CheckResult:
    """Result of a single check execution."""

    rule_id: str
    rule_name: str
    result: RuleResult
    severity: Severity
    resource_name: str
    resource_type: str
    file_path: Path
    line_number: int
    message: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "result": self.result.name,
            "severity": self.severity.name,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "message": self.message,
            "remediation": self.remediation,
            "references": self.references,
        }


class BaseRule(ABC):
    """Base class for all security rules.

    All security rules must inherit from this class and implement
    the required abstract methods.

    Attributes:
        id: Unique identifier for the rule (e.g., BCK_AZURE_ST_001).
        name: Human-readable name for the rule.
        description: Detailed description of what the rule checks.
        severity: Severity level of the finding.
        resource_types: List of Azure resource types this rule applies to.
        category: Category for grouping rules (e.g., "storage", "compute").
        remediation: Guidance on how to fix the issue.
        references: List of reference URLs for more information.
        enabled: Whether the rule is enabled.
    """

    id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    resource_types: list[str] = []
    category: str = ""
    remediation: str = ""
    references: list[str] = []
    enabled: bool = True

    # Compliance framework mappings
    cis_azure: list[str] = []
    nist_800_53: list[str] = []
    pci_dss: list[str] = []
    hipaa: list[str] = []
    soc2: list[str] = []
    iso27001: list[str] = []
    azure_security_benchmark: list[str] = []

    @abstractmethod
    def check(self, resource: BicepResource) -> RuleResult:
        """Execute the security check on a resource.

        Args:
            resource: The Bicep resource to check.

        Returns:
            RuleResult indicating whether the check passed, failed, or was skipped.
        """

    def get_message(self, resource: BicepResource) -> str:
        """Get the failure message for a resource.

        Args:
            resource: The resource that failed the check.

        Returns:
            Human-readable failure message.
        """
        return f"{self.name}: {self.description}"

    def applies_to(self, resource_type: str) -> bool:
        """Check if this rule applies to a resource type.

        Args:
            resource_type: The Azure resource type (e.g., Microsoft.Storage/storageAccounts).

        Returns:
            True if the rule applies to this resource type.
        """
        if not self.resource_types:
            return True
        return resource_type in self.resource_types

    def get_compliance_mapping(self) -> dict[str, list[str]]:
        """Get compliance framework mappings for this rule.

        Returns:
            Dictionary mapping framework names to control IDs.
        """
        mappings = {}
        if self.cis_azure:
            mappings["CIS Azure"] = self.cis_azure
        if self.nist_800_53:
            mappings["NIST 800-53"] = self.nist_800_53
        if self.pci_dss:
            mappings["PCI DSS"] = self.pci_dss
        if self.hipaa:
            mappings["HIPAA"] = self.hipaa
        if self.soc2:
            mappings["SOC 2"] = self.soc2
        if self.iso27001:
            mappings["ISO 27001"] = self.iso27001
        if self.azure_security_benchmark:
            mappings["Azure Security Benchmark"] = self.azure_security_benchmark
        return mappings
