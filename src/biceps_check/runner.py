"""
Main scanner orchestrator for Biceps-Check.

This module coordinates the scanning process, including file discovery,
parsing, rule execution, and result aggregation.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import structlog

from biceps_check.config import BicepsCheckConfig
from biceps_check.parser.bicep_parser import BicepParser
from biceps_check.rules.base import BaseRule, CheckResult, RuleResult, Severity
from biceps_check.rules.registry import RuleRegistry

logger = structlog.get_logger()


@dataclass
class ScanResults:
    """Container for scan results."""

    files_scanned: int = 0
    resources_scanned: int = 0
    passed_checks: list[CheckResult] = field(default_factory=list)
    failed_checks: list[CheckResult] = field(default_factory=list)
    skipped_checks: list[CheckResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_checks(self) -> int:
        """Total number of checks run."""
        return len(self.passed_checks) + len(self.failed_checks) + len(self.skipped_checks)

    @property
    def passed_count(self) -> int:
        """Number of passed checks."""
        return len(self.passed_checks)

    @property
    def failed_count(self) -> int:
        """Number of failed checks."""
        return len(self.failed_checks)

    @property
    def skipped_count(self) -> int:
        """Number of skipped checks."""
        return len(self.skipped_checks)

    def add_result(self, result: CheckResult) -> None:
        """Add a check result to the appropriate list."""
        if result.result == RuleResult.PASSED:
            self.passed_checks.append(result)
        elif result.result == RuleResult.FAILED:
            self.failed_checks.append(result)
        elif result.result == RuleResult.SKIPPED:
            self.skipped_checks.append(result)

    def merge(self, other: "ScanResults") -> None:
        """Merge another ScanResults into this one."""
        self.files_scanned += other.files_scanned
        self.resources_scanned += other.resources_scanned
        self.passed_checks.extend(other.passed_checks)
        self.failed_checks.extend(other.failed_checks)
        self.skipped_checks.extend(other.skipped_checks)
        self.errors.extend(other.errors)


class BicepsCheckRunner:
    """Main scanner orchestrator."""

    def __init__(
        self,
        config: Optional[BicepsCheckConfig] = None,
    ) -> None:
        """Initialize the runner.

        Args:
            config: Configuration object. If None, defaults are used.
        """
        self.config = config or BicepsCheckConfig()
        self.parser = BicepParser()
        self.registry = RuleRegistry()
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all available rules into the registry."""
        self.registry.load_all_rules()

        # Apply configuration filters
        if self.config.checks.enable:
            self.registry.enable_only(self.config.checks.enable)
        if self.config.checks.skip:
            self.registry.disable(self.config.checks.skip)

        logger.info(
            "Rules loaded",
            total=self.registry.count,
            enabled=self.registry.enabled_count,
        )

    def scan_file(self, file_path: Path) -> ScanResults:
        """Scan a single Bicep file.

        Args:
            file_path: Path to the Bicep file.

        Returns:
            ScanResults containing all check results.
        """
        results = ScanResults()
        results.files_scanned = 1

        logger.info("Scanning file", path=str(file_path))

        try:
            # Parse the Bicep file
            bicep_file = self.parser.parse_file(file_path)
            results.resources_scanned = len(bicep_file.resources)

            # Run checks on each resource
            for resource in bicep_file.resources:
                applicable_rules = self.registry.get_rules_for_resource(
                    resource.resource_type
                )

                for rule in applicable_rules:
                    check_result = self._run_check(rule, resource, file_path)
                    if check_result and self._meets_severity_threshold(check_result):
                        results.add_result(check_result)

        except Exception as e:
            logger.error("Error scanning file", path=str(file_path), error=str(e))
            results.errors.append(f"{file_path}: {e}")

        return results

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
    ) -> ScanResults:
        """Scan a directory for Bicep files.

        Args:
            directory: Path to the directory.
            recursive: Whether to scan subdirectories.

        Returns:
            ScanResults containing all check results.
        """
        results = ScanResults()

        pattern = "**/*.bicep" if recursive else "*.bicep"
        bicep_files = list(directory.glob(pattern))

        logger.info(
            "Scanning directory",
            path=str(directory),
            files_found=len(bicep_files),
            recursive=recursive,
        )

        for file_path in bicep_files:
            file_results = self.scan_file(file_path)
            results.merge(file_results)

        return results

    def _run_check(
        self,
        rule: BaseRule,
        resource,
        file_path: Path,
    ) -> Optional[CheckResult]:
        """Run a single check on a resource.

        Args:
            rule: The rule to run.
            resource: The resource to check.
            file_path: Path to the source file.

        Returns:
            CheckResult or None if the check should be skipped.
        """
        # Check for inline suppressions
        if self._is_suppressed(rule.id, resource):
            return CheckResult(
                rule_id=rule.id,
                rule_name=rule.name,
                result=RuleResult.SKIPPED,
                severity=rule.severity,
                resource_name=resource.name,
                resource_type=resource.resource_type,
                file_path=file_path,
                line_number=resource.line_number,
                message="Suppressed by inline comment",
            )

        try:
            result = rule.check(resource)
            return CheckResult(
                rule_id=rule.id,
                rule_name=rule.name,
                result=result,
                severity=rule.severity,
                resource_name=resource.name,
                resource_type=resource.resource_type,
                file_path=file_path,
                line_number=resource.line_number,
                message=rule.get_message(resource) if result == RuleResult.FAILED else None,
                remediation=rule.remediation if result == RuleResult.FAILED else None,
            )
        except Exception as e:
            logger.error(
                "Error running check",
                rule=rule.id,
                resource=resource.name,
                error=str(e),
            )
            return None

    def _is_suppressed(self, rule_id: str, resource) -> bool:
        """Check if a rule is suppressed for a resource.

        Args:
            rule_id: The rule ID to check.
            resource: The resource being checked.

        Returns:
            True if the rule is suppressed.
        """
        # Check config-level suppressions
        for suppression in self.config.suppressions:
            if suppression.id == rule_id:
                if not suppression.resources or resource.name in suppression.resources:
                    # TODO: Check expiration date
                    return True

        # Inline suppressions are handled during parsing
        return resource.has_suppression(rule_id)

    def _meets_severity_threshold(self, result: CheckResult) -> bool:
        """Check if a result meets the minimum severity threshold.

        Args:
            result: The check result.

        Returns:
            True if the result meets the threshold.
        """
        severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

        result_index = severity_order.index(result.severity)
        threshold_index = severity_order.index(self.config.min_severity)

        return result_index >= threshold_index
