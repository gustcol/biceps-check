"""
CLI output formatter.

This module provides rich terminal output formatting for scan results.
"""

from typing import TYPE_CHECKING

from rich.console import Console

from biceps_check import __version__
from biceps_check.output.base import BaseFormatter
from biceps_check.rules.base import Severity

if TYPE_CHECKING:
    from biceps_check.runner import ScanResults


class CLIFormatter(BaseFormatter):
    """Rich CLI output formatter."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "[!]",
        Severity.HIGH: "[H]",
        Severity.MEDIUM: "[M]",
        Severity.LOW: "[L]",
        Severity.INFO: "[i]",
    }

    def __init__(self, no_color: bool = False, compact: bool = False) -> None:
        """Initialize the formatter.

        Args:
            no_color: Disable colored output.
            compact: Use compact output format.
        """
        self.no_color = no_color
        self.compact = compact
        self.console = Console(no_color=no_color, force_terminal=not no_color)

    def format(self, results: "ScanResults") -> str:
        """Format scan results for CLI display.

        Args:
            results: The scan results to format.

        Returns:
            Formatted string output.
        """
        output_parts = []

        # Header
        output_parts.append(self._format_header())

        # Summary
        output_parts.append(self._format_summary(results))

        # Failed checks
        if results.failed_checks:
            output_parts.append(self._format_failed_checks(results))

        # Errors
        if results.errors:
            output_parts.append(self._format_errors(results))

        return "\n".join(output_parts)

    def _format_header(self) -> str:
        """Format the output header."""
        return f"\nBiceps-Check v{__version__}\n"

    def _format_summary(self, results: "ScanResults") -> str:
        """Format the summary section."""
        lines = [
            f"Files scanned: {results.files_scanned}",
            f"Resources scanned: {results.resources_scanned}",
            "",
            f"Passed checks:  {results.passed_count}",
            f"Failed checks:  {results.failed_count}",
            f"Skipped checks: {results.skipped_count}",
            "",
        ]
        return "\n".join(lines)

    def _format_failed_checks(self, results: "ScanResults") -> str:
        """Format the failed checks section."""
        lines = ["Failed Checks:", "=" * 50, ""]

        # Sort by severity (critical first)
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        sorted_checks = sorted(
            results.failed_checks,
            key=lambda c: (severity_order.index(c.severity), c.rule_id),
        )

        for check in sorted_checks:
            if self.compact:
                lines.append(self._format_check_compact(check))
            else:
                lines.append(self._format_check_detailed(check))
                lines.append("")

        return "\n".join(lines)

    def _format_check_compact(self, check) -> str:
        """Format a single check in compact format."""
        icon = self.SEVERITY_ICONS.get(check.severity, "[?]")
        return f"{icon} {check.rule_id}: {check.file_path}:{check.line_number} - {check.resource_name}"

    def _format_check_detailed(self, check) -> str:
        """Format a single check in detailed format."""
        severity_name = check.severity.name
        lines = [
            f"[{severity_name}] {check.rule_id}: {check.rule_name}",
            f"  File: {check.file_path}:{check.line_number}",
            f"  Resource: {check.resource_name} ({check.resource_type})",
        ]

        if check.message:
            lines.append(f"  Message: {check.message}")

        if check.remediation:
            lines.append(f"  Remediation: {check.remediation}")

        lines.append(f"  Guide: https://docs.biceps-check.io/rules/{check.rule_id}")

        return "\n".join(lines)

    def _format_errors(self, results: "ScanResults") -> str:
        """Format the errors section."""
        lines = ["", "Errors:", "-" * 30]
        for error in results.errors:
            lines.append(f"  - {error}")
        return "\n".join(lines)
