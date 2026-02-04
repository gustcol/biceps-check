"""
JSON output formatter.

This module provides JSON output formatting for scan results.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from biceps_check import __version__
from biceps_check.output.base import BaseFormatter

if TYPE_CHECKING:
    from biceps_check.runner import ScanResults


class JSONFormatter(BaseFormatter):
    """JSON output formatter."""

    def __init__(self, pretty: bool = True) -> None:
        """Initialize the formatter.

        Args:
            pretty: Use pretty-printed JSON output.
        """
        self.pretty = pretty

    def format(self, results: "ScanResults") -> str:
        """Format scan results as JSON.

        Args:
            results: The scan results to format.

        Returns:
            JSON string output.
        """
        output = {
            "version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "summary": {
                "files_scanned": results.files_scanned,
                "resources_scanned": results.resources_scanned,
                "passed_checks": results.passed_count,
                "failed_checks": results.failed_count,
                "skipped_checks": results.skipped_count,
            },
            "passed": [check.to_dict() for check in results.passed_checks],
            "failed": [check.to_dict() for check in results.failed_checks],
            "skipped": [check.to_dict() for check in results.skipped_checks],
            "errors": results.errors,
        }

        if self.pretty:
            return json.dumps(output, indent=2, default=str)
        return json.dumps(output, default=str)
