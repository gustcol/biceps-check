"""
SARIF output formatter.

This module provides SARIF (Static Analysis Results Interchange Format)
output formatting for integration with GitHub Security and other tools.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from biceps_check import __version__
from biceps_check.output.base import BaseFormatter
from biceps_check.rules.base import Severity

if TYPE_CHECKING:
    from biceps_check.runner import ScanResults


class SARIFFormatter(BaseFormatter):
    """SARIF 2.1.0 output formatter."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    def format(self, results: "ScanResults") -> str:
        """Format scan results as SARIF.

        Args:
            results: The scan results to format.

        Returns:
            SARIF JSON string output.
        """
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": self._get_tool_info(),
                    "results": self._get_results(results),
                    "invocations": [
                        {
                            "executionSuccessful": len(results.errors) == 0,
                            "endTimeUtc": datetime.now(timezone.utc)
                            .isoformat()
                            .replace("+00:00", "Z"),
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _get_tool_info(self) -> dict[str, Any]:
        """Generate the tool information section."""
        return {
            "driver": {
                "name": "biceps-check",
                "version": __version__,
                "informationUri": "https://github.com/gustcol/biceps-check",
                "rules": [],  # Rules are populated dynamically
            }
        }

    def _get_results(self, results: "ScanResults") -> list[dict[str, Any]]:
        """Generate the results section."""
        sarif_results = []

        for check in results.failed_checks:
            sarif_result = {
                "ruleId": check.rule_id,
                "level": self.SEVERITY_TO_LEVEL.get(check.severity, "warning"),
                "message": {
                    "text": check.message or check.rule_name,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(check.file_path),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": check.line_number,
                            },
                        },
                        "logicalLocations": [
                            {
                                "name": check.resource_name,
                                "kind": "resource",
                                "fullyQualifiedName": f"{check.resource_type}/{check.resource_name}",
                            }
                        ],
                    }
                ],
                "properties": {
                    "severity": check.severity.name,
                    "resourceType": check.resource_type,
                    "resourceName": check.resource_name,
                },
            }

            if check.remediation:
                sarif_result["fixes"] = [
                    {
                        "description": {
                            "text": check.remediation,
                        }
                    }
                ]

            sarif_results.append(sarif_result)

        return sarif_results
