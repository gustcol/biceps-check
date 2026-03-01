"""Unit tests for output formatters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from biceps_check import __version__
from biceps_check.output.cli_formatter import CLIFormatter
from biceps_check.output.json_formatter import JSONFormatter
from biceps_check.output.sarif_formatter import SARIFFormatter
from biceps_check.rules.base import CheckResult, RuleResult, Severity
from biceps_check.runner import ScanResults

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_check_result(
    rule_id: str = "BCK_AZURE_ST_001",
    rule_name: str = "Storage HTTPS Only",
    result: RuleResult = RuleResult.FAILED,
    severity: Severity = Severity.HIGH,
    resource_name: str = "myStorage",
    resource_type: str = "Microsoft.Storage/storageAccounts",
    file_path: str = "infra/main.bicep",
    line_number: int = 10,
    message: str | None = "HTTPS-only traffic must be enforced",
    remediation: str | None = "Set supportsHttpsTrafficOnly to true",
    references: list[str] | None = None,
) -> CheckResult:
    """Build a CheckResult with sensible defaults."""
    return CheckResult(
        rule_id=rule_id,
        rule_name=rule_name,
        result=result,
        severity=severity,
        resource_name=resource_name,
        resource_type=resource_type,
        file_path=Path(file_path),
        line_number=line_number,
        message=message,
        remediation=remediation,
        references=references or [],
    )


@pytest.fixture
def passed_check() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_001",
        rule_name="Storage HTTPS Only",
        result=RuleResult.PASSED,
        severity=Severity.HIGH,
        message=None,
        remediation=None,
    )


@pytest.fixture
def failed_check_high() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_002",
        rule_name="Storage Minimum TLS",
        result=RuleResult.FAILED,
        severity=Severity.HIGH,
        message="Minimum TLS version must be TLS1_2",
        remediation="Set minimumTlsVersion to TLS1_2",
    )


@pytest.fixture
def failed_check_critical() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_005",
        rule_name="Storage Network Rules",
        result=RuleResult.FAILED,
        severity=Severity.CRITICAL,
        message="Network access must be restricted",
        remediation="Set networkAcls.defaultAction to Deny",
    )


@pytest.fixture
def failed_check_medium() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_004",
        rule_name="Storage Public Blob Access",
        result=RuleResult.FAILED,
        severity=Severity.MEDIUM,
        message="Public blob access should be disabled",
        remediation="Set allowBlobPublicAccess to false",
    )


@pytest.fixture
def failed_check_low() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_010",
        rule_name="Storage Diagnostic Logs",
        result=RuleResult.FAILED,
        severity=Severity.LOW,
        message="Diagnostic logs should be enabled",
        remediation="Enable diagnostic settings",
    )


@pytest.fixture
def failed_check_info() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_099",
        rule_name="Storage Tagging",
        result=RuleResult.FAILED,
        severity=Severity.INFO,
        message="Resource should have cost-center tag",
        remediation="Add a cost-center tag",
    )


@pytest.fixture
def skipped_check() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_008",
        rule_name="Storage Infrastructure Encryption",
        result=RuleResult.SKIPPED,
        severity=Severity.HIGH,
        message="Suppressed by inline comment",
        remediation=None,
    )


@pytest.fixture
def failed_check_no_message() -> CheckResult:
    return make_check_result(
        rule_id="BCK_AZURE_ST_003",
        rule_name="Storage Shared Key Access",
        result=RuleResult.FAILED,
        severity=Severity.MEDIUM,
        message=None,
        remediation=None,
    )


@pytest.fixture
def empty_results() -> ScanResults:
    return ScanResults(files_scanned=0, resources_scanned=0)


@pytest.fixture
def results_with_all_outcomes(passed_check, failed_check_high, skipped_check) -> ScanResults:
    results = ScanResults(files_scanned=1, resources_scanned=3)
    results.add_result(passed_check)
    results.add_result(failed_check_high)
    results.add_result(skipped_check)
    return results


@pytest.fixture
def results_only_failures(
    failed_check_critical, failed_check_high, failed_check_medium
) -> ScanResults:
    results = ScanResults(files_scanned=2, resources_scanned=5)
    results.add_result(failed_check_critical)
    results.add_result(failed_check_high)
    results.add_result(failed_check_medium)
    return results


@pytest.fixture
def results_with_errors(failed_check_high) -> ScanResults:
    results = ScanResults(files_scanned=1, resources_scanned=1)
    results.add_result(failed_check_high)
    results.errors.append("infra/broken.bicep: SyntaxError at line 5")
    return results


# ---------------------------------------------------------------------------
# CLIFormatter tests
# ---------------------------------------------------------------------------


class TestCLIFormatterNoResults:
    """CLIFormatter behaviour when there are no check results."""

    def test_format_returns_string(self, empty_results):
        formatter = CLIFormatter()
        output = formatter.format(empty_results)
        assert isinstance(output, str)

    def test_header_present(self, empty_results):
        formatter = CLIFormatter()
        output = formatter.format(empty_results)
        assert f"Biceps-Check v{__version__}" in output

    def test_summary_counts_zero(self, empty_results):
        formatter = CLIFormatter()
        output = formatter.format(empty_results)
        assert "Files scanned: 0" in output
        assert "Resources scanned: 0" in output
        assert "Passed checks:  0" in output
        assert "Failed checks:  0" in output
        assert "Skipped checks: 0" in output

    def test_no_failed_checks_section(self, empty_results):
        formatter = CLIFormatter()
        output = formatter.format(empty_results)
        assert "Failed Checks:" not in output

    def test_no_errors_section(self, empty_results):
        formatter = CLIFormatter()
        output = formatter.format(empty_results)
        assert "Errors:" not in output


class TestCLIFormatterWithResults:
    """CLIFormatter with mixed passed / failed / skipped results."""

    def test_summary_reflects_counts(self, results_with_all_outcomes):
        formatter = CLIFormatter()
        output = formatter.format(results_with_all_outcomes)
        assert "Passed checks:  1" in output
        assert "Failed checks:  1" in output
        assert "Skipped checks: 1" in output

    def test_failed_checks_section_present(self, results_with_all_outcomes):
        formatter = CLIFormatter()
        output = formatter.format(results_with_all_outcomes)
        assert "Failed Checks:" in output

    def test_failed_checks_separator(self, results_with_all_outcomes):
        formatter = CLIFormatter()
        output = formatter.format(results_with_all_outcomes)
        assert "=" * 50 in output

    def test_files_and_resources_scanned(self, results_with_all_outcomes):
        formatter = CLIFormatter()
        output = formatter.format(results_with_all_outcomes)
        assert "Files scanned: 1" in output
        assert "Resources scanned: 3" in output

    def test_errors_section_shown_when_errors_present(self, results_with_errors):
        formatter = CLIFormatter()
        output = formatter.format(results_with_errors)
        assert "Errors:" in output
        assert "infra/broken.bicep: SyntaxError at line 5" in output

    def test_errors_section_absent_when_no_errors(self, results_with_all_outcomes):
        formatter = CLIFormatter()
        output = formatter.format(results_with_all_outcomes)
        assert "Errors:" not in output


class TestCLIFormatterCompactMode:
    """CLIFormatter compact=True mode."""

    def test_compact_uses_icon_prefix(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results_with_all_outcomes)
        # HIGH severity icon is [H]
        assert "[H]" in output

    def test_compact_includes_rule_id_and_file(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results_with_all_outcomes)
        assert "BCK_AZURE_ST_002" in output
        assert "infra/main.bicep" in output

    def test_compact_includes_resource_name(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results_with_all_outcomes)
        assert "myStorage" in output

    def test_compact_does_not_include_remediation(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results_with_all_outcomes)
        # Compact mode does not render the full detail block
        assert "Remediation:" not in output

    def test_compact_includes_line_number(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results_with_all_outcomes)
        assert ":10" in output


class TestCLIFormatterDetailedMode:
    """CLIFormatter compact=False (default, detailed) mode."""

    def test_detailed_includes_severity_label(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "[HIGH]" in output

    def test_detailed_includes_rule_name(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "Storage Minimum TLS" in output

    def test_detailed_includes_file_and_line(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "File: infra/main.bicep:10" in output

    def test_detailed_includes_resource_type(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "Microsoft.Storage/storageAccounts" in output

    def test_detailed_includes_message(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "Minimum TLS version must be TLS1_2" in output

    def test_detailed_includes_remediation(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "Remediation: Set minimumTlsVersion to TLS1_2" in output

    def test_detailed_includes_guide_link(self, results_with_all_outcomes):
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results_with_all_outcomes)
        assert "Guide: https://docs.biceps-check.io/rules/BCK_AZURE_ST_002" in output

    def test_detailed_omits_message_when_none(self, failed_check_no_message):
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(failed_check_no_message)
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results)
        assert "Message:" not in output

    def test_detailed_omits_remediation_when_none(self, failed_check_no_message):
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(failed_check_no_message)
        formatter = CLIFormatter(compact=False)
        output = formatter.format(results)
        assert "Remediation:" not in output


class TestCLIFormatterNoColor:
    """CLIFormatter no_color option."""

    def test_no_color_returns_string(self, results_with_all_outcomes):
        formatter = CLIFormatter(no_color=True)
        output = formatter.format(results_with_all_outcomes)
        assert isinstance(output, str)

    def test_no_color_still_contains_content(self, results_with_all_outcomes):
        formatter = CLIFormatter(no_color=True)
        output = formatter.format(results_with_all_outcomes)
        assert f"Biceps-Check v{__version__}" in output
        assert "Failed Checks:" in output

    def test_no_color_flag_stored_on_formatter(self):
        formatter = CLIFormatter(no_color=True)
        assert formatter.no_color is True

    def test_color_enabled_by_default(self):
        formatter = CLIFormatter()
        assert formatter.no_color is False


class TestCLIFormatterFormatCheckCompact:
    """Unit-level tests for _format_check_compact."""

    def test_critical_icon(self, failed_check_critical):
        formatter = CLIFormatter()
        line = formatter._format_check_compact(failed_check_critical)
        assert line.startswith("[!]")

    def test_high_icon(self, failed_check_high):
        formatter = CLIFormatter()
        line = formatter._format_check_compact(failed_check_high)
        assert line.startswith("[H]")

    def test_medium_icon(self, failed_check_medium):
        formatter = CLIFormatter()
        line = formatter._format_check_compact(failed_check_medium)
        assert line.startswith("[M]")

    def test_low_icon(self, failed_check_low):
        formatter = CLIFormatter()
        line = formatter._format_check_compact(failed_check_low)
        assert line.startswith("[L]")

    def test_info_icon(self, failed_check_info):
        formatter = CLIFormatter()
        line = formatter._format_check_compact(failed_check_info)
        assert line.startswith("[i]")

    def test_compact_format_structure(self, failed_check_high):
        formatter = CLIFormatter()
        line = formatter._format_check_compact(failed_check_high)
        assert "BCK_AZURE_ST_002" in line
        assert "infra/main.bicep" in line
        assert "10" in line
        assert "myStorage" in line


class TestCLIFormatterFormatCheckDetailed:
    """Unit-level tests for _format_check_detailed."""

    def test_severity_name_in_brackets(self, failed_check_critical):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_critical)
        assert "[CRITICAL]" in block

    def test_rule_id_present(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "BCK_AZURE_ST_002" in block

    def test_rule_name_present(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "Storage Minimum TLS" in block

    def test_file_line_present(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "infra/main.bicep:10" in block

    def test_resource_name_and_type_present(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "myStorage" in block
        assert "Microsoft.Storage/storageAccounts" in block

    def test_message_rendered(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "Message: Minimum TLS version must be TLS1_2" in block

    def test_remediation_rendered(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "Remediation: Set minimumTlsVersion to TLS1_2" in block

    def test_guide_link_rendered(self, failed_check_high):
        formatter = CLIFormatter()
        block = formatter._format_check_detailed(failed_check_high)
        assert "https://docs.biceps-check.io/rules/BCK_AZURE_ST_002" in block


class TestCLIFormatterSeveritySorting:
    """Failed checks must be emitted in descending severity order."""

    def test_critical_before_high(self, failed_check_critical, failed_check_high):
        results = ScanResults(files_scanned=1, resources_scanned=2)
        # Insert in reverse order to confirm sorting
        results.add_result(failed_check_high)
        results.add_result(failed_check_critical)
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results)
        critical_pos = output.index("BCK_AZURE_ST_005")
        high_pos = output.index("BCK_AZURE_ST_002")
        assert critical_pos < high_pos

    def test_high_before_medium(self, failed_check_high, failed_check_medium):
        results = ScanResults(files_scanned=1, resources_scanned=2)
        results.add_result(failed_check_medium)
        results.add_result(failed_check_high)
        formatter = CLIFormatter(compact=True)
        output = formatter.format(results)
        high_pos = output.index("BCK_AZURE_ST_002")
        medium_pos = output.index("BCK_AZURE_ST_004")
        assert high_pos < medium_pos

    def test_all_severities_ordered(
        self,
        failed_check_critical,
        failed_check_high,
        failed_check_medium,
        failed_check_low,
        failed_check_info,
    ):
        results = ScanResults(files_scanned=1, resources_scanned=5)
        # Add in worst-to-best order and verify same order is preserved in output
        for check in [
            failed_check_info,
            failed_check_low,
            failed_check_medium,
            failed_check_high,
            failed_check_critical,
        ]:
            results.add_result(check)

        formatter = CLIFormatter(compact=True)
        output = formatter.format(results)

        positions = {
            "CRITICAL": output.index("BCK_AZURE_ST_005"),
            "HIGH": output.index("BCK_AZURE_ST_002"),
            "MEDIUM": output.index("BCK_AZURE_ST_004"),
            "LOW": output.index("BCK_AZURE_ST_010"),
            "INFO": output.index("BCK_AZURE_ST_099"),
        }
        assert positions["CRITICAL"] < positions["HIGH"]
        assert positions["HIGH"] < positions["MEDIUM"]
        assert positions["MEDIUM"] < positions["LOW"]
        assert positions["LOW"] < positions["INFO"]


# ---------------------------------------------------------------------------
# JSONFormatter tests
# ---------------------------------------------------------------------------


class TestJSONFormatterFormat:
    """JSONFormatter.format produces valid, well-structured JSON."""

    def test_output_is_valid_json(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        output = formatter.format(results_with_all_outcomes)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_pretty_output_has_indentation(self, results_with_all_outcomes):
        formatter = JSONFormatter(pretty=True)
        output = formatter.format(results_with_all_outcomes)
        assert "\n" in output
        assert "  " in output

    def test_non_pretty_output_is_compact(self, results_with_all_outcomes):
        formatter = JSONFormatter(pretty=False)
        output = formatter.format(results_with_all_outcomes)
        data = json.loads(output)
        assert isinstance(data, dict)
        # Compact JSON should not start with whitespace on the second line
        lines = output.splitlines()
        assert len(lines) == 1

    def test_pretty_flag_default_is_true(self):
        formatter = JSONFormatter()
        assert formatter.pretty is True


class TestJSONFormatterTopLevelFields:
    """JSON output must include version, timestamp, and summary."""

    def test_version_field_matches_package_version(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["version"] == __version__

    def test_timestamp_field_present(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "timestamp" in data
        assert data["timestamp"].endswith("Z")

    def test_summary_field_present(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "summary" in data

    def test_summary_files_scanned(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["summary"]["files_scanned"] == 1

    def test_summary_resources_scanned(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["summary"]["resources_scanned"] == 3

    def test_summary_passed_checks_count(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["summary"]["passed_checks"] == 1

    def test_summary_failed_checks_count(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["summary"]["failed_checks"] == 1

    def test_summary_skipped_checks_count(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["summary"]["skipped_checks"] == 1

    def test_errors_list_included(self, results_with_errors):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_errors))
        assert "errors" in data
        assert len(data["errors"]) == 1
        assert "infra/broken.bicep" in data["errors"][0]

    def test_errors_empty_when_no_errors(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["errors"] == []


class TestJSONFormatterCheckSerialization:
    """Each CheckResult must be properly serialized in the JSON output."""

    def test_passed_list_present(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "passed" in data
        assert len(data["passed"]) == 1

    def test_failed_list_present(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "failed" in data
        assert len(data["failed"]) == 1

    def test_skipped_list_present(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "skipped" in data
        assert len(data["skipped"]) == 1

    def test_failed_check_rule_id(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["rule_id"] == "BCK_AZURE_ST_002"

    def test_failed_check_rule_name(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["rule_name"] == "Storage Minimum TLS"

    def test_failed_check_result_value(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["result"] == "FAILED"

    def test_failed_check_severity(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["severity"] == "HIGH"

    def test_failed_check_resource_name(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["resource_name"] == "myStorage"

    def test_failed_check_resource_type(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["resource_type"] == "Microsoft.Storage/storageAccounts"

    def test_failed_check_file_path(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert "infra/main.bicep" in failed["file_path"]

    def test_failed_check_line_number(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["line_number"] == 10

    def test_failed_check_message(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["message"] == "Minimum TLS version must be TLS1_2"

    def test_failed_check_remediation(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert failed["remediation"] == "Set minimumTlsVersion to TLS1_2"

    def test_failed_check_references_list(self, results_with_all_outcomes):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        failed = data["failed"][0]
        assert isinstance(failed["references"], list)

    def test_empty_results_produce_empty_lists(self, empty_results):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(empty_results))
        assert data["passed"] == []
        assert data["failed"] == []
        assert data["skipped"] == []

    def test_multiple_failed_checks_all_serialized(self, results_only_failures):
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results_only_failures))
        assert len(data["failed"]) == 3

    def test_message_is_null_when_none(self, passed_check):
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(passed_check)
        formatter = JSONFormatter()
        data = json.loads(formatter.format(results))
        passed = data["passed"][0]
        assert passed["message"] is None


# ---------------------------------------------------------------------------
# SARIFFormatter tests
# ---------------------------------------------------------------------------


class TestSARIFFormatterSchemaAndVersion:
    """SARIF output must declare the correct version and schema."""

    def test_output_is_valid_json(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        output = formatter.format(results_with_all_outcomes)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_sarif_version(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["version"] == "2.1.0"

    def test_sarif_schema_field(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert data["$schema"] == SARIFFormatter.SARIF_SCHEMA

    def test_sarif_schema_url_points_to_oasis(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "oasis-tcs" in data["$schema"]

    def test_runs_list_present(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "runs" in data
        assert len(data["runs"]) == 1


class TestSARIFFormatterToolInfo:
    """Tool driver section must be present and well-formed."""

    def test_tool_driver_name(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "biceps-check"

    def test_tool_driver_version(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__

    def test_tool_driver_information_uri(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        driver = data["runs"][0]["tool"]["driver"]
        assert "biceps-check" in driver["informationUri"]

    def test_tool_driver_rules_is_list(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        driver = data["runs"][0]["tool"]["driver"]
        assert isinstance(driver["rules"], list)


class TestSARIFFormatterSeverityMapping:
    """Severity values must map to the correct SARIF level strings."""

    def _get_level_for_check(self, check: CheckResult) -> str:
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(check)
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results))
        return data["runs"][0]["results"][0]["level"]

    def test_critical_maps_to_error(self, failed_check_critical):
        assert self._get_level_for_check(failed_check_critical) == "error"

    def test_high_maps_to_error(self, failed_check_high):
        assert self._get_level_for_check(failed_check_high) == "error"

    def test_medium_maps_to_warning(self, failed_check_medium):
        assert self._get_level_for_check(failed_check_medium) == "warning"

    def test_low_maps_to_note(self, failed_check_low):
        assert self._get_level_for_check(failed_check_low) == "note"

    def test_info_maps_to_note(self, failed_check_info):
        assert self._get_level_for_check(failed_check_info) == "note"


class TestSARIFFormatterResults:
    """SARIF results entries must contain required fields."""

    def _get_first_result(self, check: CheckResult) -> dict:
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(check)
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results))
        return data["runs"][0]["results"][0]

    def test_rule_id_in_result(self, failed_check_high):
        entry = self._get_first_result(failed_check_high)
        assert entry["ruleId"] == "BCK_AZURE_ST_002"

    def test_message_text_in_result(self, failed_check_high):
        entry = self._get_first_result(failed_check_high)
        assert entry["message"]["text"] == "Minimum TLS version must be TLS1_2"

    def test_message_falls_back_to_rule_name_when_no_message(self, failed_check_no_message):
        entry = self._get_first_result(failed_check_no_message)
        assert entry["message"]["text"] == "Storage Shared Key Access"

    def test_only_failed_checks_appear_in_sarif_results(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        # results_with_all_outcomes has 1 failed, 1 passed, 1 skipped
        assert len(data["runs"][0]["results"]) == 1

    def test_empty_results_yields_no_sarif_results(self, empty_results):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(empty_results))
        assert data["runs"][0]["results"] == []

    def test_multiple_failures_all_in_sarif(self, results_only_failures):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_only_failures))
        assert len(data["runs"][0]["results"]) == 3


class TestSARIFFormatterLocations:
    """SARIF result locations must contain physicalLocation and logicalLocations."""

    def _get_location(self, check: CheckResult) -> dict:
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(check)
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results))
        return data["runs"][0]["results"][0]["locations"][0]

    def test_physical_location_present(self, failed_check_high):
        location = self._get_location(failed_check_high)
        assert "physicalLocation" in location

    def test_artifact_location_uri(self, failed_check_high):
        location = self._get_location(failed_check_high)
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        assert "infra/main.bicep" in uri

    def test_artifact_location_uri_base_id(self, failed_check_high):
        location = self._get_location(failed_check_high)
        base_id = location["physicalLocation"]["artifactLocation"]["uriBaseId"]
        assert base_id == "%SRCROOT%"

    def test_region_start_line(self, failed_check_high):
        location = self._get_location(failed_check_high)
        start_line = location["physicalLocation"]["region"]["startLine"]
        assert start_line == 10

    def test_logical_locations_present(self, failed_check_high):
        location = self._get_location(failed_check_high)
        assert "logicalLocations" in location
        assert len(location["logicalLocations"]) == 1

    def test_logical_location_name(self, failed_check_high):
        location = self._get_location(failed_check_high)
        log_loc = location["logicalLocations"][0]
        assert log_loc["name"] == "myStorage"

    def test_logical_location_kind(self, failed_check_high):
        location = self._get_location(failed_check_high)
        log_loc = location["logicalLocations"][0]
        assert log_loc["kind"] == "resource"

    def test_logical_location_fully_qualified_name(self, failed_check_high):
        location = self._get_location(failed_check_high)
        log_loc = location["logicalLocations"][0]
        assert log_loc["fullyQualifiedName"] == "Microsoft.Storage/storageAccounts/myStorage"


class TestSARIFFormatterProperties:
    """SARIF result properties must include severity and resource metadata."""

    def _get_properties(self, check: CheckResult) -> dict:
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(check)
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results))
        return data["runs"][0]["results"][0]["properties"]

    def test_severity_property(self, failed_check_high):
        props = self._get_properties(failed_check_high)
        assert props["severity"] == "HIGH"

    def test_severity_property_critical(self, failed_check_critical):
        props = self._get_properties(failed_check_critical)
        assert props["severity"] == "CRITICAL"

    def test_resource_type_property(self, failed_check_high):
        props = self._get_properties(failed_check_high)
        assert props["resourceType"] == "Microsoft.Storage/storageAccounts"

    def test_resource_name_property(self, failed_check_high):
        props = self._get_properties(failed_check_high)
        assert props["resourceName"] == "myStorage"


class TestSARIFFormatterFixes:
    """Remediation text must appear in the SARIF fixes section."""

    def _get_first_result(self, check: CheckResult) -> dict:
        results = ScanResults(files_scanned=1, resources_scanned=1)
        results.add_result(check)
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results))
        return data["runs"][0]["results"][0]

    def test_fixes_present_when_remediation_set(self, failed_check_high):
        entry = self._get_first_result(failed_check_high)
        assert "fixes" in entry

    def test_fixes_description_text(self, failed_check_high):
        entry = self._get_first_result(failed_check_high)
        description = entry["fixes"][0]["description"]["text"]
        assert description == "Set minimumTlsVersion to TLS1_2"

    def test_fixes_absent_when_no_remediation(self, failed_check_no_message):
        # failed_check_no_message has remediation=None
        entry = self._get_first_result(failed_check_no_message)
        assert "fixes" not in entry

    def test_fixes_critical_check(self, failed_check_critical):
        entry = self._get_first_result(failed_check_critical)
        assert "fixes" in entry
        assert "Deny" in entry["fixes"][0]["description"]["text"]


class TestSARIFFormatterInvocations:
    """Invocations section must reflect execution status."""

    def test_invocations_present(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        assert "invocations" in data["runs"][0]

    def test_execution_successful_when_no_errors(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        invocation = data["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True

    def test_execution_not_successful_when_errors(self, results_with_errors):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_errors))
        invocation = data["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False

    def test_end_time_utc_present(self, results_with_all_outcomes):
        formatter = SARIFFormatter()
        data = json.loads(formatter.format(results_with_all_outcomes))
        invocation = data["runs"][0]["invocations"][0]
        assert "endTimeUtc" in invocation
        assert invocation["endTimeUtc"].endswith("Z")
