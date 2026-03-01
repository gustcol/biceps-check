"""Unit tests for BicepsCheckRunner and ScanResults."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from biceps_check.config import BicepsCheckConfig, ChecksConfig, SuppressionConfig
from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, CheckResult, RuleResult, Severity
from biceps_check.runner import BicepsCheckRunner, ScanResults

# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


def _make_resource(
    name: str = "testResource",
    resource_type: str = "Microsoft.Storage/storageAccounts",
    suppressions: list[str] | None = None,
    line_number: int = 1,
) -> BicepResource:
    """Return a minimal BicepResource for use in tests."""
    return BicepResource(
        name=name,
        resource_type=resource_type,
        api_version="2023-01-01",
        properties={},
        line_number=line_number,
        suppressions=suppressions or [],
    )


def _make_check_result(
    result: RuleResult = RuleResult.PASSED,
    severity: Severity = Severity.MEDIUM,
    rule_id: str = "TEST_RULE_001",
    resource_name: str = "testResource",
    file_path: Path | None = None,
) -> CheckResult:
    """Return a minimal CheckResult for use in tests."""
    return CheckResult(
        rule_id=rule_id,
        rule_name="Test Rule",
        result=result,
        severity=severity,
        resource_name=resource_name,
        resource_type="Microsoft.Storage/storageAccounts",
        file_path=file_path or Path("test.bicep"),
        line_number=1,
        message="Test message" if result == RuleResult.FAILED else None,
    )


class _PassingRule(BaseRule):
    """Stub rule that always passes."""

    id = "TEST_PASS_001"
    name = "Always Pass"
    description = "A rule that always passes."
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "test"
    remediation = "No remediation needed."

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.PASSED


class _FailingRule(BaseRule):
    """Stub rule that always fails."""

    id = "TEST_FAIL_001"
    name = "Always Fail"
    description = "A rule that always fails."
    severity = Severity.HIGH
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "test"
    remediation = "Fix the issue."

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.FAILED

    def get_message(self, resource: BicepResource) -> str:
        return f"Resource {resource.name} failed the check."


class _ExplodingRule(BaseRule):
    """Stub rule whose check() raises an exception."""

    id = "TEST_EXPLODE_001"
    name = "Always Explode"
    description = "A rule that raises an exception."
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "test"
    remediation = ""

    def check(self, resource: BicepResource) -> RuleResult:
        raise RuntimeError("Unexpected error during check")


# ---------------------------------------------------------------------------
# Minimal valid Bicep content used across tests
# ---------------------------------------------------------------------------

VALID_BICEP_CONTENT = """\
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'teststorage'
  location: 'eastus'
  properties: {
    supportsHttpsTrafficOnly: true
  }
}
"""

EMPTY_BICEP_CONTENT = """\
// No resources defined here
param location string = 'eastus'
"""


# ---------------------------------------------------------------------------
# ScanResults tests
# ---------------------------------------------------------------------------


class TestScanResults:
    """Tests for the ScanResults dataclass."""

    def test_default_initialization(self):
        """ScanResults should start with zeroed counters and empty lists."""
        results = ScanResults()

        assert results.files_scanned == 0
        assert results.resources_scanned == 0
        assert results.passed_checks == []
        assert results.failed_checks == []
        assert results.skipped_checks == []
        assert results.errors == []

    def test_total_checks_empty(self):
        """total_checks should be 0 when no results have been added."""
        results = ScanResults()
        assert results.total_checks == 0

    def test_add_result_passed(self):
        """add_result should route PASSED results to passed_checks."""
        results = ScanResults()
        check = _make_check_result(result=RuleResult.PASSED)

        results.add_result(check)

        assert len(results.passed_checks) == 1
        assert results.passed_checks[0] is check
        assert results.failed_checks == []
        assert results.skipped_checks == []

    def test_add_result_failed(self):
        """add_result should route FAILED results to failed_checks."""
        results = ScanResults()
        check = _make_check_result(result=RuleResult.FAILED)

        results.add_result(check)

        assert len(results.failed_checks) == 1
        assert results.failed_checks[0] is check
        assert results.passed_checks == []
        assert results.skipped_checks == []

    def test_add_result_skipped(self):
        """add_result should route SKIPPED results to skipped_checks."""
        results = ScanResults()
        check = _make_check_result(result=RuleResult.SKIPPED)

        results.add_result(check)

        assert len(results.skipped_checks) == 1
        assert results.skipped_checks[0] is check
        assert results.passed_checks == []
        assert results.failed_checks == []

    def test_total_checks_reflects_all_lists(self):
        """total_checks should be the sum across all three result lists."""
        results = ScanResults()
        results.add_result(_make_check_result(result=RuleResult.PASSED))
        results.add_result(_make_check_result(result=RuleResult.PASSED))
        results.add_result(_make_check_result(result=RuleResult.FAILED))
        results.add_result(_make_check_result(result=RuleResult.SKIPPED))

        assert results.total_checks == 4
        assert results.passed_count == 2
        assert results.failed_count == 1
        assert results.skipped_count == 1

    def test_properties_are_counts(self):
        """passed_count, failed_count, and skipped_count mirror list lengths."""
        results = ScanResults()
        results.passed_checks.append(_make_check_result(RuleResult.PASSED))
        results.failed_checks.append(_make_check_result(RuleResult.FAILED))
        results.failed_checks.append(_make_check_result(RuleResult.FAILED))

        assert results.passed_count == 1
        assert results.failed_count == 2
        assert results.skipped_count == 0
        assert results.total_checks == 3

    def test_merge_accumulates_files_and_resources(self):
        """merge should sum numeric counters from both ScanResults instances."""
        a = ScanResults(files_scanned=2, resources_scanned=5)
        b = ScanResults(files_scanned=3, resources_scanned=7)

        a.merge(b)

        assert a.files_scanned == 5
        assert a.resources_scanned == 12

    def test_merge_extends_check_lists(self):
        """merge should append every check list from the other instance."""
        a = ScanResults()
        a.add_result(_make_check_result(RuleResult.PASSED))

        b = ScanResults()
        b.add_result(_make_check_result(RuleResult.FAILED))
        b.add_result(_make_check_result(RuleResult.SKIPPED))

        a.merge(b)

        assert a.passed_count == 1
        assert a.failed_count == 1
        assert a.skipped_count == 1
        assert a.total_checks == 3

    def test_merge_extends_errors(self):
        """merge should append error messages from the other instance."""
        a = ScanResults()
        a.errors.append("error in file A")

        b = ScanResults()
        b.errors.append("error in file B")

        a.merge(b)

        assert len(a.errors) == 2
        assert "error in file A" in a.errors
        assert "error in file B" in a.errors

    def test_merge_with_empty_other(self):
        """Merging with an empty ScanResults should not change the target."""
        a = ScanResults(files_scanned=1, resources_scanned=3)
        a.add_result(_make_check_result(RuleResult.PASSED))

        a.merge(ScanResults())

        assert a.files_scanned == 1
        assert a.resources_scanned == 3
        assert a.total_checks == 1


# ---------------------------------------------------------------------------
# BicepsCheckRunner initialisation tests
# ---------------------------------------------------------------------------


class TestBicepsCheckRunnerInit:
    """Tests for BicepsCheckRunner construction."""

    def test_init_with_default_config(self):
        """Runner created without arguments should use a default BicepsCheckConfig."""
        runner = BicepsCheckRunner()

        assert isinstance(runner.config, BicepsCheckConfig)
        assert runner.config.min_severity == Severity.INFO

    def test_init_with_custom_config(self):
        """Runner created with a custom config should preserve it."""
        custom_config = BicepsCheckConfig(min_severity=Severity.HIGH)
        runner = BicepsCheckRunner(config=custom_config)

        assert runner.config is custom_config
        assert runner.config.min_severity == Severity.HIGH

    def test_init_creates_parser(self):
        """Runner should expose a BicepParser instance after construction."""
        from biceps_check.parser.bicep_parser import BicepParser

        runner = BicepsCheckRunner()
        assert isinstance(runner.parser, BicepParser)

    def test_init_creates_registry(self):
        """Runner should expose a RuleRegistry instance after construction."""
        from biceps_check.rules.registry import RuleRegistry

        runner = BicepsCheckRunner()
        assert isinstance(runner.registry, RuleRegistry)

    def test_init_loads_rules(self):
        """Rules should be loaded into the registry during construction."""
        runner = BicepsCheckRunner()
        assert runner.registry.count > 0

    def test_init_with_skip_checks_config(self):
        """Rules listed in config.checks.skip should be disabled after init."""
        # Find a real rule ID that will be loaded so we can skip it.
        probe_runner = BicepsCheckRunner()
        all_rules = probe_runner.registry.get_rules(enabled_only=False)
        if not all_rules:
            pytest.skip("No rules loaded; cannot test skip configuration.")

        target_rule_id = all_rules[0].id
        config = BicepsCheckConfig(checks=ChecksConfig(skip=[target_rule_id]))
        runner = BicepsCheckRunner(config=config)

        assert target_rule_id not in runner.registry._enabled_rules

    def test_init_with_enable_only_config(self):
        """Only rules listed in config.checks.enable should remain enabled."""
        probe_runner = BicepsCheckRunner()
        all_rules = probe_runner.registry.get_rules(enabled_only=False)
        if len(all_rules) < 2:
            pytest.skip("Need at least 2 rules to test enable_only.")

        target_rule_id = all_rules[0].id
        config = BicepsCheckConfig(checks=ChecksConfig(enable=[target_rule_id]))
        runner = BicepsCheckRunner(config=config)

        assert runner.registry.enabled_count == 1
        assert target_rule_id in runner.registry._enabled_rules


# ---------------------------------------------------------------------------
# scan_file tests
# ---------------------------------------------------------------------------


class TestScanFile:
    """Tests for BicepsCheckRunner.scan_file."""

    def test_scan_valid_bicep_file_returns_scan_results(self):
        """scan_file should return a ScanResults for a valid Bicep file."""
        runner = BicepsCheckRunner()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as tmp:
            tmp.write(VALID_BICEP_CONTENT)
            tmp_path = Path(tmp.name)

        results = runner.scan_file(tmp_path)

        assert isinstance(results, ScanResults)
        assert results.files_scanned == 1

    def test_scan_valid_bicep_file_counts_resources(self):
        """scan_file should count the resources found in the file."""
        runner = BicepsCheckRunner()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as tmp:
            tmp.write(VALID_BICEP_CONTENT)
            tmp_path = Path(tmp.name)

        results = runner.scan_file(tmp_path)

        assert results.resources_scanned >= 1

    def test_scan_nonexistent_file_returns_error(self):
        """scan_file should record an error when the file does not exist."""
        runner = BicepsCheckRunner()
        missing = Path("nonexistent_dir/does_not_exist.bicep")

        results = runner.scan_file(missing)

        assert results.files_scanned == 1
        assert len(results.errors) == 1
        assert "does_not_exist.bicep" in results.errors[0]

    def test_scan_invalid_file_does_not_raise(self):
        """scan_file must not propagate exceptions; errors go into results.errors."""
        runner = BicepsCheckRunner()

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bicep", delete=False) as tmp:
            # Write invalid (binary noise) content that will fail parsing.
            tmp.write(b"\x00\xff\xfe malformed \x00")
            tmp_path = Path(tmp.name)

        results = runner.scan_file(tmp_path)

        # Should not raise; error may or may not be recorded depending on parser
        assert isinstance(results, ScanResults)
        assert results.files_scanned == 1

    def test_scan_empty_bicep_file_no_resources(self):
        """scan_file on a file with no resources should report zero resources."""
        runner = BicepsCheckRunner()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as tmp:
            tmp.write(EMPTY_BICEP_CONTENT)
            tmp_path = Path(tmp.name)

        results = runner.scan_file(tmp_path)

        assert results.resources_scanned == 0
        assert results.errors == []


# ---------------------------------------------------------------------------
# scan_directory tests
# ---------------------------------------------------------------------------


class TestScanDirectory:
    """Tests for BicepsCheckRunner.scan_directory."""

    def test_scan_directory_recursive_finds_nested_files(self):
        """With recursive=True the runner should descend into subdirectories."""
        runner = BicepsCheckRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subdir = root / "sub"
            subdir.mkdir()

            (root / "top.bicep").write_text(VALID_BICEP_CONTENT)
            (subdir / "nested.bicep").write_text(VALID_BICEP_CONTENT)

            results = runner.scan_directory(root, recursive=True)

        # Both files should be scanned (2 files, each with 1 resource).
        assert results.files_scanned == 2

    def test_scan_directory_non_recursive_ignores_subdirs(self):
        """With recursive=False the runner should only look at the top level."""
        runner = BicepsCheckRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subdir = root / "sub"
            subdir.mkdir()

            (root / "top.bicep").write_text(VALID_BICEP_CONTENT)
            (subdir / "nested.bicep").write_text(VALID_BICEP_CONTENT)

            results = runner.scan_directory(root, recursive=False)

        # Only the top-level file should be scanned.
        assert results.files_scanned == 1

    def test_scan_directory_no_bicep_files_returns_empty_results(self):
        """A directory with no .bicep files should yield zeroed ScanResults."""
        runner = BicepsCheckRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("# hello")

            results = runner.scan_directory(root)

        assert results.files_scanned == 0
        assert results.resources_scanned == 0
        assert results.total_checks == 0
        assert results.errors == []

    def test_scan_directory_merges_individual_results(self):
        """ScanResults from multiple files should be merged into one object."""
        runner = BicepsCheckRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "a.bicep").write_text(VALID_BICEP_CONTENT)
            (root / "b.bicep").write_text(VALID_BICEP_CONTENT)

            results = runner.scan_directory(root, recursive=False)

        assert results.files_scanned == 2


# ---------------------------------------------------------------------------
# _is_suppressed tests
# ---------------------------------------------------------------------------


class TestIsSuppressed:
    """Tests for BicepsCheckRunner._is_suppressed."""

    def test_not_suppressed_by_default(self):
        """A resource with no suppressions should not be suppressed."""
        runner = BicepsCheckRunner()
        resource = _make_resource()

        assert runner._is_suppressed("ANY_RULE_001", resource) is False

    def test_suppressed_by_inline_comment(self):
        """A resource with an inline suppression should be suppressed."""
        runner = BicepsCheckRunner()
        resource = _make_resource(suppressions=["BCK_AZURE_ST_001"])

        assert runner._is_suppressed("BCK_AZURE_ST_001", resource) is True

    def test_not_suppressed_for_different_rule_id(self):
        """Suppression of one rule must not suppress a different rule."""
        runner = BicepsCheckRunner()
        resource = _make_resource(suppressions=["BCK_AZURE_ST_001"])

        assert runner._is_suppressed("BCK_AZURE_ST_002", resource) is False

    def test_suppressed_by_config_level_global_suppression(self):
        """A config-level suppression with no resources list covers all resources."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", reason="Global suppression")
        config = BicepsCheckConfig(suppressions=[suppression])
        runner = BicepsCheckRunner(config=config)
        resource = _make_resource(name="anyResource")

        assert runner._is_suppressed("BCK_AZURE_ST_001", resource) is True

    def test_suppressed_by_config_level_targeted_suppression(self):
        """A config suppression that lists specific resources targets only them."""
        suppression = SuppressionConfig(
            id="BCK_AZURE_ST_001",
            reason="Only for legacyStorage",
            resources=["legacyStorage"],
        )
        config = BicepsCheckConfig(suppressions=[suppression])
        runner = BicepsCheckRunner(config=config)

        targeted = _make_resource(name="legacyStorage")
        other = _make_resource(name="newStorage")

        assert runner._is_suppressed("BCK_AZURE_ST_001", targeted) is True
        assert runner._is_suppressed("BCK_AZURE_ST_001", other) is False

    def test_config_suppression_does_not_cover_different_rule(self):
        """A config suppression for rule A must not suppress rule B."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", reason="Test")
        config = BicepsCheckConfig(suppressions=[suppression])
        runner = BicepsCheckRunner(config=config)
        resource = _make_resource()

        assert runner._is_suppressed("BCK_AZURE_KV_001", resource) is False


# ---------------------------------------------------------------------------
# _meets_severity_threshold tests
# ---------------------------------------------------------------------------


class TestMeetsSeverityThreshold:
    """Tests for BicepsCheckRunner._meets_severity_threshold."""

    def _runner_with_min_severity(self, min_severity: Severity) -> BicepsCheckRunner:
        config = BicepsCheckConfig(min_severity=min_severity)
        return BicepsCheckRunner(config=config)

    def test_result_at_threshold_is_included(self):
        """A result whose severity equals the threshold should be included."""
        runner = self._runner_with_min_severity(Severity.MEDIUM)
        check = _make_check_result(severity=Severity.MEDIUM)

        assert runner._meets_severity_threshold(check) is True

    def test_result_above_threshold_is_included(self):
        """A result whose severity is higher than the threshold should be included."""
        runner = self._runner_with_min_severity(Severity.MEDIUM)
        check = _make_check_result(severity=Severity.HIGH)

        assert runner._meets_severity_threshold(check) is True

    def test_result_below_threshold_is_excluded(self):
        """A result whose severity is lower than the threshold should be excluded."""
        runner = self._runner_with_min_severity(Severity.HIGH)
        check = _make_check_result(severity=Severity.MEDIUM)

        assert runner._meets_severity_threshold(check) is False

    def test_info_threshold_includes_all_severities(self):
        """With threshold INFO every severity level should pass."""
        runner = self._runner_with_min_severity(Severity.INFO)

        for severity in Severity:
            check = _make_check_result(severity=severity)
            assert runner._meets_severity_threshold(check) is True, (
                f"Expected {severity} to pass INFO threshold"
            )

    def test_critical_threshold_excludes_lower_severities(self):
        """With threshold CRITICAL only CRITICAL results should pass."""
        runner = self._runner_with_min_severity(Severity.CRITICAL)

        for severity in [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]:
            check = _make_check_result(severity=severity)
            assert runner._meets_severity_threshold(check) is False, (
                f"Expected {severity} to fail CRITICAL threshold"
            )

        critical_check = _make_check_result(severity=Severity.CRITICAL)
        assert runner._meets_severity_threshold(critical_check) is True


# ---------------------------------------------------------------------------
# _run_check tests
# ---------------------------------------------------------------------------


class TestRunCheck:
    """Tests for BicepsCheckRunner._run_check."""

    def test_run_check_passing_rule_returns_passed_result(self):
        """_run_check should return a PASSED CheckResult for a passing rule."""
        runner = BicepsCheckRunner()
        rule = _PassingRule()
        resource = _make_resource()
        file_path = Path("test.bicep")

        result = runner._run_check(rule, resource, file_path)

        assert result is not None
        assert result.result == RuleResult.PASSED
        assert result.rule_id == rule.id
        assert result.resource_name == resource.name
        assert result.file_path == file_path

    def test_run_check_failing_rule_returns_failed_result_with_message(self):
        """_run_check should return a FAILED CheckResult including a message."""
        runner = BicepsCheckRunner()
        rule = _FailingRule()
        resource = _make_resource()
        file_path = Path("test.bicep")

        result = runner._run_check(rule, resource, file_path)

        assert result is not None
        assert result.result == RuleResult.FAILED
        assert result.message is not None
        assert resource.name in result.message
        assert result.remediation == rule.remediation

    def test_run_check_failing_rule_sets_remediation(self):
        """_run_check on a failing rule should populate the remediation field."""
        runner = BicepsCheckRunner()
        rule = _FailingRule()

        result = runner._run_check(rule, _make_resource(), Path("test.bicep"))

        assert result is not None
        assert result.remediation == rule.remediation

    def test_run_check_passed_rule_has_no_message(self):
        """A passing check should not include a failure message."""
        runner = BicepsCheckRunner()
        rule = _PassingRule()

        result = runner._run_check(rule, _make_resource(), Path("test.bicep"))

        assert result is not None
        assert result.result == RuleResult.PASSED
        assert result.message is None

    def test_run_check_exception_in_rule_returns_none(self):
        """When rule.check() raises an exception _run_check should return None."""
        runner = BicepsCheckRunner()
        rule = _ExplodingRule()
        resource = _make_resource()

        result = runner._run_check(rule, resource, Path("test.bicep"))

        assert result is None

    def test_run_check_suppressed_resource_returns_skipped(self):
        """_run_check should return SKIPPED for a resource with an inline suppression."""
        rule = _FailingRule()
        resource = _make_resource(suppressions=[rule.id])
        runner = BicepsCheckRunner()

        result = runner._run_check(rule, resource, Path("test.bicep"))

        assert result is not None
        assert result.result == RuleResult.SKIPPED
        assert "Suppressed" in result.message

    def test_run_check_records_line_number(self):
        """CheckResult should carry the resource's original line number."""
        runner = BicepsCheckRunner()
        rule = _PassingRule()
        resource = _make_resource(line_number=42)

        result = runner._run_check(rule, resource, Path("test.bicep"))

        assert result is not None
        assert result.line_number == 42

    def test_run_check_records_severity_from_rule(self):
        """CheckResult severity should match the rule's defined severity."""
        runner = BicepsCheckRunner()
        rule = _FailingRule()  # severity = HIGH

        result = runner._run_check(rule, _make_resource(), Path("test.bicep"))

        assert result is not None
        assert result.severity == Severity.HIGH
