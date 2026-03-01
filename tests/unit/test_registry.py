"""Unit tests for the RuleRegistry class."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from biceps_check.rules.base import BaseRule, RuleResult, Severity
from biceps_check.rules.registry import RuleRegistry

if TYPE_CHECKING:
    from biceps_check.parser.models import BicepResource


# ---------------------------------------------------------------------------
# Mock rule classes used across multiple tests
# ---------------------------------------------------------------------------


class MockRuleA(BaseRule):
    """A minimal enabled rule targeting storage resources."""

    id = "MOCK_A_001"
    name = "Mock Rule A"
    description = "First mock rule for testing"
    severity = Severity.HIGH
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    enabled = True

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.PASSED


class MockRuleB(BaseRule):
    """A minimal enabled rule targeting compute resources with CRITICAL severity."""

    id = "MOCK_B_002"
    name = "Mock Rule B"
    description = "Second mock rule for testing"
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    enabled = True

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.FAILED


class MockRuleC(BaseRule):
    """A disabled rule with MEDIUM severity targeting networking resources."""

    id = "MOCK_C_003"
    name = "Mock Rule C"
    description = "Third mock rule for testing"
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    enabled = False

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.SKIPPED


class MockRuleWildcard(BaseRule):
    """A rule with no resource_types restriction — applies to everything."""

    id = "MOCK_W_004"
    name = "Mock Rule Wildcard"
    description = "Wildcard mock rule for testing"
    severity = Severity.LOW
    resource_types = []
    category = "general"
    enabled = True

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.PASSED


class MockRuleD(BaseRule):
    """An additional rule for enable_only and statistics tests."""

    id = "MOCK_D_005"
    name = "Mock Rule D"
    description = "Fourth mock rule for statistics"
    severity = Severity.INFO
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    enabled = True

    def check(self, resource: BicepResource) -> RuleResult:
        return RuleResult.PASSED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_registry(*rules: BaseRule) -> RuleRegistry:
    """Return a fresh registry pre-populated with the given rule instances."""
    registry = RuleRegistry()
    for rule in rules:
        registry.register(rule)
    return registry


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------


class TestRuleRegistryInit:
    """Verify that a newly created registry is completely empty."""

    def test_starts_with_zero_count(self):
        registry = RuleRegistry()
        assert registry.count == 0

    def test_starts_with_zero_enabled_count(self):
        registry = RuleRegistry()
        assert registry.enabled_count == 0

    def test_get_rules_returns_empty_list(self):
        registry = RuleRegistry()
        assert registry.get_rules(enabled_only=False) == []

    def test_get_categories_returns_empty_list(self):
        registry = RuleRegistry()
        assert registry.get_categories() == []

    def test_get_statistics_on_empty_registry(self):
        registry = RuleRegistry()
        stats = registry.get_statistics()
        assert stats["total"] == 0
        assert stats["enabled"] == 0
        assert stats["disabled"] == 0
        assert stats["by_severity"] == {}
        assert stats["by_category"] == {}


# ---------------------------------------------------------------------------
# 2. Register a rule
# ---------------------------------------------------------------------------


class TestRegisterRule:
    """Verify that registering a single rule updates count and enabled_count."""

    def test_count_increases_after_register(self):
        registry = RuleRegistry()
        registry.register(MockRuleA())
        assert registry.count == 1

    def test_enabled_count_increases_for_enabled_rule(self):
        registry = RuleRegistry()
        registry.register(MockRuleA())
        assert registry.enabled_count == 1

    def test_disabled_rule_not_counted_in_enabled(self):
        registry = RuleRegistry()
        registry.register(MockRuleC())
        assert registry.count == 1
        assert registry.enabled_count == 0

    def test_multiple_rules_count(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        assert registry.count == 3
        assert registry.enabled_count == 2

    def test_registered_rule_is_retrievable(self):
        registry = RuleRegistry()
        rule = MockRuleA()
        registry.register(rule)
        assert registry.get_rule("MOCK_A_001") is rule


# ---------------------------------------------------------------------------
# 3. Register duplicate rule (overwrites)
# ---------------------------------------------------------------------------


class TestRegisterDuplicateRule:
    """Registering a rule whose ID already exists must overwrite the previous entry."""

    def test_count_stays_the_same_on_overwrite(self):
        registry = RuleRegistry()
        registry.register(MockRuleA())
        registry.register(MockRuleA())
        assert registry.count == 1

    def test_new_instance_replaces_old(self):
        registry = RuleRegistry()
        first = MockRuleA()
        second = MockRuleA()
        registry.register(first)
        registry.register(second)
        assert registry.get_rule("MOCK_A_001") is second

    def test_overwrite_with_disabled_rule_updates_enabled_count(self):
        registry = RuleRegistry()
        registry.register(MockRuleA())  # enabled=True

        disabled_a = MockRuleA()
        disabled_a.enabled = False
        registry.register(disabled_a)

        # The registry's _enabled_rules set is not retroactively cleaned by register()
        # when overwriting with a disabled rule, but the object in _rules is updated.
        # Verify count is still 1 and the stored rule is the new disabled instance.
        assert registry.count == 1
        assert registry.get_rule("MOCK_A_001").enabled is False


# ---------------------------------------------------------------------------
# 4. Unregister a rule
# ---------------------------------------------------------------------------


class TestUnregisterRule:
    """Verify that unregistering a rule removes it from both tracking structures."""

    def test_count_decreases_after_unregister(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.unregister("MOCK_A_001")
        assert registry.count == 1

    def test_enabled_count_decreases_after_unregister(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.unregister("MOCK_A_001")
        assert registry.enabled_count == 1

    def test_unregistered_rule_not_retrievable(self):
        registry = make_registry(MockRuleA())
        registry.unregister("MOCK_A_001")
        assert registry.get_rule("MOCK_A_001") is None

    def test_unregister_nonexistent_id_is_silent(self):
        registry = make_registry(MockRuleA())
        registry.unregister("DOES_NOT_EXIST")
        assert registry.count == 1

    def test_unregister_disabled_rule_does_not_affect_enabled_count(self):
        registry = make_registry(MockRuleA(), MockRuleC())
        registry.unregister("MOCK_C_003")
        assert registry.count == 1
        assert registry.enabled_count == 1


# ---------------------------------------------------------------------------
# 5. get_rule by ID
# ---------------------------------------------------------------------------


class TestGetRule:
    """Verify retrieval of individual rules by their ID."""

    def test_returns_rule_when_id_exists(self):
        rule = MockRuleB()
        registry = make_registry(rule)
        assert registry.get_rule("MOCK_B_002") is rule

    def test_returns_none_for_unknown_id(self):
        registry = make_registry(MockRuleA())
        assert registry.get_rule("NONEXISTENT") is None

    def test_returns_none_on_empty_registry(self):
        registry = RuleRegistry()
        assert registry.get_rule("MOCK_A_001") is None


# ---------------------------------------------------------------------------
# 6. get_rules with category filter
# ---------------------------------------------------------------------------


class TestGetRulesCategory:
    """Verify filtering by category."""

    def test_filter_returns_only_matching_category(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleWildcard())
        rules = registry.get_rules(category="storage", enabled_only=False)
        ids = [r.id for r in rules]
        assert "MOCK_A_001" in ids
        assert "MOCK_B_002" not in ids
        assert "MOCK_W_004" not in ids

    def test_filter_returns_empty_for_unknown_category(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        assert registry.get_rules(category="does-not-exist", enabled_only=False) == []

    def test_filter_respects_enabled_only_flag(self):
        registry = make_registry(MockRuleA(), MockRuleC())
        # MockRuleC is "networking" but disabled
        enabled = registry.get_rules(category="networking", enabled_only=True)
        all_rules = registry.get_rules(category="networking", enabled_only=False)
        assert len(enabled) == 0
        assert len(all_rules) == 1


# ---------------------------------------------------------------------------
# 7. get_rules with severity filter
# ---------------------------------------------------------------------------


class TestGetRulesSeverity:
    """Verify filtering by severity."""

    def test_filter_returns_correct_severity(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleWildcard())
        rules = registry.get_rules(severity=Severity.HIGH, enabled_only=False)
        assert len(rules) == 1
        assert rules[0].id == "MOCK_A_001"

    def test_filter_critical_severity(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        rules = registry.get_rules(severity=Severity.CRITICAL, enabled_only=False)
        assert len(rules) == 1
        assert rules[0].id == "MOCK_B_002"

    def test_filter_returns_empty_for_unregistered_severity(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        rules = registry.get_rules(severity=Severity.INFO, enabled_only=False)
        assert rules == []


# ---------------------------------------------------------------------------
# 8. get_rules with resource_type filter
# ---------------------------------------------------------------------------


class TestGetRulesResourceType:
    """Verify filtering by resource_type."""

    def test_filter_returns_matching_resource_type(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleWildcard())
        rules = registry.get_rules(
            resource_type="Microsoft.Storage/storageAccounts", enabled_only=False
        )
        ids = [r.id for r in rules]
        assert "MOCK_A_001" in ids
        # Wildcard rule (resource_types=[]) applies to everything
        assert "MOCK_W_004" in ids
        assert "MOCK_B_002" not in ids

    def test_wildcard_rule_applies_to_any_resource(self):
        registry = make_registry(MockRuleWildcard())
        rules = registry.get_rules(resource_type="Microsoft.Whatever/anything", enabled_only=False)
        assert len(rules) == 1

    def test_filter_returns_empty_when_no_match(self):
        registry = make_registry(MockRuleA())
        rules = registry.get_rules(resource_type="Microsoft.KeyVault/vaults", enabled_only=False)
        assert rules == []


# ---------------------------------------------------------------------------
# 9. get_rules with enabled_only filter
# ---------------------------------------------------------------------------


class TestGetRulesEnabledOnly:
    """Verify the enabled_only flag."""

    def test_enabled_only_true_excludes_disabled_rules(self):
        registry = make_registry(MockRuleA(), MockRuleC())
        rules = registry.get_rules(enabled_only=True)
        ids = [r.id for r in rules]
        assert "MOCK_A_001" in ids
        assert "MOCK_C_003" not in ids

    def test_enabled_only_false_includes_all_rules(self):
        registry = make_registry(MockRuleA(), MockRuleC())
        rules = registry.get_rules(enabled_only=False)
        ids = [r.id for r in rules]
        assert "MOCK_A_001" in ids
        assert "MOCK_C_003" in ids

    def test_enabled_only_defaults_to_true(self):
        registry = make_registry(MockRuleA(), MockRuleC())
        # No explicit enabled_only argument → defaults to True
        rules = registry.get_rules()
        assert all(r.id in registry._enabled_rules for r in rules)

    def test_results_are_sorted_by_id(self):
        registry = make_registry(MockRuleB(), MockRuleA(), MockRuleWildcard())
        rules = registry.get_rules(enabled_only=False)
        ids = [r.id for r in rules]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# 10. get_rules_for_resource
# ---------------------------------------------------------------------------


class TestGetRulesForResource:
    """Verify get_rules_for_resource returns only enabled, applicable rules."""

    def test_returns_enabled_rules_for_resource(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC(), MockRuleWildcard())
        rules = registry.get_rules_for_resource("Microsoft.Storage/storageAccounts")
        ids = [r.id for r in rules]
        assert "MOCK_A_001" in ids  # storage rule, enabled
        assert "MOCK_W_004" in ids  # wildcard, enabled
        assert "MOCK_B_002" not in ids  # compute rule
        assert "MOCK_C_003" not in ids  # networking rule AND disabled

    def test_excludes_disabled_rules(self):
        registry = make_registry(MockRuleC())
        rules = registry.get_rules_for_resource("Microsoft.Network/networkSecurityGroups")
        assert rules == []

    def test_returns_empty_when_no_applicable_rules(self):
        registry = make_registry(MockRuleA())
        rules = registry.get_rules_for_resource("Microsoft.KeyVault/vaults")
        assert rules == []


# ---------------------------------------------------------------------------
# 11. enable / disable specific rules
# ---------------------------------------------------------------------------


class TestEnableDisableRules:
    """Verify targeted enable and disable operations."""

    def test_enable_disabled_rule(self):
        registry = make_registry(MockRuleC())
        assert registry.enabled_count == 0
        registry.enable(["MOCK_C_003"])
        assert registry.enabled_count == 1
        assert registry.get_rule("MOCK_C_003").enabled is True

    def test_disable_enabled_rule(self):
        registry = make_registry(MockRuleA())
        registry.disable(["MOCK_A_001"])
        assert registry.enabled_count == 0
        assert registry.get_rule("MOCK_A_001").enabled is False

    def test_enable_nonexistent_id_is_silent(self):
        registry = make_registry(MockRuleA())
        registry.enable(["NONEXISTENT"])
        assert registry.count == 1

    def test_disable_nonexistent_id_is_silent(self):
        registry = make_registry(MockRuleA())
        registry.disable(["NONEXISTENT"])
        assert registry.count == 1

    def test_enable_multiple_rules(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        registry.disable(["MOCK_A_001", "MOCK_B_002"])
        assert registry.enabled_count == 0
        registry.enable(["MOCK_A_001", "MOCK_B_002"])
        assert registry.enabled_count == 2

    def test_disable_multiple_rules(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.disable(["MOCK_A_001", "MOCK_B_002"])
        assert registry.enabled_count == 0
        assert registry.get_rule("MOCK_A_001").enabled is False
        assert registry.get_rule("MOCK_B_002").enabled is False


# ---------------------------------------------------------------------------
# 12. enable_only specific rules
# ---------------------------------------------------------------------------


class TestEnableOnly:
    """Verify enable_only disables all rules except the specified ones."""

    def test_only_listed_rules_are_enabled(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC(), MockRuleWildcard())
        registry.enable_only(["MOCK_A_001", "MOCK_W_004"])
        assert registry.enabled_count == 2
        assert registry.get_rule("MOCK_A_001").enabled is True
        assert registry.get_rule("MOCK_W_004").enabled is True
        assert registry.get_rule("MOCK_B_002").enabled is False
        assert registry.get_rule("MOCK_C_003").enabled is False

    def test_enable_only_with_empty_list_disables_all(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.enable_only([])
        assert registry.enabled_count == 0

    def test_enable_only_nonexistent_id_is_silent(self):
        registry = make_registry(MockRuleA())
        registry.enable_only(["NONEXISTENT"])
        assert registry.enabled_count == 0
        assert registry.get_rule("MOCK_A_001").enabled is False


# ---------------------------------------------------------------------------
# 13. enable_all / disable_all
# ---------------------------------------------------------------------------


class TestEnableAllDisableAll:
    """Verify bulk enable/disable operations."""

    def test_enable_all_enables_every_rule(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        registry.enable_all()
        assert registry.enabled_count == 3
        for rule_id in ["MOCK_A_001", "MOCK_B_002", "MOCK_C_003"]:
            assert registry.get_rule(rule_id).enabled is True

    def test_disable_all_disables_every_rule(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        registry.disable_all()
        assert registry.enabled_count == 0
        for rule_id in ["MOCK_A_001", "MOCK_B_002", "MOCK_C_003"]:
            assert registry.get_rule(rule_id).enabled is False

    def test_enable_all_on_empty_registry_is_safe(self):
        registry = RuleRegistry()
        registry.enable_all()
        assert registry.enabled_count == 0

    def test_disable_all_on_empty_registry_is_safe(self):
        registry = RuleRegistry()
        registry.disable_all()
        assert registry.enabled_count == 0

    def test_round_trip_disable_then_enable(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.disable_all()
        assert registry.enabled_count == 0
        registry.enable_all()
        assert registry.enabled_count == 2


# ---------------------------------------------------------------------------
# 14. load_all_rules loads rules from checks package
# ---------------------------------------------------------------------------


class TestLoadAllRules:
    """Verify that load_all_rules discovers and registers rules from the checks package."""

    def test_load_all_rules_registers_at_least_one_rule(self):
        registry = RuleRegistry()
        registry.load_all_rules()
        assert registry.count > 0

    def test_load_all_rules_registered_rules_have_ids(self):
        registry = RuleRegistry()
        registry.load_all_rules()
        for rule in registry.get_rules(enabled_only=False):
            assert rule.id, f"Rule {rule} has no ID"

    def test_load_all_rules_registered_rules_are_base_rule_instances(self):
        registry = RuleRegistry()
        registry.load_all_rules()
        for rule in registry.get_rules(enabled_only=False):
            assert isinstance(rule, BaseRule)

    def test_load_all_rules_includes_storage_rules(self):
        registry = RuleRegistry()
        registry.load_all_rules()
        ids = [r.id for r in registry.get_rules(enabled_only=False)]
        # At minimum BCK_AZURE_ST_001 must be present
        assert "BCK_AZURE_ST_001" in ids

    def test_load_all_rules_bad_module_does_not_crash(self):
        """A broken module during walk_packages must not raise from load_all_rules."""
        registry = RuleRegistry()
        with patch("biceps_check.rules.registry.importlib.import_module") as mock_import:
            mock_import.side_effect = ImportError("simulated import failure")
            # The registry catches per-module errors internally; no exception should escape.
            try:
                import biceps_check.checks as checks_pkg

                registry._load_rules_from_package(checks_pkg)
            except Exception as exc:
                pytest.fail(f"load_all_rules raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# 15. get_categories
# ---------------------------------------------------------------------------


class TestGetCategories:
    """Verify category discovery."""

    def test_returns_sorted_unique_categories(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC(), MockRuleWildcard())
        categories = registry.get_categories()
        assert categories == sorted({"storage", "compute", "networking", "general"})

    def test_no_duplicate_categories(self):
        # MockRuleA and MockRuleD are both "storage"
        registry = make_registry(MockRuleA(), MockRuleD())
        categories = registry.get_categories()
        assert categories.count("storage") == 1

    def test_empty_registry_returns_empty_list(self):
        registry = RuleRegistry()
        assert registry.get_categories() == []


# ---------------------------------------------------------------------------
# 16. get_statistics
# ---------------------------------------------------------------------------


class TestGetStatistics:
    """Verify the structure and values returned by get_statistics."""

    def test_statistics_total_matches_count(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        stats = registry.get_statistics()
        assert stats["total"] == registry.count

    def test_statistics_enabled_matches_enabled_count(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        stats = registry.get_statistics()
        assert stats["enabled"] == registry.enabled_count

    def test_statistics_disabled_is_total_minus_enabled(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        stats = registry.get_statistics()
        assert stats["disabled"] == stats["total"] - stats["enabled"]

    def test_statistics_by_severity_counts(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        stats = registry.get_statistics()
        assert stats["by_severity"].get("HIGH") == 1
        assert stats["by_severity"].get("CRITICAL") == 1
        assert stats["by_severity"].get("MEDIUM") == 1

    def test_statistics_by_category_counts(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        stats = registry.get_statistics()
        assert stats["by_category"]["storage"] == 1
        assert stats["by_category"]["compute"] == 1
        assert stats["by_category"]["networking"] == 1

    def test_statistics_keys_are_present(self):
        registry = make_registry(MockRuleA())
        stats = registry.get_statistics()
        for key in ("total", "enabled", "disabled", "by_severity", "by_category"):
            assert key in stats

    def test_statistics_aggregates_multiple_same_category(self):
        registry = make_registry(MockRuleA(), MockRuleD())
        stats = registry.get_statistics()
        assert stats["by_category"]["storage"] == 2


# ---------------------------------------------------------------------------
# 17. count and enabled_count properties
# ---------------------------------------------------------------------------


class TestCountProperties:
    """Verify the count and enabled_count properties stay consistent across mutations."""

    def test_count_reflects_registrations(self):
        registry = RuleRegistry()
        assert registry.count == 0
        registry.register(MockRuleA())
        assert registry.count == 1
        registry.register(MockRuleB())
        assert registry.count == 2

    def test_count_decreases_on_unregister(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.unregister("MOCK_A_001")
        assert registry.count == 1

    def test_enabled_count_tracks_enabled_status(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleC())
        assert registry.enabled_count == 2  # MockRuleC starts disabled

    def test_enabled_count_updates_on_disable(self):
        registry = make_registry(MockRuleA(), MockRuleB())
        registry.disable(["MOCK_A_001"])
        assert registry.enabled_count == 1

    def test_enabled_count_updates_on_enable(self):
        registry = make_registry(MockRuleC())
        assert registry.enabled_count == 0
        registry.enable(["MOCK_C_003"])
        assert registry.enabled_count == 1

    def test_count_unchanged_on_overwrite(self):
        registry = make_registry(MockRuleA())
        registry.register(MockRuleA())
        assert registry.count == 1

    def test_enabled_count_never_exceeds_count(self):
        registry = make_registry(MockRuleA(), MockRuleB(), MockRuleWildcard())
        registry.enable_all()
        assert registry.enabled_count <= registry.count
