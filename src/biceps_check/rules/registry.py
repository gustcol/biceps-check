"""
Rule registry for managing security rules.

This module provides a centralized registry for discovering, loading,
and managing security rules.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Any, Optional

import structlog

from biceps_check.rules.base import BaseRule, Severity

logger = structlog.get_logger()


class RuleRegistry:
    """Registry for managing security rules.

    The registry handles rule discovery, loading, filtering, and retrieval.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._rules: dict[str, BaseRule] = {}
        self._enabled_rules: set[str] = set()

    @property
    def count(self) -> int:
        """Total number of registered rules."""
        return len(self._rules)

    @property
    def enabled_count(self) -> int:
        """Number of enabled rules."""
        return len(self._enabled_rules)

    def register(self, rule: BaseRule) -> None:
        """Register a rule in the registry.

        Args:
            rule: The rule instance to register.
        """
        if rule.id in self._rules:
            logger.warning("Rule already registered, overwriting", rule_id=rule.id)

        self._rules[rule.id] = rule
        if rule.enabled:
            self._enabled_rules.add(rule.id)

        logger.debug("Rule registered", rule_id=rule.id, name=rule.name)

    def unregister(self, rule_id: str) -> None:
        """Remove a rule from the registry.

        Args:
            rule_id: The ID of the rule to remove.
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            self._enabled_rules.discard(rule_id)

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Get a rule by its ID.

        Args:
            rule_id: The rule ID to look up.

        Returns:
            The rule instance, or None if not found.
        """
        return self._rules.get(rule_id)

    def get_rules(
        self,
        category: Optional[str] = None,
        severity: Optional[Severity] = None,
        resource_type: Optional[str] = None,
        enabled_only: bool = True,
    ) -> list[BaseRule]:
        """Get rules matching the specified criteria.

        Args:
            category: Filter by category.
            severity: Filter by severity.
            resource_type: Filter by resource type.
            enabled_only: Only return enabled rules.

        Returns:
            List of matching rules.
        """
        rules = []

        for rule_id, rule in self._rules.items():
            if enabled_only and rule_id not in self._enabled_rules:
                continue
            if category and rule.category != category:
                continue
            if severity and rule.severity != severity:
                continue
            if resource_type and not rule.applies_to(resource_type):
                continue
            rules.append(rule)

        return sorted(rules, key=lambda r: r.id)

    def get_rules_for_resource(self, resource_type: str) -> list[BaseRule]:
        """Get all enabled rules that apply to a resource type.

        Args:
            resource_type: The Azure resource type.

        Returns:
            List of applicable rules.
        """
        return self.get_rules(resource_type=resource_type, enabled_only=True)

    def enable(self, rule_ids: list[str]) -> None:
        """Enable specific rules.

        Args:
            rule_ids: List of rule IDs to enable.
        """
        for rule_id in rule_ids:
            if rule_id in self._rules:
                self._enabled_rules.add(rule_id)
                self._rules[rule_id].enabled = True

    def disable(self, rule_ids: list[str]) -> None:
        """Disable specific rules.

        Args:
            rule_ids: List of rule IDs to disable.
        """
        for rule_id in rule_ids:
            self._enabled_rules.discard(rule_id)
            if rule_id in self._rules:
                self._rules[rule_id].enabled = False

    def enable_only(self, rule_ids: list[str]) -> None:
        """Enable only the specified rules, disabling all others.

        Args:
            rule_ids: List of rule IDs to enable.
        """
        self._enabled_rules = set()
        for rule_id in rule_ids:
            if rule_id in self._rules:
                self._enabled_rules.add(rule_id)
                self._rules[rule_id].enabled = True

        for rule_id, rule in self._rules.items():
            if rule_id not in self._enabled_rules:
                rule.enabled = False

    def enable_all(self) -> None:
        """Enable all registered rules."""
        self._enabled_rules = set(self._rules.keys())
        for rule in self._rules.values():
            rule.enabled = True

    def disable_all(self) -> None:
        """Disable all registered rules."""
        self._enabled_rules = set()
        for rule in self._rules.values():
            rule.enabled = False

    def load_all_rules(self) -> None:
        """Load all built-in rules from the checks package."""
        from biceps_check import checks

        self._load_rules_from_package(checks)
        logger.info("Loaded all built-in rules", count=self.count)

    def load_custom_rules(self, directory: Path) -> None:
        """Load custom rules from a directory.

        Args:
            directory: Path to the custom rules directory.
        """
        if not directory.exists():
            logger.warning("Custom rules directory not found", path=str(directory))
            return

        # TODO: Implement custom rule loading
        logger.info("Custom rule loading not yet implemented")

    def _load_rules_from_package(self, package) -> None:
        """Load rules from a Python package.

        Args:
            package: The package to load rules from.
        """
        package_path = Path(package.__file__).parent

        for _, module_name, is_pkg in pkgutil.walk_packages(
            [str(package_path)],
            prefix=f"{package.__name__}.",
        ):
            if is_pkg:
                continue

            try:
                module = importlib.import_module(module_name)
                self._register_rules_from_module(module)
            except Exception as e:
                logger.error(
                    "Error loading module",
                    module=module_name,
                    error=str(e),
                )

    def _register_rules_from_module(self, module) -> None:
        """Register all rule classes from a module.

        Args:
            module: The module to scan for rule classes.
        """
        for attr_name in dir(module):
            attr = getattr(module, attr_name)

            # Check if it's a rule class (not the base class)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseRule)
                and attr is not BaseRule
                and attr.id  # Must have an ID defined
            ):
                try:
                    rule_instance = attr()
                    self.register(rule_instance)
                except Exception as e:
                    logger.error(
                        "Error instantiating rule",
                        rule=attr_name,
                        error=str(e),
                    )

    def get_categories(self) -> list[str]:
        """Get all unique categories.

        Returns:
            Sorted list of category names.
        """
        categories = set(rule.category for rule in self._rules.values())
        return sorted(categories)

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about registered rules.

        Returns:
            Dictionary with rule statistics.
        """
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for rule in self._rules.values():
            sev = rule.severity.name
            by_severity[sev] = by_severity.get(sev, 0) + 1

            cat = rule.category
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "total": self.count,
            "enabled": self.enabled_count,
            "disabled": self.count - self.enabled_count,
            "by_severity": by_severity,
            "by_category": by_category,
        }
