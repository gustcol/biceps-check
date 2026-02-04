"""
Data models for parsed Bicep files.

This module defines the data structures used to represent parsed
Bicep file contents.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class BicepParameter:
    """Represents a Bicep parameter declaration."""

    name: str
    type: str
    default_value: Optional[Any] = None
    allowed_values: list[Any] = field(default_factory=list)
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    line_number: int = 0
    secure: bool = False

    def get_value(self, provided_value: Optional[Any] = None) -> Any:
        """Get the effective value of the parameter.

        Args:
            provided_value: Value provided externally (e.g., from parameter file).

        Returns:
            The effective value to use.
        """
        if provided_value is not None:
            return provided_value
        return self.default_value


@dataclass
class BicepVariable:
    """Represents a Bicep variable declaration."""

    name: str
    value: Any
    line_number: int = 0


@dataclass
class BicepOutput:
    """Represents a Bicep output declaration."""

    name: str
    type: str
    value: Any
    line_number: int = 0


@dataclass
class BicepModule:
    """Represents a Bicep module reference."""

    name: str
    source: str
    params: dict[str, Any] = field(default_factory=dict)
    scope: Optional[str] = None
    condition: Optional[str] = None
    line_number: int = 0


@dataclass
class BicepResource:
    """Represents a Bicep resource declaration."""

    name: str
    resource_type: str
    api_version: str
    properties: dict[str, Any] = field(default_factory=dict)
    location: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    condition: Optional[str] = None
    scope: Optional[str] = None
    parent: Optional[str] = None
    line_number: int = 0
    raw_content: str = ""
    suppressions: list[str] = field(default_factory=list)
    children: list["BicepResource"] = field(default_factory=list)

    def get_property(self, path: str, default: Any = None) -> Any:
        """Get a property value by dot-notation path.

        Args:
            path: Property path (e.g., "properties.networkAcls.defaultAction").
            default: Default value if property not found.

        Returns:
            The property value or default.
        """
        parts = path.split(".")
        current = self.properties

        for part in parts:
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return default
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return default
            else:
                return default

        return current

    def has_property(self, path: str) -> bool:
        """Check if a property exists.

        Args:
            path: Property path to check.

        Returns:
            True if the property exists.
        """
        return self.get_property(path) is not None

    def has_suppression(self, rule_id: str) -> bool:
        """Check if a rule is suppressed for this resource.

        Args:
            rule_id: The rule ID to check.

        Returns:
            True if the rule is suppressed.
        """
        return rule_id in self.suppressions

    @property
    def kind(self) -> Optional[str]:
        """Get the resource kind property if present."""
        return self.properties.get("kind")

    @property
    def sku(self) -> Optional[dict[str, Any]]:
        """Get the resource SKU if present."""
        return self.properties.get("sku")

    @property
    def sku_name(self) -> Optional[str]:
        """Get the SKU name if present."""
        sku = self.sku
        if isinstance(sku, dict):
            return sku.get("name")
        return None


@dataclass
class BicepFile:
    """Represents a parsed Bicep file."""

    path: Path
    target_scope: str = "resourceGroup"
    parameters: list[BicepParameter] = field(default_factory=list)
    variables: list[BicepVariable] = field(default_factory=list)
    resources: list[BicepResource] = field(default_factory=list)
    modules: list[BicepModule] = field(default_factory=list)
    outputs: list[BicepOutput] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_parameter(self, name: str) -> Optional[BicepParameter]:
        """Get a parameter by name.

        Args:
            name: Parameter name.

        Returns:
            The parameter or None.
        """
        for param in self.parameters:
            if param.name == name:
                return param
        return None

    def get_variable(self, name: str) -> Optional[BicepVariable]:
        """Get a variable by name.

        Args:
            name: Variable name.

        Returns:
            The variable or None.
        """
        for var in self.variables:
            if var.name == name:
                return var
        return None

    def get_resource(self, name: str) -> Optional[BicepResource]:
        """Get a resource by name.

        Args:
            name: Resource name.

        Returns:
            The resource or None.
        """
        for resource in self.resources:
            if resource.name == name:
                return resource
        return None

    def get_resources_by_type(self, resource_type: str) -> list[BicepResource]:
        """Get all resources of a specific type.

        Args:
            resource_type: The resource type to filter by.

        Returns:
            List of matching resources.
        """
        return [r for r in self.resources if r.resource_type == resource_type]
