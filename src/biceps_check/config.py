"""
Configuration management for Biceps-Check.

This module handles loading, validating, and providing access to
configuration settings from files, environment variables, and defaults.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from biceps_check.rules.base import Severity


class ChecksConfig(BaseModel):
    """Configuration for which checks to run."""

    enable_all: bool = True
    enable: list[str] = Field(default_factory=list)
    skip: list[str] = Field(default_factory=list)


class OutputConfig(BaseModel):
    """Configuration for output formatting."""

    format: str = "cli"
    file: Optional[str] = None


class SuppressionConfig(BaseModel):
    """Configuration for a single suppression."""

    id: str
    reason: str = ""
    expires: Optional[str] = None
    resources: list[str] = Field(default_factory=list)

    def is_expired(self) -> bool:
        """Check if the suppression has expired."""
        if not self.expires:
            return False
        try:
            expiry_date = datetime.fromisoformat(self.expires).replace(tzinfo=timezone.utc).date()
            return datetime.now(tz=timezone.utc).date() > expiry_date
        except ValueError:
            return False


class BicepsCheckConfig(BaseModel):
    """Main configuration class for Biceps-Check."""

    model_config = {"use_enum_values": False}

    framework: list[str] = Field(default_factory=lambda: ["bicep"])
    checks: ChecksConfig = Field(default_factory=ChecksConfig)
    min_severity: Severity = Severity.INFO
    output: OutputConfig = Field(default_factory=OutputConfig)
    suppressions: list[SuppressionConfig] = Field(default_factory=list)
    custom_rules_dir: Optional[str] = None


def load_config(config_path: Optional[str] = None) -> BicepsCheckConfig:
    """Load configuration from file.

    Args:
        config_path: Path to configuration file. If None, searches for
            default config files in the current directory.

    Returns:
        BicepsCheckConfig instance.
    """
    # Default config file names to search for
    default_names = [
        ".biceps-check.yaml",
        ".biceps-check.yml",
        "biceps-check.yaml",
        "biceps-check.yml",
    ]

    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        return _load_config_file(path)

    # Search for default config files
    for name in default_names:
        path = Path(name)
        if path.exists():
            return _load_config_file(path)

    # Return default configuration
    return BicepsCheckConfig()


def _load_config_file(path: Path) -> BicepsCheckConfig:
    """Load configuration from a specific file.

    Args:
        path: Path to the configuration file.

    Returns:
        BicepsCheckConfig instance.
    """
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    # Handle severity as string
    if "min_severity" in data:
        data["min_severity"] = Severity[data["min_severity"]]

    return BicepsCheckConfig(**data)


def generate_default_config() -> str:
    """Generate a default configuration file content.

    Returns:
        YAML string with default configuration.
    """
    return """# Biceps-Check Configuration File
# https://docs.biceps-check.io/configuration

# Framework to scan (currently only bicep is supported)
framework:
  - bicep

# Check configuration
checks:
  # Enable all checks by default
  enable_all: true

  # Skip specific checks (uncomment to use)
  # skip:
  #   - BCK_AZURE_VM_003  # Example: Skip public IP check

  # Or enable only specific checks (uncomment to use)
  # enable:
  #   - BCK_AZURE_ST_001
  #   - BCK_AZURE_KV_001

# Minimum severity to report
# Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
min_severity: INFO

# Output configuration
output:
  # Output format: cli, json, sarif, junit, csv, html
  format: cli
  # Output file (null for stdout)
  file: null

# Suppression patterns (uncomment to use)
# suppressions:
#   - id: BCK_AZURE_ST_001
#     reason: "Legacy storage account - migration planned"
#     expires: "2024-12-31"
#     resources:
#       - "legacyStorageAccount"

# Custom rules directory (uncomment to use)
# custom_rules_dir: ./custom_rules
"""
