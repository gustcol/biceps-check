"""Unit tests for the configuration module."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from biceps_check.config import (
    BicepsCheckConfig,
    ChecksConfig,
    OutputConfig,
    SuppressionConfig,
    _load_config_file,
    generate_default_config,
    load_config,
)
from biceps_check.rules.base import Severity


class TestChecksConfigDefaults:
    """Tests for ChecksConfig default values."""

    def test_enable_all_defaults_to_true(self):
        """Should enable all checks by default."""
        config = ChecksConfig()
        assert config.enable_all is True

    def test_enable_defaults_to_empty_list(self):
        """Should have an empty enable list by default."""
        config = ChecksConfig()
        assert config.enable == []

    def test_skip_defaults_to_empty_list(self):
        """Should have an empty skip list by default."""
        config = ChecksConfig()
        assert config.skip == []

    def test_enable_lists_are_independent(self):
        """Separate instances should not share mutable default lists."""
        a = ChecksConfig()
        b = ChecksConfig()
        a.enable.append("BCK_AZURE_ST_001")
        assert "BCK_AZURE_ST_001" not in b.enable

    def test_skip_lists_are_independent(self):
        """Separate instances should not share mutable default lists."""
        a = ChecksConfig()
        b = ChecksConfig()
        a.skip.append("BCK_AZURE_KV_001")
        assert "BCK_AZURE_KV_001" not in b.skip


class TestOutputConfigDefaults:
    """Tests for OutputConfig default values."""

    def test_format_defaults_to_cli(self):
        """Should use 'cli' as the default output format."""
        config = OutputConfig()
        assert config.format == "cli"

    def test_file_defaults_to_none(self):
        """Should have no output file by default."""
        config = OutputConfig()
        assert config.file is None

    def test_custom_format_accepted(self):
        """Should accept a custom format string."""
        config = OutputConfig(format="json")
        assert config.format == "json"

    def test_custom_file_accepted(self):
        """Should accept a custom output file path."""
        config = OutputConfig(file="output/results.json")  # noqa: S108
        assert config.file == "output/results.json"


class TestBicepsCheckConfigDefaults:
    """Tests for BicepsCheckConfig default values."""

    def test_framework_defaults_to_bicep(self):
        """Should include 'bicep' in the default framework list."""
        config = BicepsCheckConfig()
        assert config.framework == ["bicep"]

    def test_framework_lists_are_independent(self):
        """Separate instances should not share mutable default lists."""
        a = BicepsCheckConfig()
        b = BicepsCheckConfig()
        a.framework.append("arm")
        assert "arm" not in b.framework

    def test_checks_defaults_to_checks_config_instance(self):
        """Should create a ChecksConfig instance with defaults."""
        config = BicepsCheckConfig()
        assert isinstance(config.checks, ChecksConfig)
        assert config.checks.enable_all is True

    def test_min_severity_defaults_to_info(self):
        """Should use INFO as the minimum severity by default."""
        config = BicepsCheckConfig()
        assert config.min_severity == Severity.INFO

    def test_output_defaults_to_output_config_instance(self):
        """Should create an OutputConfig instance with defaults."""
        config = BicepsCheckConfig()
        assert isinstance(config.output, OutputConfig)
        assert config.output.format == "cli"

    def test_suppressions_defaults_to_empty_list(self):
        """Should have no suppressions by default."""
        config = BicepsCheckConfig()
        assert config.suppressions == []

    def test_suppressions_lists_are_independent(self):
        """Separate instances should not share mutable default lists."""
        a = BicepsCheckConfig()
        b = BicepsCheckConfig()
        a.suppressions.append(SuppressionConfig(id="BCK_AZURE_ST_001"))
        assert len(b.suppressions) == 0

    def test_custom_rules_dir_defaults_to_none(self):
        """Should have no custom rules directory by default."""
        config = BicepsCheckConfig()
        assert config.custom_rules_dir is None

    def test_custom_min_severity_accepted(self):
        """Should accept a non-default severity value."""
        config = BicepsCheckConfig(min_severity=Severity.HIGH)
        assert config.min_severity == Severity.HIGH


class TestSuppressionConfigIsExpired:
    """Tests for SuppressionConfig.is_expired."""

    def test_no_expires_returns_false(self):
        """Should return False when no expiry date is set."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001")
        assert suppression.is_expired() is False

    def test_empty_expires_returns_false(self):
        """Should return False when expires is an empty string."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", expires="")
        assert suppression.is_expired() is False

    def test_past_date_returns_true(self):
        """Should return True when the expiry date is in the past."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", expires="2000-01-01")
        assert suppression.is_expired() is True

    def test_future_date_returns_false(self):
        """Should return False when the expiry date is in the future."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", expires="2099-12-31")
        assert suppression.is_expired() is False

    def test_invalid_date_returns_false(self):
        """Should return False gracefully when the date string is invalid."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", expires="not-a-date")
        assert suppression.is_expired() is False

    def test_invalid_date_format_returns_false(self):
        """Should return False for a date in an unrecognised format."""
        suppression = SuppressionConfig(id="BCK_AZURE_ST_001", expires="31/12/2000")
        assert suppression.is_expired() is False

    def test_suppression_with_reason_and_resources(self):
        """is_expired should work correctly regardless of other fields."""
        suppression = SuppressionConfig(
            id="BCK_AZURE_KV_001",
            reason="Legacy vault, migration pending",
            expires="2000-06-15",
            resources=["legacyVault"],
        )
        assert suppression.is_expired() is True


class TestLoadConfigNoFile:
    """Tests for load_config when no config file is present."""

    def test_returns_biceps_check_config_instance(self):
        """Should return a BicepsCheckConfig when no file is found."""
        with patch.object(Path, "exists", return_value=False):
            config = load_config()
        assert isinstance(config, BicepsCheckConfig)

    def test_returns_defaults_when_no_file(self):
        """Should return a config with all default values when no file exists."""
        with patch.object(Path, "exists", return_value=False):
            config = load_config()
        assert config.framework == ["bicep"]
        assert config.checks.enable_all is True
        assert config.min_severity == Severity.INFO
        assert config.output.format == "cli"
        assert config.suppressions == []
        assert config.custom_rules_dir is None


class TestLoadConfigWithSpecifiedPath:
    """Tests for load_config when a specific config file path is given."""

    def test_loads_specified_yaml_file(self):
        """Should load configuration from the specified file path."""
        config_data = {
            "framework": ["bicep"],
            "checks": {"enable_all": False, "skip": ["BCK_AZURE_ST_001"]},
            "min_severity": "HIGH",
            "output": {"format": "json"},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        config = load_config(config_path=tmp_path)

        assert config.checks.enable_all is False
        assert "BCK_AZURE_ST_001" in config.checks.skip
        assert config.min_severity == Severity.HIGH
        assert config.output.format == "json"

    def test_loads_framework_from_specified_file(self):
        """Should load the framework list from the specified file."""
        config_data = {"framework": ["bicep"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        config = load_config(config_path=tmp_path)
        assert config.framework == ["bicep"]

    def test_loads_suppressions_from_specified_file(self):
        """Should load suppression entries from the specified file."""
        config_data = {
            "suppressions": [
                {
                    "id": "BCK_AZURE_KV_001",
                    "reason": "Tracked in ticket-123",
                    "expires": "2099-01-01",
                    "resources": ["myVault"],
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        config = load_config(config_path=tmp_path)
        assert len(config.suppressions) == 1
        assert config.suppressions[0].id == "BCK_AZURE_KV_001"
        assert config.suppressions[0].resources == ["myVault"]

    def test_missing_keys_fall_back_to_defaults(self):
        """Should apply defaults for any keys absent from the config file."""
        config_data = {"output": {"format": "sarif"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        config = load_config(config_path=tmp_path)
        assert config.output.format == "sarif"
        assert config.checks.enable_all is True
        assert config.min_severity == Severity.INFO


class TestLoadConfigDefaultFileSearch:
    """Tests for load_config searching for default config file names."""

    def test_finds_biceps_check_yaml(self):
        """Should load .biceps-check.yaml when it exists in the working dir."""
        config_data = {"output": {"format": "junit"}}
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_file = Path(tmp_dir) / ".biceps-check.yaml"
            config_file.write_text(yaml.dump(config_data))

            # Patch Path("...").exists() to simulate the file being present only
            # for the first default name, by patching the module-level Path usage.
            original_exists = Path.exists

            def patched_exists(self):
                # Only report the target file as existing.
                if str(self) == ".biceps-check.yaml":
                    # Read from our temp file instead by delegating to the real path.
                    return config_file.exists()
                return original_exists(self)

            with patch.object(Path, "exists", patched_exists):
                # Also patch open so reading ".biceps-check.yaml" reads our temp file.
                original_open = open

                def patched_open(path, *args, **kwargs):
                    if str(path) == ".biceps-check.yaml":
                        return original_open(str(config_file), *args, **kwargs)
                    return original_open(path, *args, **kwargs)

                with patch("builtins.open", side_effect=patched_open):
                    config = load_config()

            assert config.output.format == "junit"

    def test_returns_defaults_when_no_default_files_exist(self):
        """Should return default config when none of the default filenames exist."""
        with patch.object(Path, "exists", return_value=False):
            config = load_config()
        assert isinstance(config, BicepsCheckConfig)
        assert config.output.format == "cli"


class TestLoadConfigNonExistentPath:
    """Tests for load_config with a path that does not exist."""

    def test_raises_file_not_found_for_missing_path(self):
        """Should raise FileNotFoundError for a non-existent explicit path."""
        with pytest.raises(FileNotFoundError, match="not found"):
            load_config(config_path="/nonexistent/path/config.yaml")

    def test_error_message_includes_path(self):
        """Error message should reference the provided path."""
        bad_path = "/totally/missing/biceps-check.yaml"
        with pytest.raises(FileNotFoundError) as exc_info:
            load_config(config_path=bad_path)
        assert bad_path in str(exc_info.value)


class TestLoadConfigFile:
    """Tests for _load_config_file with valid YAML content."""

    def test_parses_complete_yaml(self):
        """Should parse a fully populated YAML config file correctly."""
        config_data = {
            "framework": ["bicep"],
            "checks": {
                "enable_all": False,
                "enable": ["BCK_AZURE_ST_001"],
                "skip": [],
            },
            "min_severity": "MEDIUM",
            "output": {"format": "sarif", "file": "output/scan.sarif"},
            "suppressions": [],
            "custom_rules_dir": "./custom",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = Path(tmp.name)

        config = _load_config_file(tmp_path)

        assert config.framework == ["bicep"]
        assert config.checks.enable_all is False
        assert config.checks.enable == ["BCK_AZURE_ST_001"]
        assert config.min_severity == Severity.MEDIUM
        assert config.output.format == "sarif"
        assert config.output.file == "output/scan.sarif"
        assert config.custom_rules_dir == "./custom"

    def test_parses_empty_yaml(self):
        """Should return a default config when the YAML file is empty."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write("")
            tmp_path = Path(tmp.name)

        config = _load_config_file(tmp_path)
        assert isinstance(config, BicepsCheckConfig)
        assert config.min_severity == Severity.INFO

    def test_severity_string_is_converted(self):
        """Should convert a severity string such as 'CRITICAL' to the enum value."""
        config_data = {"min_severity": "CRITICAL"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = Path(tmp.name)

        config = _load_config_file(tmp_path)
        assert config.min_severity == Severity.CRITICAL

    def test_all_severity_levels_are_accepted(self):
        """Should accept every valid severity level string."""
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            config_data = {"min_severity": level}
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
                yaml.dump(config_data, tmp)
                tmp_path = Path(tmp.name)

            config = _load_config_file(tmp_path)
            assert config.min_severity == Severity[level]


class TestGenerateDefaultConfig:
    """Tests for generate_default_config."""

    def test_returns_string(self):
        """Should return a string."""
        result = generate_default_config()
        assert isinstance(result, str)

    def test_returned_string_is_valid_yaml(self):
        """The returned string should be parseable as YAML."""
        result = generate_default_config()
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)

    def test_contains_framework_key(self):
        """The generated YAML should contain the 'framework' key."""
        result = generate_default_config()
        parsed = yaml.safe_load(result)
        assert "framework" in parsed
        assert "bicep" in parsed["framework"]

    def test_contains_checks_section(self):
        """The generated YAML should contain a 'checks' section."""
        result = generate_default_config()
        parsed = yaml.safe_load(result)
        assert "checks" in parsed
        assert parsed["checks"]["enable_all"] is True

    def test_contains_min_severity(self):
        """The generated YAML should specify the min_severity."""
        result = generate_default_config()
        parsed = yaml.safe_load(result)
        assert "min_severity" in parsed
        assert parsed["min_severity"] == "INFO"

    def test_contains_output_section(self):
        """The generated YAML should contain an 'output' section."""
        result = generate_default_config()
        parsed = yaml.safe_load(result)
        assert "output" in parsed
        assert parsed["output"]["format"] == "cli"

    def test_output_is_loadable_by_load_config_file(self):
        """The generated YAML should be directly loadable as a BicepsCheckConfig."""
        result = generate_default_config()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write(result)
            tmp_path = Path(tmp.name)

        config = _load_config_file(tmp_path)
        assert isinstance(config, BicepsCheckConfig)
        assert config.framework == ["bicep"]
        assert config.min_severity == Severity.INFO
        assert config.output.format == "cli"
