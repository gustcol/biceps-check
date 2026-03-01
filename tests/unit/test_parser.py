"""Unit tests for Bicep parser."""

import tempfile
from pathlib import Path

import pytest

from biceps_check.parser.bicep_parser import BicepParser
from biceps_check.parser.models import BicepFile, BicepResource


class TestBicepParser:
    """Tests for BicepParser."""

    def test_parse_simple_resource(self):
        """Should parse a simple resource declaration."""
        bicep_content = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'teststorage'
  location: 'eastus'
  properties: {
    supportsHttpsTrafficOnly: true
  }
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as f:
            f.write(bicep_content)
            f.flush()

            parser = BicepParser()
            result = parser.parse_file(Path(f.name))

            assert isinstance(result, BicepFile)
            assert len(result.resources) == 1

            resource = result.resources[0]
            assert resource.name == "storageAccount"
            assert resource.resource_type == "Microsoft.Storage/storageAccounts"
            assert resource.api_version == "2023-01-01"

    def test_parse_target_scope(self):
        """Should parse target scope declaration."""
        bicep_content = """
targetScope = 'subscription'

resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: 'test-rg'
  location: 'eastus'
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as f:
            f.write(bicep_content)
            f.flush()

            parser = BicepParser()
            result = parser.parse_file(Path(f.name))

            assert result.target_scope == "subscription"

    def test_parse_suppression_comment(self):
        """Should parse suppression comments."""
        bicep_content = """
// biceps-check:disable=BCK_AZURE_ST_001 reason="Legacy account"
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'legacystorage'
  location: 'eastus'
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as f:
            f.write(bicep_content)
            f.flush()

            parser = BicepParser()
            result = parser.parse_file(Path(f.name))

            assert len(result.resources) == 1
            resource = result.resources[0]
            assert "BCK_AZURE_ST_001" in resource.suppressions

    def test_default_target_scope(self):
        """Should default to resourceGroup scope."""
        bicep_content = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'teststorage'
  location: 'eastus'
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bicep", delete=False) as f:
            f.write(bicep_content)
            f.flush()

            parser = BicepParser()
            result = parser.parse_file(Path(f.name))

            assert result.target_scope == "resourceGroup"


class TestBicepResource:
    """Tests for BicepResource model."""

    def test_get_property_simple(self):
        """Should get a simple property."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"name": "teststorage", "location": "eastus"},
            line_number=1,
        )

        assert resource.get_property("name") == "teststorage"
        assert resource.get_property("location") == "eastus"

    def test_get_property_nested(self):
        """Should get a nested property."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"networkAcls": {"defaultAction": "Deny"}}},
            line_number=1,
        )

        assert resource.get_property("properties.networkAcls.defaultAction") == "Deny"

    def test_get_property_with_default(self):
        """Should return default when property not found."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={},
            line_number=1,
        )

        assert resource.get_property("nonexistent", "default") == "default"
        assert resource.get_property("nested.property") is None

    def test_has_property(self):
        """Should check property existence."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"name": "teststorage"},
            line_number=1,
        )

        assert resource.has_property("name") is True
        assert resource.has_property("nonexistent") is False

    def test_has_suppression(self):
        """Should check suppression."""
        resource = BicepResource(
            name="test",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={},
            line_number=1,
            suppressions=["BCK_AZURE_ST_001", "BCK_AZURE_ST_002"],
        )

        assert resource.has_suppression("BCK_AZURE_ST_001") is True
        assert resource.has_suppression("BCK_AZURE_ST_003") is False
