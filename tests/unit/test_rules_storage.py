"""Unit tests for storage account security rules."""

import pytest

from biceps_check.checks.storage.storage_account import (
    StorageAccountBlobSoftDelete,
    StorageAccountHttpsOnly,
    StorageAccountInfrastructureEncryption,
    StorageAccountMinimumTls,
    StorageAccountNetworkRules,
    StorageAccountPublicBlobAccess,
    StorageAccountSharedKeyAccess,
)
from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import RuleResult


class TestStorageAccountHttpsOnly:
    """Tests for BCK_AZURE_ST_001."""

    def test_pass_when_https_only_true(self):
        """Should pass when supportsHttpsTrafficOnly is true."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"supportsHttpsTrafficOnly": True}},
            line_number=1,
        )
        rule = StorageAccountHttpsOnly()
        result = rule.check(resource)
        assert result == RuleResult.PASSED

    def test_fail_when_https_only_false(self):
        """Should fail when supportsHttpsTrafficOnly is false."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"supportsHttpsTrafficOnly": False}},
            line_number=1,
        )
        rule = StorageAccountHttpsOnly()
        result = rule.check(resource)
        assert result == RuleResult.FAILED

    def test_pass_when_https_only_not_set(self):
        """Should pass when property not set (defaults to true in newer versions)."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {}},
            line_number=1,
        )
        rule = StorageAccountHttpsOnly()
        result = rule.check(resource)
        assert result == RuleResult.PASSED


class TestStorageAccountMinimumTls:
    """Tests for BCK_AZURE_ST_002."""

    def test_pass_when_tls12(self):
        """Should pass when minimumTlsVersion is TLS1_2."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"minimumTlsVersion": "TLS1_2"}},
            line_number=1,
        )
        rule = StorageAccountMinimumTls()
        result = rule.check(resource)
        assert result == RuleResult.PASSED

    def test_fail_when_tls10(self):
        """Should fail when minimumTlsVersion is TLS1_0."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"minimumTlsVersion": "TLS1_0"}},
            line_number=1,
        )
        rule = StorageAccountMinimumTls()
        result = rule.check(resource)
        assert result == RuleResult.FAILED

    def test_fail_when_not_set(self):
        """Should fail when minimumTlsVersion is not set."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {}},
            line_number=1,
        )
        rule = StorageAccountMinimumTls()
        result = rule.check(resource)
        assert result == RuleResult.FAILED


class TestStorageAccountPublicBlobAccess:
    """Tests for BCK_AZURE_ST_004."""

    def test_pass_when_public_access_disabled(self):
        """Should pass when allowBlobPublicAccess is false."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"allowBlobPublicAccess": False}},
            line_number=1,
        )
        rule = StorageAccountPublicBlobAccess()
        result = rule.check(resource)
        assert result == RuleResult.PASSED

    def test_fail_when_public_access_enabled(self):
        """Should fail when allowBlobPublicAccess is true."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"allowBlobPublicAccess": True}},
            line_number=1,
        )
        rule = StorageAccountPublicBlobAccess()
        result = rule.check(resource)
        assert result == RuleResult.FAILED


class TestStorageAccountNetworkRules:
    """Tests for BCK_AZURE_ST_005."""

    def test_pass_when_default_deny(self):
        """Should pass when networkAcls defaultAction is Deny."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"networkAcls": {"defaultAction": "Deny"}}},
            line_number=1,
        )
        rule = StorageAccountNetworkRules()
        result = rule.check(resource)
        assert result == RuleResult.PASSED

    def test_fail_when_default_allow(self):
        """Should fail when networkAcls defaultAction is Allow."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"networkAcls": {"defaultAction": "Allow"}}},
            line_number=1,
        )
        rule = StorageAccountNetworkRules()
        result = rule.check(resource)
        assert result == RuleResult.FAILED

    def test_fail_when_no_network_rules(self):
        """Should fail when networkAcls is not configured."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {}},
            line_number=1,
        )
        rule = StorageAccountNetworkRules()
        result = rule.check(resource)
        assert result == RuleResult.FAILED


class TestStorageAccountInfrastructureEncryption:
    """Tests for BCK_AZURE_ST_008."""

    def test_pass_when_enabled(self):
        """Should pass when requireInfrastructureEncryption is true."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"encryption": {"requireInfrastructureEncryption": True}}},
            line_number=1,
        )
        rule = StorageAccountInfrastructureEncryption()
        result = rule.check(resource)
        assert result == RuleResult.PASSED

    def test_fail_when_disabled(self):
        """Should fail when requireInfrastructureEncryption is false."""
        resource = BicepResource(
            name="testStorage",
            resource_type="Microsoft.Storage/storageAccounts",
            api_version="2023-01-01",
            properties={"properties": {"encryption": {"requireInfrastructureEncryption": False}}},
            line_number=1,
        )
        rule = StorageAccountInfrastructureEncryption()
        result = rule.check(resource)
        assert result == RuleResult.FAILED
