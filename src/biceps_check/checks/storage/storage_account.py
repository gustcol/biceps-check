"""
Security checks for Azure Storage Accounts.

Resource type: Microsoft.Storage/storageAccounts
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class StorageAccountHttpsOnly(BaseRule):
    """Check that storage account enforces HTTPS."""

    id = "BCK_AZURE_ST_001"
    name = "Storage account should enforce HTTPS"
    description = (
        "Storage accounts should be configured to only accept requests over HTTPS. "
        "HTTPS provides encryption in transit, protecting data from network eavesdropping."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = "Set 'supportsHttpsTrafficOnly' to true in the storage account properties."
    references = [
        "https://docs.microsoft.com/azure/storage/common/storage-require-secure-transfer",
        "https://docs.microsoft.com/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit",
    ]

    # Compliance mappings
    cis_azure = ["3.1"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]
    azure_security_benchmark = ["DP-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if HTTPS-only is enabled."""
        https_only = resource.get_property("properties.supportsHttpsTrafficOnly")

        # Default is true in newer API versions, but we should be explicit
        if https_only is False:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountMinimumTls(BaseRule):
    """Check that storage account uses minimum TLS 1.2."""

    id = "BCK_AZURE_ST_002"
    name = "Storage account should use minimum TLS 1.2"
    description = (
        "Storage accounts should require a minimum TLS version of 1.2 to ensure "
        "connections use modern, secure protocols. TLS 1.0 and 1.1 have known vulnerabilities."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = "Set 'minimumTlsVersion' to 'TLS1_2' in the storage account properties."
    references = [
        "https://docs.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version",
    ]

    cis_azure = ["3.12"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS 1.2 is configured."""
        min_tls = resource.get_property("properties.minimumTlsVersion")

        if min_tls is None or min_tls in ["TLS1_0", "TLS1_1"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountSecureTransfer(BaseRule):
    """Check that secure transfer is required."""

    id = "BCK_AZURE_ST_003"
    name = "Storage account should have secure transfer enabled"
    description = (
        "The secure transfer option enhances security by only allowing requests "
        "to the storage account over a secure connection (HTTPS)."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = "Set 'supportsHttpsTrafficOnly' to true."

    cis_azure = ["3.1"]
    nist_800_53 = ["SC-8"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if secure transfer is required."""
        secure_transfer = resource.get_property("properties.supportsHttpsTrafficOnly")

        if secure_transfer is False:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountPublicBlobAccess(BaseRule):
    """Check that public blob access is disabled."""

    id = "BCK_AZURE_ST_004"
    name = "Storage account should deny public blob access"
    description = (
        "Public blob access should be disabled to prevent anonymous access to data. "
        "When enabled, any user can read blob data without authentication."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = "Set 'allowBlobPublicAccess' to false in the storage account properties."
    references = [
        "https://docs.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",
    ]

    cis_azure = ["3.5"]
    nist_800_53 = ["AC-3", "AC-6"]
    pci_dss = ["7.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public blob access is disabled."""
        allow_public = resource.get_property("properties.allowBlobPublicAccess")

        if allow_public is True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountNetworkRules(BaseRule):
    """Check that network rules are configured."""

    id = "BCK_AZURE_ST_005"
    name = "Storage account should have network rules configured"
    description = (
        "Storage accounts should have network rules to restrict access from specific "
        "networks, virtual networks, or IP addresses rather than allowing access from all networks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = (
        "Configure 'networkAcls' with 'defaultAction' set to 'Deny' and specify "
        "allowed virtual networks or IP ranges."
    )
    references = [
        "https://docs.microsoft.com/azure/storage/common/storage-network-security",
    ]

    cis_azure = ["3.6"]
    nist_800_53 = ["SC-7", "AC-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if network rules restrict access."""
        default_action = resource.get_property("properties.networkAcls.defaultAction")

        # If no network rules or default action allows, fail
        if default_action is None or default_action == "Allow":
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountBlobSoftDelete(BaseRule):
    """Check that blob soft delete is enabled."""

    id = "BCK_AZURE_ST_006"
    name = "Storage account should have blob soft delete enabled"
    description = (
        "Blob soft delete protects against accidental or malicious deletion by "
        "retaining deleted blobs for a specified retention period."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = (
        "Enable soft delete for blobs in the storage account's blob service properties "
        "with an appropriate retention period."
    )

    cis_azure = ["3.8"]
    nist_800_53 = ["CP-9"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if blob soft delete is enabled."""
        # This is typically configured on blobServices, but can be checked here too
        soft_delete = resource.get_property(
            "properties.blobServiceProperties.deleteRetentionPolicy.enabled"
        )

        if soft_delete is False:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountContainerSoftDelete(BaseRule):
    """Check that container soft delete is enabled."""

    id = "BCK_AZURE_ST_007"
    name = "Storage account should have container soft delete enabled"
    description = (
        "Container soft delete protects against accidental deletion of containers "
        "by retaining deleted containers for a specified retention period."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = (
        "Enable soft delete for containers in the storage account's blob service properties."
    )

    nist_800_53 = ["CP-9"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if container soft delete is enabled."""
        soft_delete = resource.get_property(
            "properties.blobServiceProperties.containerDeleteRetentionPolicy.enabled"
        )

        if soft_delete is False:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountInfrastructureEncryption(BaseRule):
    """Check that infrastructure encryption is enabled."""

    id = "BCK_AZURE_ST_008"
    name = "Storage account should have infrastructure encryption enabled"
    description = (
        "Infrastructure encryption adds a second layer of encryption for data at rest "
        "using a different encryption algorithm, providing defense in depth."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = "Set 'requireInfrastructureEncryption' to true in the encryption settings."
    references = [
        "https://docs.microsoft.com/azure/storage/common/infrastructure-encryption-enable",
    ]

    nist_800_53 = ["SC-28", "SC-28(1)"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if infrastructure encryption is enabled."""
        infra_encryption = resource.get_property(
            "properties.encryption.requireInfrastructureEncryption"
        )

        if infra_encryption is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountSharedKeyAccess(BaseRule):
    """Check that shared key access is disabled."""

    id = "BCK_AZURE_ST_009"
    name = "Storage account should disable shared key access"
    description = (
        "Disabling shared key access forces all requests to use Azure AD authentication, "
        "which provides better security through identity-based access control and audit logging."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = "Set 'allowSharedKeyAccess' to false in the storage account properties."
    references = [
        "https://docs.microsoft.com/azure/storage/common/shared-key-authorization-prevent",
    ]

    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if shared key access is disabled."""
        allow_shared_key = resource.get_property("properties.allowSharedKeyAccess")

        if allow_shared_key is True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class StorageAccountDefender(BaseRule):
    """Check that Azure Defender for Storage is recommended."""

    id = "BCK_AZURE_ST_010"
    name = "Storage account should have Azure Defender enabled"
    description = (
        "Azure Defender for Storage provides security intelligence for detecting "
        "unusual and potentially harmful attempts to access or exploit storage accounts."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Storage/storageAccounts"]
    category = "storage"
    remediation = (
        "Enable Azure Defender for Storage at the subscription level or configure "
        "Microsoft.Security/advancedThreatProtectionSettings for the storage account."
    )
    references = [
        "https://docs.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction",
    ]

    azure_security_benchmark = ["LT-1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for Defender configuration (informational)."""
        # This is typically configured separately, so we return INFO-level pass
        # A full implementation would check for associated security settings
        return RuleResult.PASSED

    def get_message(self, resource: BicepResource) -> str:
        """Get recommendation message."""
        return (
            "Consider enabling Azure Defender for Storage to detect threats. "
            "This requires subscription-level configuration."
        )
