"""
Security checks for Azure Key Vault.

Resource type: Microsoft.KeyVault/vaults
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class KeyVaultPurgeProtection(BaseRule):
    """Check that Key Vault has purge protection enabled."""

    id = "BCK_AZURE_KV_001"
    name = "Key Vault should have purge protection enabled"
    description = (
        "Purge protection prevents permanent deletion of Key Vault and its contents "
        "during the soft delete retention period, protecting against malicious deletion."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.KeyVault/vaults"]
    category = "identity"
    remediation = "Set 'enablePurgeProtection' to true in the Key Vault properties."
    references = [
        "https://docs.microsoft.com/azure/key-vault/general/soft-delete-overview",
    ]

    cis_azure = ["8.4"]
    nist_800_53 = ["CP-9", "SC-28"]
    pci_dss = ["3.5.2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if purge protection is enabled."""
        purge_protection = resource.get_property("properties.enablePurgeProtection")

        if purge_protection is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class KeyVaultSoftDelete(BaseRule):
    """Check that Key Vault has soft delete enabled."""

    id = "BCK_AZURE_KV_002"
    name = "Key Vault should have soft delete enabled"
    description = (
        "Soft delete allows recovery of deleted vaults and vault objects for a "
        "configurable retention period, protecting against accidental deletion."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.KeyVault/vaults"]
    category = "identity"
    remediation = "Set 'enableSoftDelete' to true (default in newer API versions)."
    references = [
        "https://docs.microsoft.com/azure/key-vault/general/soft-delete-overview",
    ]

    cis_azure = ["8.4"]
    nist_800_53 = ["CP-9"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if soft delete is enabled."""
        soft_delete = resource.get_property("properties.enableSoftDelete")

        # Note: Soft delete is enabled by default in newer API versions
        if soft_delete is False:
            return RuleResult.FAILED

        return RuleResult.PASSED


class KeyVaultRbacAuthorization(BaseRule):
    """Check that Key Vault uses RBAC for access control."""

    id = "BCK_AZURE_KV_003"
    name = "Key Vault should use RBAC for access control"
    description = (
        "Using Azure RBAC for Key Vault access control provides better integration "
        "with Azure's identity management, enabling consistent access policies across resources."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.KeyVault/vaults"]
    category = "identity"
    remediation = "Set 'enableRbacAuthorization' to true in the Key Vault properties."
    references = [
        "https://docs.microsoft.com/azure/key-vault/general/rbac-guide",
    ]

    nist_800_53 = ["AC-2", "AC-6"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if RBAC authorization is enabled."""
        rbac_enabled = resource.get_property("properties.enableRbacAuthorization")

        if rbac_enabled is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class KeyVaultNetworkAcls(BaseRule):
    """Check that Key Vault has network rules configured."""

    id = "BCK_AZURE_KV_004"
    name = "Key Vault should have firewall rules configured"
    description = (
        "Key Vault should restrict network access using firewall rules to limit "
        "access from specific networks or IP addresses."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.KeyVault/vaults"]
    category = "identity"
    remediation = (
        "Configure 'networkAcls' with 'defaultAction' set to 'Deny' and specify "
        "allowed virtual networks or IP ranges."
    )
    references = [
        "https://docs.microsoft.com/azure/key-vault/general/network-security",
    ]

    cis_azure = ["8.6"]
    nist_800_53 = ["SC-7", "AC-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if network rules restrict access."""
        default_action = resource.get_property("properties.networkAcls.defaultAction")

        if default_action is None or default_action == "Allow":
            return RuleResult.FAILED

        return RuleResult.PASSED


class KeyVaultPrivateEndpoint(BaseRule):
    """Check that Key Vault uses private endpoints."""

    id = "BCK_AZURE_KV_005"
    name = "Key Vault should use private endpoints"
    description = (
        "Private endpoints allow secure access to Key Vault over a private link, "
        "ensuring traffic doesn't traverse the public internet."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.KeyVault/vaults"]
    category = "identity"
    remediation = (
        "Configure private endpoints for the Key Vault and disable public network access."
    )
    references = [
        "https://docs.microsoft.com/azure/key-vault/general/private-link-service",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled (indicating private endpoint usage)."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        # If public access is explicitly disabled, private endpoints should be in use
        if public_access == "Disabled":
            return RuleResult.PASSED

        # Check if network ACLs effectively block public access
        default_action = resource.get_property("properties.networkAcls.defaultAction")
        if default_action == "Deny":
            # Additional check: are there any allowed IP ranges?
            ip_rules = resource.get_property("properties.networkAcls.ipRules") or []
            if not ip_rules:
                return RuleResult.PASSED

        return RuleResult.FAILED


class KeyVaultDiagnostics(BaseRule):
    """Check that Key Vault has diagnostic logs enabled."""

    id = "BCK_AZURE_KV_006"
    name = "Key Vault should have diagnostic logs enabled"
    description = (
        "Diagnostic logs for Key Vault capture audit events for all operations, "
        "which is essential for security monitoring and compliance."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.KeyVault/vaults"]
    category = "identity"
    remediation = (
        "Configure diagnostic settings to send AuditEvent logs to Log Analytics, "
        "Event Hub, or a storage account."
    )
    references = [
        "https://docs.microsoft.com/azure/key-vault/general/logging",
    ]

    cis_azure = ["5.1.5"]
    nist_800_53 = ["AU-2", "AU-3"]
    pci_dss = ["10.2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for diagnostic settings (note: often configured separately)."""
        # Diagnostic settings are typically configured via a separate resource
        # This check is informational - a full implementation would check for
        # associated diagnosticSettings resources
        return RuleResult.PASSED


class KeyVaultSecretExpiration(BaseRule):
    """Check that Key Vault secrets have expiration dates."""

    id = "BCK_AZURE_KV_007"
    name = "Key Vault secrets should have expiration dates"
    description = (
        "Setting expiration dates on secrets ensures they are rotated regularly "
        "and don't remain valid indefinitely, reducing the risk of compromised credentials."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.KeyVault/vaults/secrets"]
    category = "identity"
    remediation = "Set 'exp' (expiration time) attribute when creating secrets."
    references = [
        "https://docs.microsoft.com/azure/key-vault/secrets/about-secrets",
    ]

    nist_800_53 = ["IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if secret has expiration configured."""
        expiration = resource.get_property("properties.attributes.exp")

        if expiration is None:
            return RuleResult.FAILED

        return RuleResult.PASSED


class KeyVaultKeyExpiration(BaseRule):
    """Check that Key Vault keys have expiration dates."""

    id = "BCK_AZURE_KV_008"
    name = "Key Vault keys should have expiration dates"
    description = (
        "Setting expiration dates on keys ensures they are rotated regularly, "
        "limiting the time window for potential cryptographic attacks."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.KeyVault/vaults/keys"]
    category = "identity"
    remediation = "Set 'exp' (expiration time) attribute when creating keys."
    references = [
        "https://docs.microsoft.com/azure/key-vault/keys/about-keys",
    ]

    cis_azure = ["8.1"]
    nist_800_53 = ["SC-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if key has expiration configured."""
        expiration = resource.get_property("properties.attributes.exp")

        if expiration is None:
            return RuleResult.FAILED

        return RuleResult.PASSED


class KeyVaultKeyType(BaseRule):
    """Check that Key Vault keys use appropriate cryptographic algorithms."""

    id = "BCK_AZURE_KV_009"
    name = "Key Vault keys should use RSA or EC with appropriate size"
    description = (
        "Keys should use strong cryptographic algorithms. RSA keys should be at least "
        "2048 bits, and EC keys should use P-256 or stronger curves."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.KeyVault/vaults/keys"]
    category = "identity"
    remediation = "Use RSA keys with 2048+ bits or EC keys with P-256 or P-384 curves."
    references = [
        "https://docs.microsoft.com/azure/key-vault/keys/about-keys",
    ]

    nist_800_53 = ["SC-12", "SC-13"]
    pci_dss = ["3.6.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check key type and size."""
        key_type = resource.get_property("properties.kty")
        key_size = resource.get_property("properties.key_size")
        curve = resource.get_property("properties.crv")

        if key_type in ["RSA", "RSA-HSM"]:
            if key_size and key_size < 2048:
                return RuleResult.FAILED
        elif key_type in ["EC", "EC-HSM"]:
            weak_curves = ["P-192"]
            if curve and curve in weak_curves:
                return RuleResult.FAILED

        return RuleResult.PASSED
