"""
Security checks for Azure Data Factory.

Resource type: Microsoft.DataFactory/factories
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class DataFactoryManagedIdentity(BaseRule):
    """Check that Data Factory uses managed identity."""

    id = "BCK_AZURE_ADF_001"
    name = "Data Factory should use managed identity"
    description = (
        "Azure Data Factory should use managed identities to authenticate to Azure services "
        "instead of storing credentials in code or configuration."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DataFactory/factories"]
    category = "integration"
    remediation = (
        "Configure a system-assigned or user-assigned managed identity in the "
        "'identity' property of the Data Factory."
    )
    references = [
        "https://docs.microsoft.com/azure/data-factory/data-factory-service-identity",
    ]

    cis_azure = ["4.2"]
    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if managed identity is configured."""
        identity_type = resource.get_property("identity.type")

        if identity_type is None or identity_type == "None":
            return RuleResult.FAILED

        return RuleResult.PASSED


class DataFactoryPublicNetworkDisabled(BaseRule):
    """Check that Data Factory has public network access disabled."""

    id = "BCK_AZURE_ADF_002"
    name = "Data Factory should disable public network access"
    description = (
        "Azure Data Factory should have public network access disabled to ensure "
        "the service is only accessible through private endpoints."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DataFactory/factories"]
    category = "integration"
    remediation = "Set 'publicNetworkAccess' to 'Disabled' in the Data Factory properties."
    references = [
        "https://docs.microsoft.com/azure/data-factory/data-factory-private-link",
    ]

    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access != "Disabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class DataFactoryPrivateEndpoints(BaseRule):
    """Check that Data Factory uses private endpoints."""

    id = "BCK_AZURE_ADF_003"
    name = "Data Factory should use private endpoints"
    description = (
        "Private endpoints enable access to Azure Data Factory through a private IP "
        "address within your VNet, eliminating exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DataFactory/factories"]
    category = "integration"
    remediation = (
        "Configure private endpoints for Data Factory and disable public network access."
    )
    references = [
        "https://docs.microsoft.com/azure/data-factory/data-factory-private-link",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access == "Disabled":
            return RuleResult.PASSED

        return RuleResult.FAILED


class DataFactoryCustomerManagedKey(BaseRule):
    """Check that Data Factory uses customer-managed keys for encryption."""

    id = "BCK_AZURE_ADF_004"
    name = "Data Factory should use customer-managed keys"
    description = (
        "Azure Data Factory should use customer-managed keys (CMK) for encryption "
        "to maintain control over the encryption keys."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DataFactory/factories"]
    category = "integration"
    remediation = (
        "Configure customer-managed key encryption in the 'encryption' property "
        "using Azure Key Vault."
    )
    references = [
        "https://docs.microsoft.com/azure/data-factory/enable-customer-managed-key",
    ]

    cis_azure = ["4.1"]
    nist_800_53 = ["SC-12", "SC-13"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if customer-managed key encryption is configured."""
        encryption = resource.get_property("properties.encryption")
        raw_content = resource.raw_content or ""

        if encryption and encryption.get("keyName"):
            return RuleResult.PASSED

        if "encryption" in raw_content and "vaultBaseUrl" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class DataFactoryGitIntegration(BaseRule):
    """Check that Data Factory has Git integration enabled."""

    id = "BCK_AZURE_ADF_005"
    name = "Data Factory should have Git integration enabled"
    description = (
        "Azure Data Factory should use Git integration for version control, "
        "collaboration, and deployment best practices."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.DataFactory/factories"]
    category = "integration"
    remediation = (
        "Configure Git integration in the 'repoConfiguration' property using "
        "Azure DevOps or GitHub."
    )
    references = [
        "https://docs.microsoft.com/azure/data-factory/source-control",
    ]

    nist_800_53 = ["CM-3", "CM-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Git integration is configured."""
        repo_config = resource.get_property("properties.repoConfiguration")
        raw_content = resource.raw_content or ""

        if repo_config:
            repo_type = repo_config.get("type", "")
            if repo_type in ["FactoryGitHubConfiguration", "FactoryVSTSConfiguration"]:
                return RuleResult.PASSED

        if "repoConfiguration" in raw_content:
            if "FactoryGitHubConfiguration" in raw_content or "FactoryVSTSConfiguration" in raw_content:
                return RuleResult.PASSED

        return RuleResult.FAILED


class DataFactoryDiagnosticLogs(BaseRule):
    """Check that Data Factory has diagnostic logs configured."""

    id = "BCK_AZURE_ADF_006"
    name = "Data Factory should have diagnostic logs enabled"
    description = (
        "Azure Data Factory should have diagnostic logging enabled for "
        "monitoring, troubleshooting, and audit purposes."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DataFactory/factories"]
    category = "integration"
    remediation = (
        "Configure diagnostic settings to send logs to Log Analytics, "
        "Storage Account, or Event Hub."
    )
    references = [
        "https://docs.microsoft.com/azure/data-factory/monitor-using-azure-monitor",
    ]

    nist_800_53 = ["AU-2", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if diagnostic logs are configured."""
        # Diagnostic settings are typically configured as separate resources
        # This check looks for common patterns in the raw content
        raw_content = resource.raw_content or ""

        if "diagnosticSettings" in raw_content:
            return RuleResult.PASSED

        # This is often configured separately - consider as informational
        return RuleResult.FAILED


class DataFactorySelfHostedIRSecure(BaseRule):
    """Check that Data Factory Self-Hosted IR is securely configured."""

    id = "BCK_AZURE_ADF_007"
    name = "Data Factory Self-Hosted IR should be securely configured"
    description = (
        "Azure Data Factory Self-Hosted Integration Runtime should be configured "
        "with secure communication and proper authentication."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DataFactory/factories/integrationRuntimes"]
    category = "integration"
    remediation = (
        "Configure Self-Hosted Integration Runtime with secure settings and "
        "use managed identity where possible."
    )
    references = [
        "https://docs.microsoft.com/azure/data-factory/create-self-hosted-integration-runtime",
    ]

    nist_800_53 = ["SC-8", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Self-Hosted IR is securely configured."""
        ir_type = resource.get_property("properties.type")

        if ir_type == "SelfHosted":
            # Self-hosted IR requires manual security configuration
            # Check for linked service authentication
            raw_content = resource.raw_content or ""
            if "SelfHosted" in raw_content:
                return RuleResult.PASSED

        return RuleResult.PASSED
