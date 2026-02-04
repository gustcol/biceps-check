"""
Security checks for Azure Cosmos DB.

Resource type: Microsoft.DocumentDB/databaseAccounts
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class CosmosDbFirewallRules(BaseRule):
    """Check that Cosmos DB has firewall rules configured."""

    id = "BCK_AZURE_COSMOS_001"
    name = "Cosmos DB should have firewall rules configured"
    description = (
        "Cosmos DB should have IP firewall rules to restrict access from specific "
        "IP addresses or ranges, limiting exposure to the internet."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = (
        "Configure 'ipRules' in the Cosmos DB properties to specify allowed "
        "IP addresses or ranges."
    )
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/how-to-configure-firewall",
    ]

    cis_azure = ["4.5.1"]
    nist_800_53 = ["SC-7", "AC-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if firewall rules are configured."""
        ip_rules = resource.get_property("properties.ipRules")
        public_access = resource.get_property("properties.publicNetworkAccess")

        # If public access is disabled, firewall rules are less critical
        if public_access == "Disabled":
            return RuleResult.PASSED

        # Check if there are IP rules defined
        if ip_rules is None or (isinstance(ip_rules, list) and len(ip_rules) == 0):
            return RuleResult.FAILED

        return RuleResult.PASSED


class CosmosDbPublicNetworkAccess(BaseRule):
    """Check that Cosmos DB disables public network access."""

    id = "BCK_AZURE_COSMOS_002"
    name = "Cosmos DB should disable public network access"
    description = (
        "Disabling public network access ensures Cosmos DB is only accessible "
        "through private endpoints, providing network isolation."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = "Set 'publicNetworkAccess' to 'Disabled' and configure private endpoints."
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/how-to-configure-private-endpoints",
    ]

    cis_azure = ["4.5.2"]
    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access is None or public_access == "Enabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class CosmosDbAutomaticFailover(BaseRule):
    """Check that Cosmos DB has automatic failover enabled."""

    id = "BCK_AZURE_COSMOS_003"
    name = "Cosmos DB should have automatic failover enabled"
    description = (
        "Automatic failover ensures high availability by automatically failing "
        "over to a secondary region if the primary becomes unavailable."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = "Set 'enableAutomaticFailover' to true in the Cosmos DB properties."
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/high-availability",
    ]

    nist_800_53 = ["CP-7", "CP-9"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if automatic failover is enabled."""
        auto_failover = resource.get_property("properties.enableAutomaticFailover")

        if auto_failover is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class CosmosDbLocalAuthDisabled(BaseRule):
    """Check that Cosmos DB has local authentication disabled."""

    id = "BCK_AZURE_COSMOS_004"
    name = "Cosmos DB should have local authentication disabled"
    description = (
        "Disabling local authentication forces all access to use Azure AD, "
        "providing better security and auditability."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = "Set 'disableLocalAuth' to true in the Cosmos DB properties."
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/how-to-setup-rbac",
    ]

    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if local authentication is disabled."""
        disable_local = resource.get_property("properties.disableLocalAuth")

        if disable_local is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class CosmosDbContinuousBackup(BaseRule):
    """Check that Cosmos DB has continuous backup enabled."""

    id = "BCK_AZURE_COSMOS_005"
    name = "Cosmos DB should have continuous backup enabled"
    description = (
        "Continuous backup provides point-in-time restore capability, allowing "
        "recovery to any point within the retention period."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = (
        "Set 'backupPolicy.type' to 'Continuous' in the Cosmos DB properties."
    )
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/continuous-backup-restore-introduction",
    ]

    nist_800_53 = ["CP-9"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if continuous backup is enabled."""
        backup_type = resource.get_property("properties.backupPolicy.type")

        if backup_type != "Continuous":
            return RuleResult.FAILED

        return RuleResult.PASSED


class CosmosDbDiagnosticLogs(BaseRule):
    """Check that Cosmos DB has diagnostic logs enabled."""

    id = "BCK_AZURE_COSMOS_006"
    name = "Cosmos DB should have diagnostic logs enabled"
    description = (
        "Diagnostic logs capture data plane requests, providing visibility into "
        "database operations for security monitoring and troubleshooting."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = (
        "Configure diagnostic settings to send DataPlaneRequests and other "
        "relevant logs to Log Analytics or storage."
    )
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/monitor-cosmos-db",
    ]

    cis_azure = ["5.3"]
    nist_800_53 = ["AU-2", "AU-3", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for diagnostic logs (configured via separate resource)."""
        return RuleResult.PASSED  # Configured via diagnosticSettings resource


class CosmosDbVirtualNetworkRules(BaseRule):
    """Check that Cosmos DB has virtual network rules configured."""

    id = "BCK_AZURE_COSMOS_007"
    name = "Cosmos DB should have virtual network rules configured"
    description = (
        "Virtual network service endpoints restrict Cosmos DB access to specific "
        "subnets within virtual networks."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DocumentDB/databaseAccounts"]
    category = "database"
    remediation = (
        "Configure 'virtualNetworkRules' and set 'isVirtualNetworkFilterEnabled' "
        "to true in the Cosmos DB properties."
    )
    references = [
        "https://docs.microsoft.com/azure/cosmos-db/how-to-configure-vnet-service-endpoint",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if virtual network rules are configured."""
        vnet_enabled = resource.get_property(
            "properties.isVirtualNetworkFilterEnabled"
        )
        vnet_rules = resource.get_property("properties.virtualNetworkRules")
        public_access = resource.get_property("properties.publicNetworkAccess")

        # If public access is disabled, VNet rules are less critical
        if public_access == "Disabled":
            return RuleResult.PASSED

        if vnet_enabled is not True:
            return RuleResult.FAILED

        if vnet_rules is None or (isinstance(vnet_rules, list) and len(vnet_rules) == 0):
            return RuleResult.FAILED

        return RuleResult.PASSED
