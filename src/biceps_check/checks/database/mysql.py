"""
Security checks for Azure Database for MySQL.

Resource type: Microsoft.DBforMySQL/flexibleServers
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class MySQLPublicNetworkDisabled(BaseRule):
    """Check that MySQL has public network access disabled."""

    id = "BCK_AZURE_MYSQL_001"
    name = "MySQL should disable public network access"
    description = (
        "Azure Database for MySQL should have public network access disabled to ensure "
        "the database is only accessible through private endpoints or VNet integration."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = "Set 'publicNetworkAccess' to 'Disabled' in the MySQL server properties."
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/concepts-networking",
    ]

    cis_azure = ["5.3"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access != "Disabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class MySQLPrivateEndpoints(BaseRule):
    """Check that MySQL uses private endpoints."""

    id = "BCK_AZURE_MYSQL_002"
    name = "MySQL should use private endpoints"
    description = (
        "Private endpoints enable access to Azure Database for MySQL through a private IP "
        "address within your VNet, eliminating exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = (
        "Configure private endpoints and set 'publicNetworkAccess' to 'Disabled'."
    )
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/concepts-networking-private-link",
    ]

    cis_azure = ["5.4"]
    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")
        delegated_subnet = resource.get_property("properties.delegatedSubnetResourceId")
        private_dns_zone = resource.get_property("properties.privateDnsZoneResourceId")

        # Good if public access disabled or using delegated subnet/private DNS
        if public_access == "Disabled":
            return RuleResult.PASSED

        if delegated_subnet or private_dns_zone:
            return RuleResult.PASSED

        return RuleResult.FAILED


class MySQLEntraAuthOnly(BaseRule):
    """Check that MySQL uses Microsoft Entra authentication only."""

    id = "BCK_AZURE_MYSQL_003"
    name = "MySQL should use Microsoft Entra authentication only"
    description = (
        "Azure Database for MySQL should use Microsoft Entra (Azure AD) authentication "
        "only to eliminate the use of local database passwords."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = (
        "Configure Microsoft Entra authentication and disable local authentication "
        "by setting appropriate identity and authentication properties."
    )
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/how-to-azure-ad",
    ]

    cis_azure = ["5.2"]
    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Entra-only auth is configured."""
        raw_content = resource.raw_content or ""

        # Check for Azure AD admin configuration
        if "activeDirectoryAuth" in raw_content and "Enabled" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class MySQLTLSVersion(BaseRule):
    """Check that MySQL uses minimum TLS 1.2."""

    id = "BCK_AZURE_MYSQL_004"
    name = "MySQL should use minimum TLS 1.2"
    description = (
        "Azure Database for MySQL should require TLS 1.2 or higher to ensure secure "
        "communication and prevent protocol downgrade attacks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = "Set 'require_secure_transport' to ON and 'tls_version' to 'TLSv1.2'."
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/how-to-connect-tls-ssl",
    ]

    cis_azure = ["5.9"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS 1.2 is configured."""
        raw_content = resource.raw_content or ""

        # Check for TLS 1.0 or 1.1 in the configuration
        if "TLSv1.0" in raw_content or "TLSv1.1" in raw_content:
            if "TLSv1.2" not in raw_content:
                return RuleResult.FAILED

        return RuleResult.PASSED


class MySQLSSLRequired(BaseRule):
    """Check that MySQL requires SSL connections."""

    id = "BCK_AZURE_MYSQL_005"
    name = "MySQL should require SSL connections"
    description = (
        "Azure Database for MySQL should have SSL enforcement enabled to ensure "
        "all connections are encrypted in transit."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'require_secure_transport' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/concepts-networking-ssl-tls",
    ]

    cis_azure = ["5.8"]
    nist_800_53 = ["SC-8", "SC-8(1)"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if SSL is required."""
        raw_content = resource.raw_content or ""

        # If explicitly disabled
        if "require_secure_transport" in raw_content and "OFF" in raw_content.upper():
            return RuleResult.FAILED

        return RuleResult.PASSED


class MySQLAuditLogEnabled(BaseRule):
    """Check that MySQL has audit logging enabled."""

    id = "BCK_AZURE_MYSQL_006"
    name = "MySQL should have audit logging enabled"
    description = (
        "Azure Database for MySQL should have audit logging enabled for security "
        "monitoring and compliance purposes."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'audit_log_enabled' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/concepts-audit-logs",
    ]

    cis_azure = ["5.5"]
    nist_800_53 = ["AU-2", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if audit logging is enabled."""
        raw_content = resource.raw_content or ""

        # Look for audit_log_enabled configuration
        if "audit_log_enabled" in raw_content and "ON" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class MySQLGeoRedundantBackup(BaseRule):
    """Check that MySQL has geo-redundant backup enabled."""

    id = "BCK_AZURE_MYSQL_007"
    name = "MySQL should have geo-redundant backup enabled"
    description = (
        "Azure Database for MySQL should have geo-redundant backup enabled for "
        "disaster recovery and business continuity."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = "Set 'geoRedundantBackup' to 'Enabled' in the backup configuration."
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/concepts-backup-restore",
    ]

    nist_800_53 = ["CP-9", "CP-10"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if geo-redundant backup is enabled."""
        geo_backup = resource.get_property("properties.backup.geoRedundantBackup")

        if geo_backup == "Enabled":
            return RuleResult.PASSED

        return RuleResult.FAILED


class MySQLHighAvailability(BaseRule):
    """Check that MySQL has high availability configured."""

    id = "BCK_AZURE_MYSQL_008"
    name = "MySQL should have high availability configured"
    description = (
        "Azure Database for MySQL should have high availability configured for "
        "production workloads to ensure service continuity."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforMySQL/flexibleServers"]
    category = "database"
    remediation = (
        "Configure high availability mode in the 'highAvailability' property."
    )
    references = [
        "https://docs.microsoft.com/azure/mysql/flexible-server/concepts-high-availability",
    ]

    nist_800_53 = ["CP-2", "SC-36"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if high availability is configured."""
        ha_mode = resource.get_property("properties.highAvailability.mode")

        if ha_mode in ["ZoneRedundant", "SameZone"]:
            return RuleResult.PASSED

        return RuleResult.FAILED
