"""
Security checks for Azure Database for PostgreSQL.

Resource type: Microsoft.DBforPostgreSQL/flexibleServers
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class PostgreSQLPublicNetworkDisabled(BaseRule):
    """Check that PostgreSQL has public network access disabled."""

    id = "BCK_AZURE_PSQL_001"
    name = "PostgreSQL should disable public network access"
    description = (
        "Azure Database for PostgreSQL should have public network access disabled to ensure "
        "the database is only accessible through private endpoints or VNet integration."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = "Set 'publicNetworkAccess' to 'Disabled' in the PostgreSQL server properties."
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-networking",
    ]

    cis_azure = ["6.3"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access != "Disabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class PostgreSQLPrivateEndpoints(BaseRule):
    """Check that PostgreSQL uses private endpoints."""

    id = "BCK_AZURE_PSQL_002"
    name = "PostgreSQL should use private endpoints"
    description = (
        "Private endpoints enable access to Azure Database for PostgreSQL through a private IP "
        "address within your VNet, eliminating exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Configure private endpoints and set 'publicNetworkAccess' to 'Disabled'."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-networking-private-link",
    ]

    cis_azure = ["6.4"]
    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")
        delegated_subnet = resource.get_property("properties.delegatedSubnetResourceId")
        private_dns_zone = resource.get_property("properties.privateDnsZoneArmResourceId")

        # Good if public access disabled or using delegated subnet/private DNS
        if public_access == "Disabled":
            return RuleResult.PASSED

        if delegated_subnet or private_dns_zone:
            return RuleResult.PASSED

        return RuleResult.FAILED


class PostgreSQLEntraAuthOnly(BaseRule):
    """Check that PostgreSQL uses Microsoft Entra authentication only."""

    id = "BCK_AZURE_PSQL_003"
    name = "PostgreSQL should use Microsoft Entra authentication only"
    description = (
        "Azure Database for PostgreSQL should use Microsoft Entra (Azure AD) authentication "
        "only to eliminate the use of local database passwords."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Configure Microsoft Entra authentication and disable local authentication."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/how-to-configure-sign-in-azure-ad-authentication",
    ]

    cis_azure = ["6.2"]
    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Entra-only auth is configured."""
        auth_config = resource.get_property("properties.authConfig")
        raw_content = resource.raw_content or ""

        if auth_config:
            ad_auth = auth_config.get("activeDirectoryAuth", "")
            local_auth = auth_config.get("passwordAuth", "")  # noqa: S105

            if ad_auth == "Enabled" and local_auth == "Disabled":
                return RuleResult.PASSED

        # Check raw content for Azure AD configuration
        if "activeDirectoryAuth" in raw_content and "Enabled" in raw_content:
            if "passwordAuth" in raw_content and "Disabled" in raw_content:
                return RuleResult.PASSED

        return RuleResult.FAILED


class PostgreSQLTLSVersion(BaseRule):
    """Check that PostgreSQL uses minimum TLS 1.2."""

    id = "BCK_AZURE_PSQL_004"
    name = "PostgreSQL should use minimum TLS 1.2"
    description = (
        "Azure Database for PostgreSQL should require TLS 1.2 or higher to ensure secure "
        "communication and prevent protocol downgrade attacks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = "Set 'ssl_min_protocol_version' server parameter to 'TLSv1.2'."
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/how-to-connect-tls-ssl",
    ]

    cis_azure = ["6.11"]
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


class PostgreSQLSSLRequired(BaseRule):
    """Check that PostgreSQL requires SSL connections."""

    id = "BCK_AZURE_PSQL_005"
    name = "PostgreSQL should require SSL connections"
    description = (
        "Azure Database for PostgreSQL should have SSL enforcement enabled to ensure "
        "all connections are encrypted in transit."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'require_secure_transport' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-networking-ssl-tls",
    ]

    cis_azure = ["6.10"]
    nist_800_53 = ["SC-8", "SC-8(1)"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if SSL is required."""
        raw_content = resource.raw_content or ""

        # If explicitly disabled
        if "require_secure_transport" in raw_content and "OFF" in raw_content.upper():
            return RuleResult.FAILED

        return RuleResult.PASSED


class PostgreSQLLogConnections(BaseRule):
    """Check that PostgreSQL logs connections."""

    id = "BCK_AZURE_PSQL_006"
    name = "PostgreSQL should have connection logging enabled"
    description = (
        "Azure Database for PostgreSQL should log all connection attempts for "
        "security monitoring and troubleshooting purposes."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'log_connections' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-logging",
    ]

    cis_azure = ["6.9"]
    nist_800_53 = ["AU-2", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if connection logging is enabled."""
        raw_content = resource.raw_content or ""

        if "log_connections" in raw_content and "ON" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class PostgreSQLLogDisconnections(BaseRule):
    """Check that PostgreSQL logs disconnections."""

    id = "BCK_AZURE_PSQL_007"
    name = "PostgreSQL should have disconnection logging enabled"
    description = (
        "Azure Database for PostgreSQL should log all disconnection events for "
        "security monitoring and audit purposes."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'log_disconnections' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-logging",
    ]

    cis_azure = ["6.8"]
    nist_800_53 = ["AU-2", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if disconnection logging is enabled."""
        raw_content = resource.raw_content or ""

        if "log_disconnections" in raw_content and "ON" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class PostgreSQLLogCheckpoints(BaseRule):
    """Check that PostgreSQL logs checkpoints."""

    id = "BCK_AZURE_PSQL_008"
    name = "PostgreSQL should have checkpoint logging enabled"
    description = (
        "Azure Database for PostgreSQL should log checkpoint events for "
        "performance monitoring and troubleshooting."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'log_checkpoints' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-logging",
    ]

    cis_azure = ["6.7"]
    nist_800_53 = ["AU-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if checkpoint logging is enabled."""
        raw_content = resource.raw_content or ""

        if "log_checkpoints" in raw_content and "ON" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class PostgreSQLConnectionThrottle(BaseRule):
    """Check that PostgreSQL has connection throttling enabled."""

    id = "BCK_AZURE_PSQL_009"
    name = "PostgreSQL should have connection throttling enabled"
    description = (
        "Azure Database for PostgreSQL should have connection throttling enabled to "
        "protect against brute force attacks and connection exhaustion."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = (
        "Set the 'connection_throttle.enable' server parameter to 'ON'."
    )
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-connection-throttling",
    ]

    cis_azure = ["6.5"]
    nist_800_53 = ["SC-5", "AC-6"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if connection throttling is enabled."""
        raw_content = resource.raw_content or ""

        if "connection_throttle" in raw_content and "enable" in raw_content:
            if "ON" in raw_content:
                return RuleResult.PASSED

        return RuleResult.FAILED


class PostgreSQLGeoRedundantBackup(BaseRule):
    """Check that PostgreSQL has geo-redundant backup enabled."""

    id = "BCK_AZURE_PSQL_010"
    name = "PostgreSQL should have geo-redundant backup enabled"
    description = (
        "Azure Database for PostgreSQL should have geo-redundant backup enabled for "
        "disaster recovery and business continuity."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.DBforPostgreSQL/flexibleServers"]
    category = "database"
    remediation = "Set 'geoRedundantBackup' to 'Enabled' in the backup configuration."
    references = [
        "https://docs.microsoft.com/azure/postgresql/flexible-server/concepts-backup-restore",
    ]

    nist_800_53 = ["CP-9", "CP-10"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if geo-redundant backup is enabled."""
        geo_backup = resource.get_property("properties.backup.geoRedundantBackup")

        if geo_backup == "Enabled":
            return RuleResult.PASSED

        return RuleResult.FAILED
