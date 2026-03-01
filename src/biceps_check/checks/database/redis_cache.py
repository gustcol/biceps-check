"""
Security checks for Azure Cache for Redis.

Resource type: Microsoft.Cache/redis
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class RedisTLSEnabled(BaseRule):
    """Check that Redis has TLS enabled."""

    id = "BCK_AZURE_REDIS_001"
    name = "Redis should have TLS enabled"
    description = (
        "Azure Cache for Redis should require TLS connections to encrypt data "
        "in transit and protect against eavesdropping."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = "Set 'minimumTlsVersion' to '1.2' in the Redis cache properties."
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-remove-tls-10-11",
    ]

    cis_azure = ["4.4"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if TLS is enabled with minimum version."""
        min_tls = resource.get_property("properties.minimumTlsVersion")

        if min_tls is None or min_tls in ["1.0", "1.1"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class RedisFirewallRules(BaseRule):
    """Check that Redis has firewall rules configured."""

    id = "BCK_AZURE_REDIS_002"
    name = "Redis should have firewall rules configured"
    description = (
        "Azure Cache for Redis should have firewall rules to restrict access "
        "to specific IP addresses or ranges."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = (
        "Configure firewall rules in 'properties.redisConfiguration' or use "
        "private endpoints for network isolation."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-configure",
    ]

    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for firewall configuration."""
        # Check for private endpoint (best option)
        public_access = resource.get_property("properties.publicNetworkAccess")
        if public_access == "Disabled":
            return RuleResult.PASSED

        # Check raw content for firewall rules
        raw_content = resource.raw_content or ""
        if "firewallrules" in raw_content.lower():
            return RuleResult.PASSED

        return RuleResult.FAILED


class RedisPrivateEndpoint(BaseRule):
    """Check that Redis uses private endpoints."""

    id = "BCK_AZURE_REDIS_003"
    name = "Redis should use private endpoints"
    description = (
        "Azure Cache for Redis should use private endpoints to keep traffic "
        "within the Azure network and prevent exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = (
        "Configure private endpoints for the Redis cache and set "
        "'publicNetworkAccess' to 'Disabled'."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-private-link",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access == "Disabled":
            return RuleResult.PASSED

        return RuleResult.FAILED


class RedisNonSSLPortDisabled(BaseRule):
    """Check that Redis has non-SSL port disabled."""

    id = "BCK_AZURE_REDIS_004"
    name = "Redis should have non-SSL port disabled"
    description = (
        "The non-SSL port (6379) should be disabled to ensure all connections "
        "use TLS encryption on port 6380."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = "Set 'enableNonSslPort' to false in the Redis cache properties."
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-configure#access-ports",
    ]

    cis_azure = ["4.5"]
    nist_800_53 = ["SC-8"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if non-SSL port is disabled."""
        non_ssl_port = resource.get_property("properties.enableNonSslPort")

        if non_ssl_port is True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class RedisMinimumTLS(BaseRule):
    """Check that Redis uses minimum TLS 1.2."""

    id = "BCK_AZURE_REDIS_005"
    name = "Redis should use minimum TLS 1.2"
    description = (
        "Azure Cache for Redis should require TLS 1.2 or higher to ensure "
        "secure communication and prevent downgrade attacks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = "Set 'minimumTlsVersion' to '1.2'."
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-remove-tls-10-11",
    ]

    cis_azure = ["4.4"]
    nist_800_53 = ["SC-8", "SC-8(1)"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS version is 1.2."""
        min_tls = resource.get_property("properties.minimumTlsVersion")

        if min_tls != "1.2":
            return RuleResult.FAILED

        return RuleResult.PASSED


class RedisAuthenticationEnabled(BaseRule):
    """Check that Redis has authentication enabled."""

    id = "BCK_AZURE_REDIS_006"
    name = "Redis should have authentication enabled"
    description = (
        "Azure Cache for Redis should have access key authentication enabled "
        "or use Azure AD authentication for secure access control."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = (
        "Ensure access keys are enabled (default) and consider enabling "
        "Azure AD authentication for enterprise scenarios."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication",
    ]

    cis_azure = ["4.6"]
    nist_800_53 = ["AC-3", "IA-2"]
    pci_dss = ["7.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if authentication is enabled."""
        # Check for Azure AD authentication
        aad_enabled = resource.get_property("properties.redisConfiguration.aad-enabled")
        if aad_enabled == "true":
            return RuleResult.PASSED

        # Access key auth is enabled by default unless explicitly disabled
        disable_access_key = resource.get_property("properties.disableAccessKeyAuthentication")
        if disable_access_key is True:
            # If access keys disabled, must have AAD enabled
            if aad_enabled != "true":
                return RuleResult.FAILED

        return RuleResult.PASSED


class RedisPersistenceEnabled(BaseRule):
    """Check that Redis has persistence enabled."""

    id = "BCK_AZURE_REDIS_007"
    name = "Redis should have data persistence enabled"
    description = (
        "Data persistence should be enabled for production Redis caches to "
        "protect against data loss during cache restarts or failures."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = (
        "Enable RDB or AOF persistence in 'redisConfiguration'. Requires Premium or Enterprise SKU."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-how-to-premium-persistence",
    ]

    nist_800_53 = ["CP-9", "CP-10"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if data persistence is configured."""
        # Check for RDB persistence
        rdb_enabled = resource.get_property("properties.redisConfiguration.rdb-backup-enabled")
        if rdb_enabled == "true":
            return RuleResult.PASSED

        # Check for AOF persistence
        aof_enabled = resource.get_property("properties.redisConfiguration.aof-backup-enabled")
        if aof_enabled == "true":
            return RuleResult.PASSED

        # Check SKU - only Premium/Enterprise support persistence
        sku = resource.get_property("sku.name")
        if sku in ["Basic", "Standard"]:
            # Lower SKUs don't support persistence
            return RuleResult.PASSED

        return RuleResult.FAILED


class RedisPatchingSchedule(BaseRule):
    """Check that Redis has patching schedule configured."""

    id = "BCK_AZURE_REDIS_008"
    name = "Redis should have patching schedule configured"
    description = (
        "Configure a maintenance window for Redis patching to control when "
        "updates occur and minimize impact on application availability."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = (
        "Configure 'patchSchedule' in the Redis cache properties to specify "
        "preferred maintenance windows."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-administration#schedule-updates",
    ]

    nist_800_53 = ["SI-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if patching schedule is configured."""
        raw_content = resource.raw_content or ""

        if "patchschedule" in raw_content.lower():
            return RuleResult.PASSED

        # Also check for scheduleEntries
        if "scheduleentries" in raw_content.lower():
            return RuleResult.PASSED

        return RuleResult.FAILED


class RedisPremiumTier(BaseRule):
    """Check that Redis uses Premium tier for production."""

    id = "BCK_AZURE_REDIS_009"
    name = "Redis should use Premium tier for production workloads"
    description = (
        "Premium tier provides enhanced security features including VNet support, "
        "data persistence, clustering, and zone redundancy."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = "Set 'sku.name' to 'Premium' or use Enterprise tier for production."
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-overview#feature-comparison",
    ]

    nist_800_53 = ["SC-7", "CP-10"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Premium or Enterprise tier is used."""
        sku = resource.get_property("sku.name")

        if sku in ["Basic", "Standard"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class RedisZoneRedundancy(BaseRule):
    """Check that Redis has zone redundancy enabled."""

    id = "BCK_AZURE_REDIS_010"
    name = "Redis should have zone redundancy enabled"
    description = (
        "Enable zone redundancy to distribute Redis replicas across availability "
        "zones for high availability and disaster recovery."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Cache/redis"]
    category = "database"
    remediation = (
        "Set 'zones' property to specify availability zones. "
        "Requires Premium SKU in supported regions."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-how-to-zone-redundancy",
    ]

    nist_800_53 = ["CP-10", "SC-36"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if zone redundancy is configured."""
        zones = resource.get_property("zones")

        if zones and len(zones) > 0:
            return RuleResult.PASSED

        return RuleResult.FAILED
