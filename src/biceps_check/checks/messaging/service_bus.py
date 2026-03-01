"""
Security checks for Azure Service Bus.

Resource type: Microsoft.ServiceBus/namespaces
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class ServiceBusPremiumTier(BaseRule):
    """Check that Service Bus uses Premium tier for production."""

    id = "BCK_AZURE_SB_001"
    name = "Service Bus should use Premium tier for production"
    description = (
        "Premium tier provides enhanced security features including private link, "
        "customer-managed keys, and zone redundancy."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = "Set 'sku.name' to 'Premium' for production workloads."
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/service-bus-premium-messaging",
    ]

    nist_800_53 = ["SC-7", "SC-28"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Premium SKU is used."""
        sku = resource.get_property("sku.name")

        if sku in ["Basic", "Standard"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class ServiceBusFirewallRules(BaseRule):
    """Check that Service Bus has firewall rules configured."""

    id = "BCK_AZURE_SB_002"
    name = "Service Bus should have firewall rules configured"
    description = (
        "Service Bus should have network rules to restrict access from "
        "specific networks, virtual networks, or IP addresses."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = (
        "Configure 'networkRuleSets' with 'defaultAction' set to 'Deny' "
        "and specify allowed IP rules or virtual network rules."
    )
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/network-security",
    ]

    cis_azure = ["6.3"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for firewall configuration."""
        # Check for public network access disabled
        public_access = resource.get_property("properties.publicNetworkAccess")
        if public_access == "Disabled":
            return RuleResult.PASSED

        # Check raw content for network rules
        raw_content = resource.raw_content or ""
        if "networkrulesets" in raw_content.lower():
            return RuleResult.PASSED

        return RuleResult.FAILED


class ServiceBusPrivateEndpoint(BaseRule):
    """Check that Service Bus uses private endpoints."""

    id = "BCK_AZURE_SB_003"
    name = "Service Bus should use private endpoints"
    description = (
        "Service Bus should use private endpoints to keep traffic within "
        "the Azure network and prevent exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = "Configure private endpoints and set 'publicNetworkAccess' to 'Disabled'."
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/private-link-service",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access == "Disabled":
            return RuleResult.PASSED

        return RuleResult.FAILED


class ServiceBusPublicAccessDisabled(BaseRule):
    """Check that Service Bus has public network access disabled."""

    id = "BCK_AZURE_SB_004"
    name = "Service Bus should disable public network access"
    description = (
        "Disabling public network access ensures Service Bus can only be "
        "accessed through private endpoints."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = "Set 'publicNetworkAccess' to 'Disabled'."
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/network-security",
    ]

    cis_azure = ["6.4"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access != "Disabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ServiceBusMinTLS(BaseRule):
    """Check that Service Bus uses minimum TLS 1.2."""

    id = "BCK_AZURE_SB_005"
    name = "Service Bus should use minimum TLS 1.2"
    description = (
        "Service Bus should require TLS 1.2 or higher for all client connections "
        "to ensure secure communication."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = "Set 'minimumTlsVersion' to '1.2'."
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/transport-layer-security-configure-minimum-version",
    ]

    cis_azure = ["6.5"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS version is 1.2."""
        min_tls = resource.get_property("properties.minimumTlsVersion")

        if min_tls is None or min_tls in ["1.0", "1.1"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class ServiceBusLocalAuthDisabled(BaseRule):
    """Check that Service Bus has local authentication disabled."""

    id = "BCK_AZURE_SB_006"
    name = "Service Bus should disable local authentication"
    description = (
        "Disable local (SAS key) authentication to enforce Azure AD authentication, "
        "providing better security and audit capabilities."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = "Set 'disableLocalAuth' to true."
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/authenticate-application",
    ]

    nist_800_53 = ["AC-3", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if local authentication is disabled."""
        disable_local_auth = resource.get_property("properties.disableLocalAuth")

        if disable_local_auth is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class ServiceBusDiagnosticLogs(BaseRule):
    """Check that Service Bus has diagnostic logs enabled."""

    id = "BCK_AZURE_SB_007"
    name = "Service Bus should have diagnostic logs enabled"
    description = (
        "Diagnostic logs should be enabled to capture operational metrics "
        "and runtime diagnostics for monitoring and security analysis."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = (
        "Configure diagnostic settings to send logs to Log Analytics, "
        "Storage Account, or Event Hub."
    )
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/service-bus-diagnostic-logs",
    ]

    cis_azure = ["5.3"]
    nist_800_53 = ["AU-2", "AU-3", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for diagnostic logs configuration."""
        # Diagnostic settings are typically configured as a separate resource
        # Here we check for any indication of diagnostic configuration
        raw_content = resource.raw_content or ""

        diagnostic_indicators = [
            "diagnosticsettings",
            "diagnosticlogs",
            "workspaceId",
            "storageAccountId",
        ]

        content_lower = raw_content.lower()
        for indicator in diagnostic_indicators:
            if indicator in content_lower:
                return RuleResult.PASSED

        return RuleResult.FAILED


class ServiceBusZoneRedundancy(BaseRule):
    """Check that Service Bus has zone redundancy enabled."""

    id = "BCK_AZURE_SB_008"
    name = "Service Bus should have zone redundancy enabled"
    description = (
        "Enable zone redundancy to distribute Service Bus across availability zones "
        "for high availability and disaster recovery."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ServiceBus/namespaces"]
    category = "messaging"
    remediation = "Set 'zoneRedundant' to true. Requires Premium SKU in supported regions."
    references = [
        "https://docs.microsoft.com/azure/service-bus-messaging/service-bus-outages-disasters",
    ]

    nist_800_53 = ["CP-10", "SC-36"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if zone redundancy is enabled."""
        zone_redundant = resource.get_property("properties.zoneRedundant")

        if zone_redundant is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED
