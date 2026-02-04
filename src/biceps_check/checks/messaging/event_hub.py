"""
Security checks for Azure Event Hub.

Resource type: Microsoft.EventHub/namespaces
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class EventHubFirewallRules(BaseRule):
    """Check that Event Hub has firewall rules configured."""

    id = "BCK_AZURE_EH_001"
    name = "Event Hub should have firewall rules configured"
    description = (
        "Event Hub should have network rules to restrict access from "
        "specific networks, virtual networks, or IP addresses."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = (
        "Configure 'networkRuleSets' with 'defaultAction' set to 'Deny' "
        "and specify allowed IP rules or virtual network rules."
    )
    references = [
        "https://docs.microsoft.com/azure/event-hubs/network-security",
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


class EventHubPrivateEndpoint(BaseRule):
    """Check that Event Hub uses private endpoints."""

    id = "BCK_AZURE_EH_002"
    name = "Event Hub should use private endpoints"
    description = (
        "Event Hub should use private endpoints to keep traffic within "
        "the Azure network and prevent exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = (
        "Configure private endpoints and set 'publicNetworkAccess' to 'Disabled'."
    )
    references = [
        "https://docs.microsoft.com/azure/event-hubs/private-link-service",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access == "Disabled":
            return RuleResult.PASSED

        return RuleResult.FAILED


class EventHubPublicAccessDisabled(BaseRule):
    """Check that Event Hub has public network access disabled."""

    id = "BCK_AZURE_EH_003"
    name = "Event Hub should disable public network access"
    description = (
        "Disabling public network access ensures Event Hub can only be "
        "accessed through private endpoints."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = "Set 'publicNetworkAccess' to 'Disabled'."
    references = [
        "https://docs.microsoft.com/azure/event-hubs/network-security",
    ]

    cis_azure = ["6.4"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access != "Disabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class EventHubMinTLS(BaseRule):
    """Check that Event Hub uses minimum TLS 1.2."""

    id = "BCK_AZURE_EH_004"
    name = "Event Hub should use minimum TLS 1.2"
    description = (
        "Event Hub should require TLS 1.2 or higher for all client connections "
        "to ensure secure communication."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = "Set 'minimumTlsVersion' to '1.2'."
    references = [
        "https://docs.microsoft.com/azure/event-hubs/transport-layer-security-configure-minimum-version",
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


class EventHubLocalAuthDisabled(BaseRule):
    """Check that Event Hub has local authentication disabled."""

    id = "BCK_AZURE_EH_005"
    name = "Event Hub should disable local authentication"
    description = (
        "Disable local (SAS key) authentication to enforce Azure AD authentication, "
        "providing better security and audit capabilities."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = "Set 'disableLocalAuth' to true."
    references = [
        "https://docs.microsoft.com/azure/event-hubs/authenticate-application",
    ]

    nist_800_53 = ["AC-3", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if local authentication is disabled."""
        disable_local_auth = resource.get_property("properties.disableLocalAuth")

        if disable_local_auth is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class EventHubAutoInflate(BaseRule):
    """Check that Event Hub has auto-inflate enabled."""

    id = "BCK_AZURE_EH_006"
    name = "Event Hub should have auto-inflate enabled"
    description = (
        "Auto-inflate automatically scales throughput units to handle traffic spikes "
        "without service interruption."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = (
        "Enable 'isAutoInflateEnabled' and set 'maximumThroughputUnits' appropriately."
    )
    references = [
        "https://docs.microsoft.com/azure/event-hubs/event-hubs-auto-inflate",
    ]

    nist_800_53 = ["SC-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if auto-inflate is enabled."""
        auto_inflate = resource.get_property("properties.isAutoInflateEnabled")

        if auto_inflate is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class EventHubZoneRedundancy(BaseRule):
    """Check that Event Hub has zone redundancy enabled."""

    id = "BCK_AZURE_EH_007"
    name = "Event Hub should have zone redundancy enabled"
    description = (
        "Enable zone redundancy to distribute Event Hub across availability zones "
        "for high availability and disaster recovery."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = "Set 'zoneRedundant' to true in supported regions."
    references = [
        "https://docs.microsoft.com/azure/event-hubs/event-hubs-geo-dr",
    ]

    nist_800_53 = ["CP-10", "SC-36"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if zone redundancy is enabled."""
        zone_redundant = resource.get_property("properties.zoneRedundant")

        if zone_redundant is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class EventHubCaptureEnabled(BaseRule):
    """Check that Event Hub has capture enabled for retention."""

    id = "BCK_AZURE_EH_008"
    name = "Event Hub should have capture enabled for data retention"
    description = (
        "Event Hub Capture automatically streams data to Azure Blob Storage or "
        "Data Lake for long-term retention and compliance."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.EventHub/namespaces"]
    category = "messaging"
    remediation = (
        "Enable capture on event hubs that require data retention for compliance "
        "or audit purposes."
    )
    references = [
        "https://docs.microsoft.com/azure/event-hubs/event-hubs-capture-overview",
    ]

    nist_800_53 = ["AU-4", "AU-11"]
    pci_dss = ["10.7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if capture is configured."""
        # Capture is typically configured at the event hub level, not namespace
        # Here we check for any capture configuration in raw content
        raw_content = resource.raw_content or ""

        if "capturedescription" in raw_content.lower():
            return RuleResult.PASSED

        if "capture" in raw_content.lower() and "enabled" in raw_content.lower():
            return RuleResult.PASSED

        return RuleResult.FAILED
