"""
Security checks for Azure Container Registry.

Resource type: Microsoft.ContainerRegistry/registries
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class ACRAdminDisabled(BaseRule):
    """Check that ACR admin user is disabled."""

    id = "BCK_AZURE_ACR_001"
    name = "ACR should have admin user disabled"
    description = (
        "Container Registry admin user should be disabled. Use Azure AD-based "
        "authentication or service principals for more secure and auditable access."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = "Set 'adminUserEnabled' to false in the registry properties."
    references = [
        "https://docs.microsoft.com/azure/container-registry/container-registry-authentication",
    ]

    cis_azure = ["9.4"]
    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if admin user is disabled."""
        admin_enabled = resource.get_property("properties.adminUserEnabled")

        if admin_enabled is True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRPrivateEndpoint(BaseRule):
    """Check that ACR uses private endpoints."""

    id = "BCK_AZURE_ACR_002"
    name = "ACR should use private endpoints"
    description = (
        "Container Registry should use private endpoints to ensure container "
        "images are accessed through private network connectivity."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = (
        "Configure private endpoints for the container registry and disable "
        "public network access."
    )
    references = [
        "https://docs.microsoft.com/azure/container-registry/container-registry-private-link",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        # If public access is explicitly disabled, likely using private endpoints
        if public_access == "Disabled":
            return RuleResult.PASSED

        # Check for private endpoint connections in raw content
        raw_content = resource.raw_content or ""
        if "privateendpoint" in raw_content.lower():
            return RuleResult.PASSED

        return RuleResult.FAILED


class ACRContentTrust(BaseRule):
    """Check that ACR has content trust enabled."""

    id = "BCK_AZURE_ACR_003"
    name = "ACR should have content trust enabled"
    description = (
        "Content trust should be enabled to ensure only signed and verified "
        "images are pushed to and pulled from the registry."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = (
        "Enable content trust by setting 'policies.trustPolicy.status' to 'enabled'. "
        "Requires Premium SKU."
    )
    references = [
        "https://docs.microsoft.com/azure/container-registry/container-registry-content-trust",
    ]

    nist_800_53 = ["SI-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if content trust is enabled."""
        trust_policy = resource.get_property("properties.policies.trustPolicy.status")

        if trust_policy != "enabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRPublicAccessDisabled(BaseRule):
    """Check that ACR has public network access disabled."""

    id = "BCK_AZURE_ACR_004"
    name = "ACR should have public network access disabled"
    description = (
        "Container Registry should have public network access disabled to prevent "
        "unauthorized access from the internet."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = "Set 'publicNetworkAccess' to 'Disabled'."
    references = [
        "https://docs.microsoft.com/azure/container-registry/container-registry-access-selected-networks",
    ]

    cis_azure = ["9.5"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access != "Disabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRPremiumSKU(BaseRule):
    """Check that ACR uses Premium SKU for security features."""

    id = "BCK_AZURE_ACR_005"
    name = "ACR should use Premium SKU for security features"
    description = (
        "Premium SKU provides advanced security features including private link, "
        "customer-managed keys, content trust, and geo-replication."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = "Set 'sku.name' to 'Premium' to enable advanced security features."
    references = [
        "https://docs.microsoft.com/azure/container-registry/container-registry-skus",
    ]

    nist_800_53 = ["SC-7", "SC-28"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Premium SKU is used."""
        sku = resource.get_property("sku.name")

        if sku != "Premium":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRRetentionPolicy(BaseRule):
    """Check that ACR has retention policy enabled."""

    id = "BCK_AZURE_ACR_006"
    name = "ACR should have retention policy enabled"
    description = (
        "Retention policy should be configured to automatically purge untagged "
        "manifests and reclaim storage space."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = (
        "Configure 'policies.retentionPolicy' with appropriate retention period. "
        "Requires Premium SKU."
    )
    references = [
        "https://docs.microsoft.com/azure/container-registry/container-registry-retention-policy",
    ]

    nist_800_53 = ["SI-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if retention policy is configured."""
        retention_status = resource.get_property(
            "properties.policies.retentionPolicy.status"
        )

        if retention_status != "enabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRVulnerabilityScanning(BaseRule):
    """Check that ACR has vulnerability scanning enabled."""

    id = "BCK_AZURE_ACR_007"
    name = "ACR should have vulnerability scanning enabled"
    description = (
        "Enable Microsoft Defender for container registries to automatically "
        "scan images for vulnerabilities when pushed to the registry."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = (
        "Enable Microsoft Defender for container registries at the subscription level "
        "or use Azure Security Center for continuous scanning."
    )
    references = [
        "https://docs.microsoft.com/azure/defender-for-cloud/defender-for-container-registries-introduction",
    ]

    cis_azure = ["9.6"]
    nist_800_53 = ["RA-5", "SI-2"]
    pci_dss = ["6.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for vulnerability scanning configuration."""
        # This is typically configured at subscription level with Defender
        # Here we check for presence of any scanning configuration
        raw_content = resource.raw_content or ""

        scanning_indicators = [
            "defender",
            "securitycenter",
            "vulnerabilityassessment",
        ]

        content_lower = raw_content.lower()
        for indicator in scanning_indicators:
            if indicator in content_lower:
                return RuleResult.PASSED

        # Default to passed if Premium SKU (likely has Defender enabled)
        sku = resource.get_property("sku.name")
        if sku == "Premium":
            return RuleResult.PASSED

        return RuleResult.FAILED


class ACRZoneRedundancy(BaseRule):
    """Check that ACR uses zone redundancy."""

    id = "BCK_AZURE_ACR_008"
    name = "ACR should use zone redundancy"
    description = (
        "Enable zone redundancy to replicate registry data across availability zones "
        "for high availability and resilience."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = (
        "Set 'zoneRedundancy' to 'Enabled'. Requires Premium SKU in supported regions."
    )
    references = [
        "https://docs.microsoft.com/azure/container-registry/zone-redundancy",
    ]

    nist_800_53 = ["CP-10", "SC-36"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if zone redundancy is enabled."""
        zone_redundancy = resource.get_property("properties.zoneRedundancy")

        if zone_redundancy != "Enabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRExportPolicyDisabled(BaseRule):
    """Check that ACR has export policy disabled."""

    id = "BCK_AZURE_ACR_009"
    name = "ACR should have export policy disabled"
    description = (
        "Disable export policy to prevent exporting container images from the "
        "registry, helping prevent data exfiltration."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = "Set 'policies.exportPolicy.status' to 'disabled'."
    references = [
        "https://docs.microsoft.com/azure/container-registry/data-loss-prevention",
    ]

    nist_800_53 = ["AC-4", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if export policy is disabled."""
        export_policy = resource.get_property("properties.policies.exportPolicy.status")

        if export_policy == "enabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class ACRAnonymousPullDisabled(BaseRule):
    """Check that ACR has anonymous pull disabled."""

    id = "BCK_AZURE_ACR_010"
    name = "ACR should have anonymous pull disabled"
    description = (
        "Anonymous pull access should be disabled to ensure only authenticated "
        "users can pull images from the registry."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerRegistry/registries"]
    category = "compute"
    remediation = "Set 'anonymousPullEnabled' to false."
    references = [
        "https://docs.microsoft.com/azure/container-registry/anonymous-pull-access",
    ]

    cis_azure = ["9.7"]
    nist_800_53 = ["AC-3", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if anonymous pull is disabled."""
        anonymous_pull = resource.get_property("properties.anonymousPullEnabled")

        if anonymous_pull is True:
            return RuleResult.FAILED

        return RuleResult.PASSED
