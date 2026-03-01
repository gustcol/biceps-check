"""
Security checks for Azure Kubernetes Service (AKS).

Resource type: Microsoft.ContainerService/managedClusters
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class AksRbacEnabled(BaseRule):
    """Check that AKS has RBAC enabled."""

    id = "BCK_AZURE_AKS_001"
    name = "AKS should have RBAC enabled"
    description = (
        "Role-Based Access Control (RBAC) provides fine-grained access management "
        "for Kubernetes resources, essential for security and compliance."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = "Set 'enableRBAC' to true in the AKS cluster properties."
    references = [
        "https://docs.microsoft.com/azure/aks/concepts-identity#kubernetes-rbac",
    ]

    cis_azure = ["8.5"]
    nist_800_53 = ["AC-2", "AC-6"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if RBAC is enabled."""
        rbac_enabled = resource.get_property("properties.enableRBAC")

        if rbac_enabled is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksNetworkPolicy(BaseRule):
    """Check that AKS has network policy enabled."""

    id = "BCK_AZURE_AKS_002"
    name = "AKS should have network policy enabled"
    description = (
        "Network policies control traffic between pods, providing network "
        "segmentation and reducing the blast radius of potential breaches."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = (
        "Set 'networkProfile.networkPolicy' to 'azure' or 'calico' in the AKS cluster properties."
    )
    references = [
        "https://docs.microsoft.com/azure/aks/use-network-policies",
    ]

    cis_azure = ["8.5"]
    nist_800_53 = ["SC-7", "AC-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if network policy is enabled."""
        network_policy = resource.get_property("properties.networkProfile.networkPolicy")

        if network_policy is None:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksPrivateCluster(BaseRule):
    """Check that AKS uses private cluster."""

    id = "BCK_AZURE_AKS_003"
    name = "AKS should have private cluster enabled"
    description = (
        "A private AKS cluster has a private API server endpoint, ensuring "
        "the control plane is not exposed to the internet."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = (
        "Set 'apiServerAccessProfile.enablePrivateCluster' to true in the AKS cluster properties."
    )
    references = [
        "https://docs.microsoft.com/azure/aks/private-clusters",
    ]

    cis_azure = ["8.5"]
    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if private cluster is enabled."""
        private_cluster = resource.get_property(
            "properties.apiServerAccessProfile.enablePrivateCluster"
        )

        if private_cluster is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksManagedIdentity(BaseRule):
    """Check that AKS uses managed identity."""

    id = "BCK_AZURE_AKS_004"
    name = "AKS should use managed identity"
    description = (
        "Managed identities eliminate the need to manage credentials for AKS "
        "to interact with Azure resources, improving security."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = (
        "Set 'identity.type' to 'SystemAssigned' or 'UserAssigned' in the AKS cluster properties."
    )
    references = [
        "https://docs.microsoft.com/azure/aks/use-managed-identity",
    ]

    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if managed identity is configured."""
        identity_type = resource.get_property("identity.type")

        if identity_type is None or identity_type == "None":
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksAzureAdIntegration(BaseRule):
    """Check that AKS has Azure AD integration enabled."""

    id = "BCK_AZURE_AKS_005"
    name = "AKS should have Azure AD integration enabled"
    description = (
        "Azure AD integration provides centralized identity management for "
        "AKS cluster access, enabling SSO and conditional access policies."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = "Configure 'aadProfile' with 'managed' set to true in the AKS cluster properties."
    references = [
        "https://docs.microsoft.com/azure/aks/managed-aad",
    ]

    cis_azure = ["8.5"]
    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Azure AD integration is enabled."""
        aad_profile = resource.get_property("properties.aadProfile")
        managed = resource.get_property("properties.aadProfile.managed")

        if aad_profile is None or managed is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksAuthorizedIpRanges(BaseRule):
    """Check that AKS has API server authorized IP ranges."""

    id = "BCK_AZURE_AKS_006"
    name = "AKS should have API server authorized IP ranges"
    description = (
        "Authorized IP ranges restrict which IP addresses can access the "
        "Kubernetes API server, reducing the attack surface."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = (
        "Configure 'apiServerAccessProfile.authorizedIPRanges' with specific "
        "IP addresses or CIDR ranges."
    )
    references = [
        "https://docs.microsoft.com/azure/aks/api-server-authorized-ip-ranges",
    ]

    nist_800_53 = ["SC-7", "AC-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if authorized IP ranges are configured."""
        private_cluster = resource.get_property(
            "properties.apiServerAccessProfile.enablePrivateCluster"
        )

        # If private cluster, authorized IP ranges are less critical
        if private_cluster is True:
            return RuleResult.PASSED

        ip_ranges = resource.get_property("properties.apiServerAccessProfile.authorizedIPRanges")

        if ip_ranges is None or (isinstance(ip_ranges, list) and len(ip_ranges) == 0):
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksDefenderEnabled(BaseRule):
    """Check that AKS has Defender profile enabled."""

    id = "BCK_AZURE_AKS_007"
    name = "AKS should have Defender profile enabled"
    description = (
        "Microsoft Defender for Containers provides threat protection for "
        "AKS clusters, detecting vulnerabilities and runtime threats."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = (
        "Set 'securityProfile.defender.securityMonitoring.enabled' to true "
        "in the AKS cluster properties."
    )
    references = [
        "https://docs.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction",
    ]

    azure_security_benchmark = ["LT-1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Defender is enabled."""
        defender_enabled = resource.get_property(
            "properties.securityProfile.defender.securityMonitoring.enabled"
        )

        if defender_enabled is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksLocalAccountsDisabled(BaseRule):
    """Check that AKS has local accounts disabled."""

    id = "BCK_AZURE_AKS_008"
    name = "AKS should disable local accounts"
    description = (
        "Disabling local accounts forces all authentication through Azure AD, "
        "ensuring centralized identity management and audit logging."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = "Set 'disableLocalAccounts' to true in the AKS cluster properties."
    references = [
        "https://docs.microsoft.com/azure/aks/managed-aad#disable-local-accounts",
    ]

    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if local accounts are disabled."""
        disable_local = resource.get_property("properties.disableLocalAccounts")

        if disable_local is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksAzurePolicy(BaseRule):
    """Check that AKS has Azure Policy add-on enabled."""

    id = "BCK_AZURE_AKS_009"
    name = "AKS should have Azure Policy add-on enabled"
    description = (
        "Azure Policy add-on for AKS enables enforcement of security policies "
        "on Kubernetes workloads using Open Policy Agent (OPA) Gatekeeper."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = "Set 'addonProfiles.azurepolicy.enabled' to true in the AKS cluster properties."
    references = [
        "https://docs.microsoft.com/azure/governance/policy/concepts/policy-for-kubernetes",
    ]

    nist_800_53 = ["CM-6", "CM-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Azure Policy add-on is enabled."""
        policy_enabled = resource.get_property("properties.addonProfiles.azurepolicy.enabled")

        if policy_enabled is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AksHttpApplicationRoutingDisabled(BaseRule):
    """Check that AKS has HTTP application routing disabled."""

    id = "BCK_AZURE_AKS_010"
    name = "AKS should have HTTP application routing disabled"
    description = (
        "HTTP application routing is not recommended for production as it doesn't "
        "support TLS and lacks security features. Use Azure Application Gateway instead."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.ContainerService/managedClusters"]
    category = "compute"
    remediation = (
        "Set 'addonProfiles.httpApplicationRouting.enabled' to false and use "
        "a proper ingress controller."
    )
    references = [
        "https://docs.microsoft.com/azure/aks/http-application-routing",
    ]

    nist_800_53 = ["SC-8"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if HTTP application routing is disabled."""
        http_routing = resource.get_property(
            "properties.addonProfiles.httpApplicationRouting.enabled"
        )

        if http_routing is True:
            return RuleResult.FAILED

        return RuleResult.PASSED
