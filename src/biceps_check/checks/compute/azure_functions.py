"""
Security checks for Azure Functions.

Resource type: Microsoft.Web/sites (kind: functionapp)
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class FunctionAppHttpsOnly(BaseRule):
    """Check that Function App uses HTTPS only."""

    id = "BCK_AZURE_FUNC_001"
    name = "Function App should use HTTPS only"
    description = (
        "Function App should redirect all HTTP traffic to HTTPS to ensure "
        "all data in transit is encrypted."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'httpsOnly' to true in the Function App properties."
    references = [
        "https://docs.microsoft.com/azure/azure-functions/security-concepts",
    ]

    cis_azure = ["9.2"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if HTTPS-only is enabled."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        https_only = resource.get_property("properties.httpsOnly")

        if https_only is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class FunctionAppManagedIdentity(BaseRule):
    """Check that Function App uses managed identity."""

    id = "BCK_AZURE_FUNC_002"
    name = "Function App should use managed identity"
    description = (
        "Managed identities eliminate the need for credentials in code by providing "
        "an automatically managed identity for authenticating to Azure services."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Configure a system-assigned or user-assigned managed identity in the "
        "'identity' property of the Function App."
    )
    references = [
        "https://docs.microsoft.com/azure/app-service/overview-managed-identity",
    ]

    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if managed identity is configured."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        identity_type = resource.get_property("identity.type")

        if identity_type is None or identity_type == "None":
            return RuleResult.FAILED

        return RuleResult.PASSED


class FunctionAppAuthEnabled(BaseRule):
    """Check that Function App has authentication enabled."""

    id = "BCK_AZURE_FUNC_003"
    name = "Function App should have authentication enabled"
    description = (
        "Enable Function App authentication to protect your functions from unauthenticated access."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Configure Function App Authentication (EasyAuth) using Azure portal "
        "or the authsettingsV2 resource."
    )
    references = [
        "https://docs.microsoft.com/azure/app-service/overview-authentication-authorization",
    ]

    cis_azure = ["9.1"]
    nist_800_53 = ["AC-3", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if authentication is enabled."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        # Check for function auth level (not anonymous)
        raw_content = resource.raw_content or ""
        if "authLevel" in raw_content and "anonymous" in raw_content.lower():
            return RuleResult.FAILED

        return RuleResult.PASSED


class FunctionAppLatestRuntime(BaseRule):
    """Check that Function App uses latest runtime."""

    id = "BCK_AZURE_FUNC_004"
    name = "Function App should use latest runtime version"
    description = (
        "Using the latest Functions runtime ensures you have the latest security "
        "patches, features, and performance improvements."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Update 'FUNCTIONS_EXTENSION_VERSION' to '~4' for the latest runtime."
    references = [
        "https://docs.microsoft.com/azure/azure-functions/functions-versions",
    ]

    nist_800_53 = ["SI-2"]

    # Deprecated runtime versions
    DEPRECATED_VERSIONS = ["~1", "~2", "~3"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if runtime version is current."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        raw_content = resource.raw_content or ""

        for version in self.DEPRECATED_VERSIONS:
            if "FUNCTIONS_EXTENSION_VERSION" in raw_content and version in raw_content:
                return RuleResult.FAILED

        return RuleResult.PASSED


class FunctionAppApplicationInsights(BaseRule):
    """Check that Function App has Application Insights enabled."""

    id = "BCK_AZURE_FUNC_005"
    name = "Function App should have Application Insights enabled"
    description = (
        "Application Insights provides monitoring and diagnostics capabilities "
        "essential for security monitoring and troubleshooting."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Configure 'APPINSIGHTS_INSTRUMENTATIONKEY' or 'APPLICATIONINSIGHTS_CONNECTION_STRING' "
        "in the app settings."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-functions/functions-monitoring",
    ]

    nist_800_53 = ["AU-2", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Application Insights is configured."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        raw_content = resource.raw_content or ""

        if "APPINSIGHTS_INSTRUMENTATIONKEY" in raw_content:
            return RuleResult.PASSED

        if "APPLICATIONINSIGHTS_CONNECTION_STRING" in raw_content:
            return RuleResult.PASSED

        return RuleResult.FAILED


class FunctionAppPrivateEndpoint(BaseRule):
    """Check that Function App uses private endpoints."""

    id = "BCK_AZURE_FUNC_006"
    name = "Function App should use private endpoints"
    description = (
        "Private endpoints enable access to Function Apps through a private IP "
        "address within your VNet, eliminating exposure to the public internet."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Configure private endpoints and set 'publicNetworkAccess' to 'Disabled'."
    references = [
        "https://docs.microsoft.com/azure/azure-functions/functions-create-private-site-access",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for private endpoint configuration."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access == "Disabled":
            return RuleResult.PASSED

        return RuleResult.FAILED


class FunctionAppPublicNetworkDisabled(BaseRule):
    """Check that Function App has public network access disabled."""

    id = "BCK_AZURE_FUNC_007"
    name = "Function App should disable public network access"
    description = (
        "Disabling public network access ensures the Function App can only be "
        "accessed through private endpoints or VNet integration."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'publicNetworkAccess' to 'Disabled'."
    references = [
        "https://docs.microsoft.com/azure/azure-functions/functions-networking-options",
    ]

    cis_azure = ["9.8"]
    nist_800_53 = ["AC-3", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access not in ["Disabled", None]:
            if public_access == "Enabled":
                return RuleResult.FAILED

        return RuleResult.PASSED


class FunctionAppMinTLS(BaseRule):
    """Check that Function App uses minimum TLS 1.2."""

    id = "BCK_AZURE_FUNC_008"
    name = "Function App should use minimum TLS 1.2"
    description = (
        "Function App should require TLS 1.2 or higher to ensure secure "
        "communication and prevent downgrade attacks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'siteConfig.minTlsVersion' to '1.2' or higher."
    references = [
        "https://docs.microsoft.com/azure/app-service/configure-ssl-bindings",
    ]

    cis_azure = ["9.3"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS 1.2 is configured."""
        # Only check function apps
        kind = resource.properties.get("kind", "")
        if "functionapp" not in str(kind).lower():
            return RuleResult.PASSED

        min_tls = resource.get_property("properties.siteConfig.minTlsVersion")

        if min_tls is None or min_tls in ["1.0", "1.1"]:
            return RuleResult.FAILED

        return RuleResult.PASSED
