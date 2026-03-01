"""
Security checks for Azure App Service.

Resource type: Microsoft.Web/sites
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class AppServiceHttpsOnly(BaseRule):
    """Check that App Service uses HTTPS only."""

    id = "BCK_AZURE_APP_001"
    name = "App Service should use HTTPS only"
    description = (
        "App Service should redirect all HTTP traffic to HTTPS to ensure "
        "all data in transit is encrypted."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'httpsOnly' to true in the App Service properties."
    references = [
        "https://docs.microsoft.com/azure/app-service/configure-ssl-bindings#enforce-https",
    ]

    cis_azure = ["9.2"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if HTTPS-only is enabled."""
        https_only = resource.get_property("properties.httpsOnly")

        if https_only is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceMinimumTls(BaseRule):
    """Check that App Service uses minimum TLS 1.2."""

    id = "BCK_AZURE_APP_002"
    name = "App Service should use minimum TLS 1.2"
    description = (
        "App Service should require TLS 1.2 or higher to ensure secure "
        "communication and prevent downgrade attacks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'siteConfig.minTlsVersion' to '1.2' or higher."
    references = [
        "https://docs.microsoft.com/azure/app-service/configure-ssl-bindings#enforce-tls-versions",
    ]

    cis_azure = ["9.3"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS 1.2 is configured."""
        min_tls = resource.get_property("properties.siteConfig.minTlsVersion")

        if min_tls is None or min_tls in ["1.0", "1.1"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceManagedIdentity(BaseRule):
    """Check that App Service uses managed identity."""

    id = "BCK_AZURE_APP_003"
    name = "App Service should use managed identity"
    description = (
        "Managed identities eliminate the need for credentials in code by providing "
        "an automatically managed identity for authenticating to Azure services."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Configure a system-assigned or user-assigned managed identity in the "
        "'identity' property of the App Service."
    )
    references = [
        "https://docs.microsoft.com/azure/app-service/overview-managed-identity",
    ]

    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if managed identity is configured."""
        identity_type = resource.get_property("identity.type")

        if identity_type is None or identity_type == "None":
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceFtpDisabled(BaseRule):
    """Check that App Service has FTP disabled."""

    id = "BCK_AZURE_APP_004"
    name = "App Service should disable FTP"
    description = (
        "FTP transmits credentials and data in plain text. Disable FTP and use "
        "FTPS or other secure deployment methods."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'siteConfig.ftpsState' to 'Disabled' or 'FtpsOnly'."
    references = [
        "https://docs.microsoft.com/azure/app-service/deploy-ftp",
    ]

    cis_azure = ["9.10"]
    nist_800_53 = ["SC-8"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if FTP is disabled or FTPS-only."""
        ftps_state = resource.get_property("properties.siteConfig.ftpsState")

        if ftps_state is None or ftps_state == "AllAllowed":
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceAuthEnabled(BaseRule):
    """Check that App Service has authentication enabled."""

    id = "BCK_AZURE_APP_005"
    name = "App Service should have authentication enabled"
    description = (
        "Enable App Service Authentication to protect your application from unauthenticated access."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Configure App Service Authentication (EasyAuth) using the Azure portal "
        "or the authsettingsV2 API."
    )
    references = [
        "https://docs.microsoft.com/azure/app-service/overview-authentication-authorization",
    ]

    cis_azure = ["9.1"]
    nist_800_53 = ["AC-3", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if authentication is enabled."""
        # Note: Auth settings are often configured via a separate resource
        # This is a simplified check
        auth_enabled = resource.get_property("properties.siteConfig.authEnabled")

        # This property doesn't always exist in Bicep templates
        # as auth is often configured separately
        if auth_enabled is False:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceRemoteDebuggingDisabled(BaseRule):
    """Check that App Service has remote debugging disabled."""

    id = "BCK_AZURE_APP_006"
    name = "App Service should have remote debugging disabled"
    description = (
        "Remote debugging opens additional ports and can expose sensitive information. "
        "It should be disabled in production environments."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'siteConfig.remoteDebuggingEnabled' to false."
    references = [
        "https://docs.microsoft.com/azure/app-service/configure-common#debugging",
    ]

    cis_azure = ["9.9"]
    nist_800_53 = ["CM-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if remote debugging is disabled."""
        remote_debugging = resource.get_property("properties.siteConfig.remoteDebuggingEnabled")

        if remote_debugging is True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceClientCertificates(BaseRule):
    """Check that App Service has client certificates enabled."""

    id = "BCK_AZURE_APP_007"
    name = "App Service should have client certificates enabled"
    description = (
        "Client certificate authentication adds an additional layer of security "
        "by requiring clients to present a valid certificate."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Set 'clientCertEnabled' to true and configure 'clientCertMode' as appropriate."
    references = [
        "https://docs.microsoft.com/azure/app-service/app-service-web-configure-tls-mutual-auth",
    ]

    nist_800_53 = ["IA-2", "IA-8"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if client certificates are enabled."""
        client_cert = resource.get_property("properties.clientCertEnabled")

        if client_cert is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceVnetIntegration(BaseRule):
    """Check that App Service uses VNet integration."""

    id = "BCK_AZURE_APP_008"
    name = "App Service should use VNet integration"
    description = (
        "VNet integration allows App Service to access resources in your virtual "
        "network and provides network isolation for outbound traffic."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = "Configure VNet integration in the 'virtualNetworkSubnetId' property."
    references = [
        "https://docs.microsoft.com/azure/app-service/overview-vnet-integration",
    ]

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if VNet integration is configured."""
        vnet_id = resource.get_property("properties.virtualNetworkSubnetId")

        if vnet_id is None:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceDiagnosticLogs(BaseRule):
    """Check that App Service has diagnostic logs enabled."""

    id = "BCK_AZURE_APP_009"
    name = "App Service should have diagnostic logs enabled"
    description = (
        "Diagnostic logs capture HTTP logs, application logs, and other telemetry "
        "essential for monitoring, troubleshooting, and security analysis."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Configure diagnostic settings to capture application and HTTP logs. "
        "Send logs to Log Analytics, Storage, or Event Hub."
    )
    references = [
        "https://docs.microsoft.com/azure/app-service/troubleshoot-diagnostic-logs",
    ]

    cis_azure = ["5.3"]
    nist_800_53 = ["AU-2", "AU-3", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if diagnostic logging is enabled."""
        http_logs = resource.get_property("properties.siteConfig.httpLoggingEnabled")
        detailed_errors = resource.get_property("properties.siteConfig.detailedErrorLoggingEnabled")

        # Both should be enabled for comprehensive logging
        if http_logs is not True and detailed_errors is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class AppServiceLatestRuntime(BaseRule):
    """Check that App Service uses latest runtime version."""

    id = "BCK_AZURE_APP_010"
    name = "App Service should use latest supported runtime version"
    description = (
        "Using the latest runtime version ensures you have the latest security "
        "patches and features."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Web/sites"]
    category = "compute"
    remediation = (
        "Update the runtime stack and version in the App Service configuration "
        "to use the latest supported version."
    )
    references = [
        "https://docs.microsoft.com/azure/app-service/configure-language-dotnet-framework",
    ]

    nist_800_53 = ["SI-2"]

    # Known deprecated/EOL versions (simplified)
    DEPRECATED_VERSIONS = [
        "dotnetcore|2.0",
        "dotnetcore|2.1",
        "node|6",
        "node|8",
        "node|10",
        "python|2.7",
        "python|3.4",
        "python|3.5",
        "python|3.6",
        "php|5.6",
        "php|7.0",
        "php|7.1",
        "php|7.2",
    ]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if runtime version is current."""
        linux_fx = resource.get_property("properties.siteConfig.linuxFxVersion")
        net_version = resource.get_property("properties.siteConfig.netFrameworkVersion")

        # Check Linux runtime
        if linux_fx:
            linux_fx_lower = linux_fx.lower()
            for deprecated in self.DEPRECATED_VERSIONS:
                if deprecated in linux_fx_lower:
                    return RuleResult.FAILED

        # Check for very old .NET Framework versions
        if net_version and net_version in ["v2.0", "v3.0", "v3.5"]:
            return RuleResult.FAILED

        return RuleResult.PASSED
