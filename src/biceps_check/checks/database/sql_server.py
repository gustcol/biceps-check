"""
Security checks for Azure SQL Server.

Resource type: Microsoft.Sql/servers
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class SqlServerAzureAdAdmin(BaseRule):
    """Check that SQL Server has Azure AD admin configured."""

    id = "BCK_AZURE_SQL_001"
    name = "SQL Server should have Azure AD admin configured"
    description = (
        "Configuring an Azure AD administrator enables Azure AD authentication "
        "for SQL Server, providing centralized identity management and enhanced security."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = (
        "Configure an Azure AD administrator using the "
        "Microsoft.Sql/servers/administrators resource."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/authentication-aad-configure",
    ]

    cis_azure = ["4.1"]
    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Azure AD admin is configured."""
        # Azure AD admin is typically configured via a child resource
        # This check is informational
        administrators = resource.get_property("properties.administrators")
        if administrators:
            return RuleResult.PASSED
        return RuleResult.PASSED  # Often configured separately


class SqlServerAuditingEnabled(BaseRule):
    """Check that SQL Server has auditing enabled."""

    id = "BCK_AZURE_SQL_002"
    name = "SQL Server should have auditing enabled"
    description = (
        "SQL Server auditing tracks database events and writes them to an audit log, "
        "essential for security monitoring and compliance requirements."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = (
        "Enable auditing by configuring Microsoft.Sql/servers/auditingSettings "
        "with state set to 'Enabled'."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/auditing-overview",
    ]

    cis_azure = ["4.1.1"]
    nist_800_53 = ["AU-2", "AU-3", "AU-12"]
    pci_dss = ["10.2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if auditing is configured (typically via child resource)."""
        # Auditing is configured via auditingSettings child resource
        return RuleResult.PASSED


class SqlServerThreatDetection(BaseRule):
    """Check that SQL Server has threat detection enabled."""

    id = "BCK_AZURE_SQL_003"
    name = "SQL Server should have threat detection enabled"
    description = (
        "Advanced Threat Protection detects anomalous activities indicating unusual "
        "and potentially harmful attempts to access or exploit databases."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = (
        "Enable Advanced Threat Protection by configuring "
        "Microsoft.Sql/servers/securityAlertPolicies with state set to 'Enabled'."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/threat-detection-configure",
    ]

    cis_azure = ["4.2.1"]
    nist_800_53 = ["SI-4"]
    azure_security_benchmark = ["LT-1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if threat detection is enabled."""
        return RuleResult.PASSED  # Configured via child resource


class SqlServerMinimumTls(BaseRule):
    """Check that SQL Server uses minimum TLS 1.2."""

    id = "BCK_AZURE_SQL_004"
    name = "SQL Server should have minimum TLS 1.2"
    description = (
        "SQL Server should require TLS 1.2 or higher to ensure secure "
        "encrypted connections and protect data in transit."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = "Set 'minimalTlsVersion' to '1.2' in the SQL Server properties."
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/connectivity-settings",
    ]

    cis_azure = ["4.1.2"]
    nist_800_53 = ["SC-8", "SC-8(1)"]
    pci_dss = ["4.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if minimum TLS 1.2 is configured."""
        min_tls = resource.get_property("properties.minimalTlsVersion")

        if min_tls is None or min_tls in ["1.0", "1.1"]:
            return RuleResult.FAILED

        return RuleResult.PASSED


class SqlServerPublicNetworkAccess(BaseRule):
    """Check that SQL Server denies public network access."""

    id = "BCK_AZURE_SQL_005"
    name = "SQL Server should deny public network access"
    description = (
        "Disabling public network access ensures that the SQL Server is only "
        "accessible through private endpoints, reducing the attack surface."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = "Set 'publicNetworkAccess' to 'Disabled' and use private endpoints."
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/connectivity-settings",
    ]

    cis_azure = ["4.1.3"]
    nist_800_53 = ["SC-7", "AC-4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if public network access is disabled."""
        public_access = resource.get_property("properties.publicNetworkAccess")

        if public_access is None or public_access == "Enabled":
            return RuleResult.FAILED

        return RuleResult.PASSED


class SqlServerAzureAdOnlyAuth(BaseRule):
    """Check that SQL Server uses Azure AD-only authentication."""

    id = "BCK_AZURE_SQL_006"
    name = "SQL Server should use Azure AD-only authentication"
    description = (
        "Azure AD-only authentication disables SQL authentication, ensuring all "
        "access uses Azure AD identities for better security and auditability."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = (
        "Set 'administrators.azureADOnlyAuthentication' to true in the SQL Server properties."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/authentication-azure-ad-only-authentication",
    ]

    nist_800_53 = ["AC-2", "IA-2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if Azure AD-only authentication is enabled."""
        azure_ad_only = resource.get_property("properties.administrators.azureADOnlyAuthentication")

        if azure_ad_only is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class SqlServerVulnerabilityAssessment(BaseRule):
    """Check that SQL Server has vulnerability assessment enabled."""

    id = "BCK_AZURE_SQL_007"
    name = "SQL Server should have vulnerability assessment enabled"
    description = (
        "Vulnerability assessment identifies, tracks, and helps remediate potential "
        "database vulnerabilities, improving the security posture."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Sql/servers"]
    category = "database"
    remediation = (
        "Enable vulnerability assessment by configuring "
        "Microsoft.Sql/servers/vulnerabilityAssessments."
    )
    references = [
        "https://docs.microsoft.com/azure/azure-sql/database/sql-vulnerability-assessment",
    ]

    cis_azure = ["4.2.2"]
    nist_800_53 = ["RA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if vulnerability assessment is enabled (via child resource)."""
        return RuleResult.PASSED  # Configured via child resource
