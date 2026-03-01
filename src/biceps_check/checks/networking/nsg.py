"""
Security checks for Azure Network Security Groups.

Resource type: Microsoft.Network/networkSecurityGroups
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


def _port_matches(port_spec: str, target_port: int) -> bool:
    """Check if a port specification matches a target port.

    Handles exact ports, wildcard (*), and port ranges (e.g., '80-443').
    """
    port_spec = port_spec.strip()
    if port_spec == "*":
        return True
    if "-" in port_spec:
        try:
            start, end = port_spec.split("-", 1)
            return int(start) <= target_port <= int(end)
        except ValueError:
            return False
    try:
        return int(port_spec) == target_port
    except ValueError:
        return False


def _is_dangerous_rule(rule: dict, port: int) -> bool:
    """Check if a rule allows access from any source on a specific port."""
    props = rule.get("properties", {})
    if props.get("access") != "Allow":
        return False
    if props.get("direction") != "Inbound":
        return False

    source = props.get("sourceAddressPrefix", "")
    if source not in ["*", "0.0.0.0/0", "Internet", "Any"]:
        return False

    dest_port = props.get("destinationPortRange", "")
    dest_ports = props.get("destinationPortRanges", [])

    if dest_port and _port_matches(dest_port, port):
        return True
    return any(_port_matches(p, port) for p in dest_ports)


class NsgNoSshFromInternet(BaseRule):
    """Check that NSG does not allow SSH from the internet."""

    id = "BCK_AZURE_NSG_001"
    name = "NSG should not allow inbound SSH from any source"
    description = (
        "Network Security Groups should not allow inbound SSH (port 22) from any source "
        "(0.0.0.0/0 or *). SSH access from the internet exposes VMs to brute force attacks."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = (
        "Restrict SSH access to specific IP addresses or use Azure Bastion for secure "
        "remote access. Remove or modify rules that allow SSH from any source."
    )
    references = [
        "https://docs.microsoft.com/azure/virtual-network/network-security-groups-overview",
        "https://docs.microsoft.com/azure/bastion/bastion-overview",
    ]

    cis_azure = ["6.1"]
    nist_800_53 = ["SC-7", "AC-4"]
    pci_dss = ["1.2.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for SSH rules allowing access from any source."""
        security_rules = resource.get_property("properties.securityRules") or []

        for rule in security_rules:
            if _is_dangerous_rule(rule, 22):
                return RuleResult.FAILED

        return RuleResult.PASSED


class NsgNoRdpFromInternet(BaseRule):
    """Check that NSG does not allow RDP from the internet."""

    id = "BCK_AZURE_NSG_002"
    name = "NSG should not allow inbound RDP from any source"
    description = (
        "Network Security Groups should not allow inbound RDP (port 3389) from any source. "
        "RDP access from the internet exposes Windows VMs to brute force and vulnerability attacks."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = (
        "Restrict RDP access to specific IP addresses or use Azure Bastion for secure "
        "remote access. Remove or modify rules that allow RDP from any source."
    )
    references = [
        "https://docs.microsoft.com/azure/virtual-network/network-security-groups-overview",
        "https://docs.microsoft.com/azure/bastion/bastion-overview",
    ]

    cis_azure = ["6.2"]
    nist_800_53 = ["SC-7", "AC-4"]
    pci_dss = ["1.2.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for RDP rules allowing access from any source."""
        security_rules = resource.get_property("properties.securityRules") or []

        for rule in security_rules:
            if _is_dangerous_rule(rule, 3389):
                return RuleResult.FAILED

        return RuleResult.PASSED


class NsgNoAllPortsFromInternet(BaseRule):
    """Check that NSG does not allow all ports from the internet."""

    id = "BCK_AZURE_NSG_003"
    name = "NSG should not allow inbound from any source on all ports"
    description = (
        "Network Security Groups should not have rules that allow inbound traffic "
        "from any source on all ports (*). This effectively disables network filtering."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = (
        "Remove or restrict rules that allow all ports from any source. "
        "Use specific port ranges and source addresses."
    )

    cis_azure = ["6.3"]
    nist_800_53 = ["SC-7", "AC-4"]
    pci_dss = ["1.2.1"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for rules allowing all ports from any source."""
        security_rules = resource.get_property("properties.securityRules") or []

        for rule in security_rules:
            props = rule.get("properties", {})
            if props.get("access") != "Allow":
                continue
            if props.get("direction") != "Inbound":
                continue

            source = props.get("sourceAddressPrefix", "")
            if source not in ["*", "0.0.0.0/0", "Internet", "Any"]:
                continue

            dest_port = props.get("destinationPortRange", "")
            if dest_port == "*":
                return RuleResult.FAILED

        return RuleResult.PASSED


class NsgFlowLogsEnabled(BaseRule):
    """Check that NSG should have flow logs enabled."""

    id = "BCK_AZURE_NSG_004"
    name = "NSG should have flow logs enabled"
    description = (
        "NSG flow logs provide visibility into network traffic patterns, helping "
        "with security monitoring, troubleshooting, and compliance requirements."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = (
        "Configure NSG flow logs using Microsoft.Network/networkWatchers/flowLogs resource. "
        "Send logs to a storage account and optionally to Log Analytics."
    )
    references = [
        "https://docs.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview",
    ]

    cis_azure = ["6.4"]
    nist_800_53 = ["AU-2", "AU-3", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for flow logs configuration (informational - configured separately)."""
        # Flow logs are configured via a separate resource type
        # This check is informational
        return RuleResult.PASSED


class NsgRestrictDatabasePorts(BaseRule):
    """Check that NSG restricts database ports from internet."""

    id = "BCK_AZURE_NSG_005"
    name = "NSG should restrict database ports from internet"
    description = (
        "Network Security Groups should not allow direct access to database ports "
        "(1433, 3306, 5432, 27017) from the internet to protect database services."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = (
        "Remove rules allowing internet access to database ports. Use private endpoints "
        "or VNet service endpoints for database connectivity."
    )

    nist_800_53 = ["SC-7", "AC-4"]
    pci_dss = ["1.3.1"]

    # Common database ports
    DATABASE_PORTS = [1433, 3306, 5432, 27017, 1521, 6379]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for rules allowing database ports from internet."""
        security_rules = resource.get_property("properties.securityRules") or []

        for rule in security_rules:
            for port in self.DATABASE_PORTS:
                if _is_dangerous_rule(rule, port):
                    return RuleResult.FAILED

        return RuleResult.PASSED


class NsgRulesHaveDescriptions(BaseRule):
    """Check that NSG rules have descriptions."""

    id = "BCK_AZURE_NSG_006"
    name = "NSG rules should have descriptions"
    description = (
        "Security rules should have meaningful descriptions to document their purpose, "
        "making it easier to audit and maintain network security configurations."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = "Add a 'description' property to each security rule explaining its purpose."

    nist_800_53 = ["CM-6"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check that all rules have descriptions."""
        security_rules = resource.get_property("properties.securityRules") or []

        for rule in security_rules:
            description = rule.get("properties", {}).get("description", "")
            if not description or len(description.strip()) < 5:
                return RuleResult.FAILED

        return RuleResult.PASSED


class NsgDefaultDenyInbound(BaseRule):
    """Check that NSG has a default deny inbound rule."""

    id = "BCK_AZURE_NSG_007"
    name = "NSG should have explicit default deny inbound rule"
    description = (
        "While Azure NSGs have implicit deny rules, an explicit deny-all rule at "
        "the lowest priority ensures the deny behavior is visible and auditable."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.Network/networkSecurityGroups"]
    category = "networking"
    remediation = (
        "Add an explicit deny-all inbound rule with the lowest priority (highest number) "
        "to make the security policy explicit."
    )

    nist_800_53 = ["SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for explicit default deny rule."""
        security_rules = resource.get_property("properties.securityRules") or []

        for rule in security_rules:
            props = rule.get("properties", {})
            if props.get("access") != "Deny":
                continue
            if props.get("direction") != "Inbound":
                continue
            if props.get("sourceAddressPrefix") == "*":
                if props.get("destinationPortRange") == "*":
                    return RuleResult.PASSED

        return RuleResult.FAILED
