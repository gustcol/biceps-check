"""
Security checks for Azure Virtual Machines.

Resource type: Microsoft.Compute/virtualMachines
"""

from __future__ import annotations

from biceps_check.parser.models import BicepResource
from biceps_check.rules.base import BaseRule, RuleResult, Severity


class VMDiskEncryption(BaseRule):
    """Check that VM has disk encryption enabled."""

    id = "BCK_AZURE_VM_001"
    name = "VM should have managed disks with encryption enabled"
    description = (
        "Virtual machines should use managed disks with encryption enabled "
        "to protect data at rest. Azure Disk Encryption uses BitLocker (Windows) "
        "or dm-crypt (Linux) to encrypt OS and data disks."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "Enable Azure Disk Encryption or use encryption at host by setting "
        "'securityProfile.encryptionAtHost' to true."
    )
    references = [
        "https://docs.microsoft.com/azure/virtual-machines/disk-encryption-overview",
    ]

    cis_azure = ["7.2"]
    nist_800_53 = ["SC-28", "SC-28(1)"]
    pci_dss = ["3.4"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if disk encryption is enabled."""
        encryption_at_host = resource.get_property("properties.securityProfile.encryptionAtHost")

        if encryption_at_host is True:
            return RuleResult.PASSED

        # Check for managed disk encryption settings
        os_disk_encryption = resource.get_property(
            "properties.storageProfile.osDisk.encryptionSettings.enabled"
        )
        if os_disk_encryption is True:
            return RuleResult.PASSED

        return RuleResult.FAILED


class VMNoPublicIP(BaseRule):
    """Check that VM does not have a public IP directly attached."""

    id = "BCK_AZURE_VM_002"
    name = "VM should not have public IP directly attached"
    description = (
        "Virtual machines should not have public IP addresses directly attached. "
        "Use Azure Bastion, VPN Gateway, or a jump box for secure remote access."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "Remove direct public IP association from the VM. Use Azure Bastion "
        "or other secure access methods instead."
    )
    references = [
        "https://docs.microsoft.com/azure/bastion/bastion-overview",
    ]

    cis_azure = ["7.1"]
    nist_800_53 = ["AC-17", "SC-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if VM has public IP."""
        network_interfaces = resource.get_property("properties.networkProfile.networkInterfaces")

        if not network_interfaces:
            return RuleResult.PASSED

        # This is a simplified check - in practice, you'd need to
        # resolve the NIC reference to check for public IP
        # For now, check if publicIPAddress is referenced
        raw_content = resource.raw_content or ""
        if "publicIPAddress" in raw_content.lower():
            return RuleResult.FAILED

        return RuleResult.PASSED


class VMManagedIdentity(BaseRule):
    """Check that VM uses managed identity."""

    id = "BCK_AZURE_VM_003"
    name = "VM should use managed identity"
    description = (
        "Virtual machines should use managed identities for authenticating "
        "to Azure services without storing credentials in code or configuration."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "Configure a system-assigned or user-assigned managed identity in the "
        "'identity' property of the VM."
    )
    references = [
        "https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/",
    ]

    nist_800_53 = ["IA-2", "IA-5"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if managed identity is configured."""
        identity_type = resource.get_property("identity.type")

        if identity_type is None or identity_type == "None":
            return RuleResult.FAILED

        return RuleResult.PASSED


class VMBootDiagnostics(BaseRule):
    """Check that VM has boot diagnostics enabled."""

    id = "BCK_AZURE_VM_004"
    name = "VM should have boot diagnostics enabled"
    description = (
        "Boot diagnostics should be enabled to capture serial console output "
        "and screenshots during VM boot for troubleshooting and auditing."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = "Enable boot diagnostics in 'diagnosticsProfile.bootDiagnostics.enabled'."
    references = [
        "https://docs.microsoft.com/azure/virtual-machines/boot-diagnostics",
    ]

    cis_azure = ["7.4"]
    nist_800_53 = ["AU-2", "AU-12"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if boot diagnostics is enabled."""
        boot_diag = resource.get_property("properties.diagnosticsProfile.bootDiagnostics.enabled")

        if boot_diag is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class VMAutoUpdates(BaseRule):
    """Check that VM has automatic OS updates enabled."""

    id = "BCK_AZURE_VM_005"
    name = "VM should have automatic OS updates enabled"
    description = (
        "Virtual machines should have automatic OS updates enabled to ensure "
        "security patches are applied promptly."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "For Windows VMs, set 'osProfile.windowsConfiguration.enableAutomaticUpdates' "
        "to true. For Linux, configure Update Management or unattended-upgrades."
    )
    references = [
        "https://docs.microsoft.com/azure/automation/update-management/overview",
    ]

    cis_azure = ["7.3"]
    nist_800_53 = ["SI-2", "SI-3"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if automatic updates is enabled."""
        # Windows VM check
        windows_auto_updates = resource.get_property(
            "properties.osProfile.windowsConfiguration.enableAutomaticUpdates"
        )
        if windows_auto_updates is True:
            return RuleResult.PASSED

        # Check for patch mode automatic
        linux_patch_mode = resource.get_property(
            "properties.osProfile.linuxConfiguration.patchSettings.patchMode"
        )
        if linux_patch_mode == "AutomaticByPlatform":
            return RuleResult.PASSED

        windows_patch_mode = resource.get_property(
            "properties.osProfile.windowsConfiguration.patchSettings.patchMode"
        )
        if windows_patch_mode == "AutomaticByPlatform":
            return RuleResult.PASSED

        return RuleResult.FAILED


class VMSecureBoot(BaseRule):
    """Check that VM has secure boot enabled (Gen2 VMs)."""

    id = "BCK_AZURE_VM_006"
    name = "VM should have secure boot enabled"
    description = (
        "Generation 2 VMs should have secure boot enabled to protect against "
        "boot-level malware and unauthorized boot loaders."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "Set 'securityProfile.securityType' to 'TrustedLaunch' and "
        "'securityProfile.uefiSettings.secureBootEnabled' to true."
    )
    references = [
        "https://docs.microsoft.com/azure/virtual-machines/trusted-launch",
    ]

    nist_800_53 = ["SI-7"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if secure boot is enabled."""
        security_type = resource.get_property("properties.securityProfile.securityType")
        secure_boot = resource.get_property(
            "properties.securityProfile.uefiSettings.secureBootEnabled"
        )

        if security_type == "TrustedLaunch" and secure_boot is True:
            return RuleResult.PASSED

        # Check for Confidential VM
        if security_type == "ConfidentialVM":
            return RuleResult.PASSED

        return RuleResult.FAILED


class VMvTPM(BaseRule):
    """Check that VM has vTPM enabled (Gen2 VMs)."""

    id = "BCK_AZURE_VM_007"
    name = "VM should have vTPM enabled"
    description = (
        "Generation 2 VMs should have virtual Trusted Platform Module (vTPM) "
        "enabled for hardware-based security features like BitLocker and attestation."
    )
    severity = Severity.MEDIUM
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = "Set 'securityProfile.uefiSettings.vTpmEnabled' to true with TrustedLaunch."
    references = [
        "https://docs.microsoft.com/azure/virtual-machines/trusted-launch",
    ]

    nist_800_53 = ["SC-13"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if vTPM is enabled."""
        vtpm = resource.get_property("properties.securityProfile.uefiSettings.vTpmEnabled")

        if vtpm is not True:
            return RuleResult.FAILED

        return RuleResult.PASSED


class VMEndpointProtection(BaseRule):
    """Check that VM has endpoint protection configured."""

    id = "BCK_AZURE_VM_008"
    name = "VM should have endpoint protection configured"
    description = (
        "Virtual machines should have antimalware/endpoint protection solutions "
        "installed to protect against malware and threats."
    )
    severity = Severity.HIGH
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "Install Microsoft Antimalware extension or a third-party endpoint "
        "protection solution via VM extensions."
    )
    references = [
        "https://docs.microsoft.com/azure/security/fundamentals/antimalware",
    ]

    cis_azure = ["7.5"]
    nist_800_53 = ["SI-3"]
    pci_dss = ["5.1", "5.2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check for endpoint protection extension."""
        # Check raw content for antimalware extension reference
        raw_content = resource.raw_content or ""
        antimalware_indicators = [
            "iaasantimalware",
            "antimalware",
            "endpointprotection",
            "microsoftmonitoringagent",
            "mde.",  # Microsoft Defender for Endpoint
        ]

        content_lower = raw_content.lower()
        for indicator in antimalware_indicators:
            if indicator in content_lower:
                return RuleResult.PASSED

        return RuleResult.FAILED


class VMAdminPasswordComplexity(BaseRule):
    """Check that VM admin password meets complexity requirements."""

    id = "BCK_AZURE_VM_009"
    name = "VM should not use simple admin credentials"
    description = (
        "Virtual machine admin accounts should use strong authentication. "
        "Avoid hardcoded passwords and prefer SSH keys for Linux VMs."
    )
    severity = Severity.CRITICAL
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "For Linux VMs, use SSH keys by setting 'disablePasswordAuthentication' to true. "
        "For Windows VMs, use Azure Key Vault to store admin passwords."
    )
    references = [
        "https://docs.microsoft.com/azure/virtual-machines/linux/create-ssh-keys-detailed",
    ]

    cis_azure = ["7.6"]
    nist_800_53 = ["IA-5", "IA-5(1)"]
    pci_dss = ["8.2"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check admin credential configuration."""
        # Check if password auth is disabled for Linux
        disable_password = resource.get_property(
            "properties.osProfile.linuxConfiguration.disablePasswordAuthentication"
        )
        if disable_password is True:
            return RuleResult.PASSED

        # Check for SSH key configuration
        ssh_keys = resource.get_property("properties.osProfile.linuxConfiguration.ssh.publicKeys")
        if ssh_keys:
            return RuleResult.PASSED

        # Check if admin password is hardcoded (bad practice)
        raw_content = resource.raw_content or ""
        if "adminPassword:" in raw_content and "'" in raw_content:
            # Hardcoded password detected
            return RuleResult.FAILED

        return RuleResult.PASSED


class VMGuestAgent(BaseRule):
    """Check that VM has guest agent provisioning enabled."""

    id = "BCK_AZURE_VM_010"
    name = "VM should have guest agent enabled"
    description = (
        "Virtual machines should have the guest agent enabled to support "
        "VM extensions, monitoring, and management capabilities."
    )
    severity = Severity.LOW
    resource_types = ["Microsoft.Compute/virtualMachines"]
    category = "compute"
    remediation = (
        "Ensure 'osProfile.allowExtensionOperations' is set to true "
        "(default is true if not specified)."
    )
    references = [
        "https://docs.microsoft.com/azure/virtual-machines/extensions/agent-windows",
    ]

    nist_800_53 = ["CM-6"]

    def check(self, resource: BicepResource) -> RuleResult:
        """Check if guest agent is enabled."""
        allow_extensions = resource.get_property("properties.osProfile.allowExtensionOperations")

        # Default is true if not specified
        if allow_extensions is False:
            return RuleResult.FAILED

        return RuleResult.PASSED
