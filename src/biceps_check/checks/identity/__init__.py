"""
Security checks for Azure Identity and Security resources.

This module contains security rules for:
- Key Vault (Microsoft.KeyVault/vaults)
- Managed Identity (Microsoft.ManagedIdentity/userAssignedIdentities)
- Role Assignments (Microsoft.Authorization/roleAssignments)
"""

from biceps_check.checks.identity.key_vault import *
