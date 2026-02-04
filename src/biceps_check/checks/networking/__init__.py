"""
Security checks for Azure Networking resources.

This module contains security rules for:
- Network Security Groups (Microsoft.Network/networkSecurityGroups)
- Virtual Networks (Microsoft.Network/virtualNetworks)
- Application Gateway (Microsoft.Network/applicationGateways)
- Azure Firewall (Microsoft.Network/azureFirewalls)
- Load Balancers (Microsoft.Network/loadBalancers)
"""

from biceps_check.checks.networking.nsg import *
