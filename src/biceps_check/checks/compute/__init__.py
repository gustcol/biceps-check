"""
Security checks for Azure Compute resources.

This module contains security rules for:
- App Service (Microsoft.Web/sites)
- Functions (Microsoft.Web/sites kind: functionapp)
- Virtual Machines (Microsoft.Compute/virtualMachines)
- VM Scale Sets (Microsoft.Compute/virtualMachineScaleSets)
- AKS (Microsoft.ContainerService/managedClusters)
- ACR (Microsoft.ContainerRegistry/registries)
- Container Instances (Microsoft.ContainerInstance/containerGroups)
"""

from biceps_check.checks.compute.aks import *
from biceps_check.checks.compute.app_service import *
from biceps_check.checks.compute.azure_functions import *
from biceps_check.checks.compute.container_registry import *
from biceps_check.checks.compute.virtual_machine import *
