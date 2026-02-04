"""
Security checks for Azure Integration resources.

This module contains security rules for:
- API Management (Microsoft.ApiManagement/service)
- Logic Apps (Microsoft.Logic/workflows)
- Data Factory (Microsoft.DataFactory/factories)
"""

from biceps_check.checks.integration.data_factory import *
