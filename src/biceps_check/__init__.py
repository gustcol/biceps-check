"""
Biceps-Check: A comprehensive security scanning tool for Azure Bicep templates.

This package provides static analysis capabilities for Azure Bicep files,
detecting security misconfigurations, compliance violations, and best practice
deviations before deployment.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from biceps_check.rules.base import BaseRule, RuleResult, Severity
from biceps_check.runner import BicepsCheckRunner

__all__ = [
    "__version__",
    "BicepsCheckRunner",
    "BaseRule",
    "RuleResult",
    "Severity",
]
