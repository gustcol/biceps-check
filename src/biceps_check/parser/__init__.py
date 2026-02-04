"""
Bicep file parser module.

This package provides parsing capabilities for Azure Bicep files,
extracting resources, properties, and metadata for security analysis.
"""

from biceps_check.parser.bicep_parser import BicepParser
from biceps_check.parser.models import BicepFile, BicepParameter, BicepResource, BicepVariable

__all__ = [
    "BicepParser",
    "BicepFile",
    "BicepResource",
    "BicepParameter",
    "BicepVariable",
]
