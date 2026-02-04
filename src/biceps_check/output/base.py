"""
Base formatter class for output formatting.

This module defines the abstract base class for all output formatters.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from biceps_check.runner import ScanResults


class BaseFormatter(ABC):
    """Abstract base class for output formatters."""

    @abstractmethod
    def format(self, results: "ScanResults") -> str:
        """Format scan results into the target format.

        Args:
            results: The scan results to format.

        Returns:
            Formatted string output.
        """
