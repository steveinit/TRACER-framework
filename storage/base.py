"""
Base storage interface for TRACER framework
Defines the contract that all storage backends must implement
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

class StorageInterface(ABC):
    """Abstract base class defining storage operations for TRACER"""

    @abstractmethod
    def initialize_database(self) -> None:
        """Initialize the storage backend (create files, connections, etc.)"""
        pass

    @abstractmethod
    def save_case(self, case_id: str, case_data: Dict[str, Any]) -> bool:
        """
        Save complete case data to storage

        Args:
            case_id: Unique identifier for the case
            case_data: Complete case analysis data

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def load_case(self, case_id: str) -> Dict[str, Any]:
        """
        Load existing case data from storage

        Args:
            case_id: Unique identifier for the case

        Returns:
            Case data dictionary, or empty dict if not found
        """
        pass

    @abstractmethod
    def list_cases(self) -> List[str]:
        """
        Get list of all existing case IDs

        Returns:
            List of case ID strings
        """
        pass

    @abstractmethod
    def write_log_entry(self, log_filename: str, entry: Dict[str, Any]) -> bool:
        """
        Write a log entry to the specified log file

        Args:
            log_filename: Name of the log file
            entry: Log entry data to write

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def case_exists(self, case_id: str) -> bool:
        """
        Check if a case exists in storage

        Args:
            case_id: Unique identifier for the case

        Returns:
            True if case exists, False otherwise
        """
        pass