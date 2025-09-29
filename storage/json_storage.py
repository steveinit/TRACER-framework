"""
JSON file storage implementation for TRACER framework
Maintains the current JSON-based storage behavior
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from .base import StorageInterface

class JsonStorage(StorageInterface):
    """JSON file-based storage backend for TRACER"""

    def __init__(self, db_filename: str = "tracer_database.json"):
        """
        Initialize JSON storage

        Args:
            db_filename: Name of the JSON database file
        """
        self.db_filename = db_filename

    def initialize_database(self) -> None:
        """Create JSON database file if it doesn't exist"""
        if not os.path.exists(self.db_filename):
            initial_db = {
                "cases": {},
                "metadata": {
                    "created": datetime.now().isoformat(),
                    "version": "1.0"
                }
            }
            with open(self.db_filename, 'w') as f:
                json.dump(initial_db, f, indent=2)
            print(f"Created new database: {self.db_filename}")
        else:
            print(f"Using existing database: {self.db_filename}")

    def save_case(self, case_id: str, case_data: Dict[str, Any]) -> bool:
        """Save complete case data to JSON database"""
        try:
            # Load existing database
            with open(self.db_filename, 'r') as f:
                db_data = json.load(f)

            # Add/update case data
            db_data["cases"][case_id] = case_data

            # Write back to file
            with open(self.db_filename, 'w') as f:
                json.dump(db_data, f, indent=2)

            return True

        except Exception as e:
            print(f"Warning: Could not save case to database: {e}")
            return False

    def load_case(self, case_id: str) -> Dict[str, Any]:
        """Load existing case data from JSON database"""
        case_data = {
            "initial_detection": {},
            "network_elements": {},
            "path_sequence": []
        }

        try:
            with open(self.db_filename, 'r') as f:
                db_data = json.load(f)

            if case_id in db_data.get("cases", {}):
                stored_case = db_data["cases"][case_id]
                case_data["initial_detection"] = stored_case.get("initial_detection", {})
                case_data["network_elements"] = stored_case.get("network_elements", {})
                case_data["path_sequence"] = stored_case.get("path_sequence", [])

        except Exception as e:
            print(f"Warning: Could not load existing case: {e}")

        return case_data

    def list_cases(self) -> List[str]:
        """Get list of all existing case IDs"""
        if not os.path.exists(self.db_filename):
            return []

        try:
            with open(self.db_filename, 'r') as f:
                db_data = json.load(f)
            return list(db_data.get("cases", {}).keys())
        except Exception as e:
            print(f"Warning: Could not read existing cases: {e}")
            return []

    def write_log_entry(self, log_filename: str, entry: Dict[str, Any]) -> bool:
        """Write a log entry to the specified JSON log file"""
        try:
            if os.path.exists(log_filename):
                with open(log_filename, 'r') as f:
                    log_data = json.load(f)
            else:
                log_data = {"tracer_log": []}

            log_data["tracer_log"].append(entry)

            with open(log_filename, 'w') as f:
                json.dump(log_data, f, indent=2)

            return True

        except Exception as e:
            print(f"Warning: Could not write to log file: {e}")
            return False

    def case_exists(self, case_id: str) -> bool:
        """Check if a case exists in the JSON database"""
        try:
            with open(self.db_filename, 'r') as f:
                db_data = json.load(f)
            return case_id in db_data.get("cases", {})
        except Exception:
            return False