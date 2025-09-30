"""
Synchronous MongoDB storage backend for TRACER framework
Thread-safe implementation that works with both CLI and FastAPI
"""

import os
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from .base import StorageInterface

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, OperationFailure
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    MongoClient = None

class MongoStorageSync(StorageInterface):
    """Thread-safe synchronous MongoDB storage backend"""

    def __init__(self, mongodb_url: Optional[str] = None):
        if not MONGODB_AVAILABLE:
            raise ImportError("MongoDB dependencies not installed. Run: pip install pymongo")

        self.mongodb_url = mongodb_url or os.getenv("MONGODB_URL", "mongodb://localhost:27017")
        self.database_name = os.getenv("MONGODB_DATABASE", "tracer")
        self.client: Optional[MongoClient] = None
        self.db = None
        self._initialized = False
        self._lock = threading.Lock()

    def initialize_database(self) -> None:
        """Initialize MongoDB connection with thread safety"""
        with self._lock:
            if self._initialized:
                return

            try:
                # Create client with shorter timeout for faster failover
                self.client = MongoClient(
                    self.mongodb_url,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=5000
                )
                self.db = self.client[self.database_name]

                # Test connection
                self.client.admin.command('ping')
                print(f"Connected to MongoDB: {self.database_name}")

                # Create indexes for better performance
                try:
                    self.db.cases.create_index("case_id", unique=True)
                    self.db.cases.create_index("timestamp")
                    self.db.logs.create_index([("case_id", 1), ("timestamp", 1)])
                except Exception as e:
                    print(f"Warning: Could not create indexes: {e}")

                self._initialized = True

            except Exception as e:
                print(f"Failed to connect to MongoDB: {e}")
                print("Falling back to JSON storage...")
                if self.client:
                    self.client.close()
                    self.client = None
                raise ConnectionError(f"MongoDB connection failed: {e}")

    def save_case(self, case_id: str, case_data: Dict[str, Any]) -> bool:
        """Save complete case data to MongoDB"""
        try:
            if not self._initialized:
                self.initialize_database()

            document = {
                "case_id": case_id,
                "timestamp": datetime.now(),
                "data": case_data
            }

            with self._lock:
                self.db.cases.replace_one(
                    {"case_id": case_id},
                    document,
                    upsert=True
                )
            return True

        except Exception as e:
            print(f"Error saving case to MongoDB: {e}")
            return False

    def load_case(self, case_id: str) -> Dict[str, Any]:
        """Load existing case data from MongoDB"""
        try:
            if not self._initialized:
                self.initialize_database()

            with self._lock:
                document = self.db.cases.find_one({"case_id": case_id})
            return document["data"] if document else {}

        except Exception as e:
            print(f"Error loading case from MongoDB: {e}")
            return {}

    def list_cases(self) -> List[str]:
        """Get list of all case IDs from MongoDB"""
        try:
            if not self._initialized:
                self.initialize_database()

            with self._lock:
                cursor = self.db.cases.find({}, {"case_id": 1})
                cases = list(cursor)
            return [case["case_id"] for case in cases]

        except Exception as e:
            print(f"Error listing cases from MongoDB: {e}")
            return []

    def case_exists(self, case_id: str) -> bool:
        """Check if case exists in MongoDB"""
        try:
            if not self._initialized:
                self.initialize_database()

            with self._lock:
                count = self.db.cases.count_documents({"case_id": case_id})
            return count > 0

        except Exception as e:
            print(f"Error checking case existence in MongoDB: {e}")
            return False

    def write_log_entry(self, log_filename: str, entry: Dict[str, Any]) -> bool:
        """Write log entry to MongoDB"""
        try:
            if not self._initialized:
                self.initialize_database()

            # Extract case_id from log filename or entry
            case_id = entry.get("case_id", "unknown")

            log_document = {
                "case_id": case_id,
                "log_filename": log_filename,
                "timestamp": datetime.now(),
                "entry": entry
            }

            with self._lock:
                self.db.logs.insert_one(log_document)
            return True

        except Exception as e:
            print(f"Error writing log to MongoDB: {e}")
            return False

    def close(self) -> None:
        """Close MongoDB connection"""
        with self._lock:
            if self.client:
                self.client.close()
                self.client = None
                self._initialized = False