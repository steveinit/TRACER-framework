"""
MongoDB storage backend for TRACER framework
Provides async MongoDB integration with Atlas support
"""

import asyncio
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from .base import StorageInterface

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    AsyncIOMotorClient = None

class MongoStorage(StorageInterface):
    """MongoDB storage backend with Atlas support"""

    def __init__(self, mongodb_url: Optional[str] = None):
        if not MONGODB_AVAILABLE:
            raise ImportError("MongoDB dependencies not installed. Run: pip install motor pymongo")

        self.mongodb_url = mongodb_url or os.getenv("MONGODB_URL", "mongodb://localhost:27017")
        self.database_name = os.getenv("MONGODB_DATABASE", "tracer")
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        self._initialized = False

    def initialize_database(self) -> None:
        """Initialize MongoDB connection (sync wrapper for async)"""
        if not self._initialized:
            asyncio.run(self._async_initialize())

    async def _async_initialize(self) -> None:
        """Async MongoDB initialization"""
        try:
            self.client = AsyncIOMotorClient(self.mongodb_url)
            self.db = self.client[self.database_name]

            # Test connection
            await self.client.admin.command('ping')
            print(f"Connected to MongoDB: {self.database_name}")

            # Create indexes for better performance
            await self.db.cases.create_index("case_id", unique=True)
            await self.db.cases.create_index("timestamp")
            await self.db.logs.create_index([("case_id", 1), ("timestamp", 1)])

            self._initialized = True

        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            print("Falling back to JSON storage...")
            raise ConnectionError(f"MongoDB connection failed: {e}")

    def save_case(self, case_id: str, case_data: Dict[str, Any]) -> bool:
        """Save complete case data to MongoDB"""
        return asyncio.run(self._async_save_case(case_id, case_data))

    async def _async_save_case(self, case_id: str, case_data: Dict[str, Any]) -> bool:
        """Async case saving"""
        try:
            if not self._initialized:
                await self._async_initialize()

            document = {
                "case_id": case_id,
                "timestamp": datetime.now(),
                "data": case_data
            }

            await self.db.cases.replace_one(
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
        return asyncio.run(self._async_load_case(case_id))

    async def _async_load_case(self, case_id: str) -> Dict[str, Any]:
        """Async case loading"""
        try:
            if not self._initialized:
                await self._async_initialize()

            document = await self.db.cases.find_one({"case_id": case_id})
            return document["data"] if document else {}

        except Exception as e:
            print(f"Error loading case from MongoDB: {e}")
            return {}

    def list_cases(self) -> List[str]:
        """Get list of all case IDs from MongoDB"""
        return asyncio.run(self._async_list_cases())

    async def _async_list_cases(self) -> List[str]:
        """Async case listing"""
        try:
            if not self._initialized:
                await self._async_initialize()

            cursor = self.db.cases.find({}, {"case_id": 1})
            cases = await cursor.to_list(length=None)
            return [case["case_id"] for case in cases]

        except Exception as e:
            print(f"Error listing cases from MongoDB: {e}")
            return []

    def case_exists(self, case_id: str) -> bool:
        """Check if case exists in MongoDB"""
        return asyncio.run(self._async_case_exists(case_id))

    async def _async_case_exists(self, case_id: str) -> bool:
        """Async case existence check"""
        try:
            if not self._initialized:
                await self._async_initialize()

            count = await self.db.cases.count_documents({"case_id": case_id})
            return count > 0

        except Exception as e:
            print(f"Error checking case existence in MongoDB: {e}")
            return False

    def write_log_entry(self, log_filename: str, entry: Dict[str, Any]) -> bool:
        """Write log entry to MongoDB"""
        return asyncio.run(self._async_write_log_entry(log_filename, entry))

    async def _async_write_log_entry(self, log_filename: str, entry: Dict[str, Any]) -> bool:
        """Async log writing"""
        try:
            if not self._initialized:
                await self._async_initialize()

            # Extract case_id from log filename or entry
            case_id = entry.get("case_id", "unknown")

            log_document = {
                "case_id": case_id,
                "log_filename": log_filename,
                "timestamp": datetime.now(),
                "entry": entry
            }

            await self.db.logs.insert_one(log_document)
            return True

        except Exception as e:
            print(f"Error writing log to MongoDB: {e}")
            return False

    def close(self) -> None:
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self._initialized = False