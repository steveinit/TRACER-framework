"""
Storage factory for TRACER framework
Auto-detects and configures the appropriate storage backend
"""

import os
from typing import Optional
from .base import StorageInterface
from .json_storage import JsonStorage

def get_storage_backend(force_backend: Optional[str] = None) -> StorageInterface:
    """
    Auto-detect and return the appropriate storage backend

    Priority:
    1. force_backend parameter (for testing)
    2. MONGODB_URL environment variable (if set, use MongoDB)
    3. Default to JSON storage

    Args:
        force_backend: Force a specific backend ('json' or 'mongo')

    Returns:
        Configured storage backend instance
    """

    # Check for forced backend
    if force_backend:
        if force_backend.lower() == 'json':
            print("Using JSON storage (forced)")
            return JsonStorage()
        elif force_backend.lower() == 'mongo':
            print("Using MongoDB storage (forced)")
            return _get_mongo_storage()
        else:
            raise ValueError(f"Unknown storage backend: {force_backend}")

    # Check for MongoDB configuration
    mongodb_url = os.getenv("MONGODB_URL")
    storage_type = os.getenv("STORAGE_TYPE", "auto").lower()

    if storage_type == "mongo" or (storage_type == "auto" and mongodb_url):
        try:
            print(f"MongoDB URL detected: {mongodb_url[:20]}..." if mongodb_url else "Using default MongoDB URL")
            return _get_mongo_storage(mongodb_url)
        except Exception as e:
            print(f"Failed to initialize MongoDB storage: {e}")
            print("Falling back to JSON storage")
            return JsonStorage()

    # Default to JSON storage
    print("Using JSON storage (default)")
    return JsonStorage()

def _get_mongo_storage(mongodb_url: Optional[str] = None) -> StorageInterface:
    """Get MongoDB storage instance with error handling"""
    try:
        from .mongo_storage_sync import MongoStorageSync
        storage = MongoStorageSync(mongodb_url)
        # Test initialization
        storage.initialize_database()
        return storage
    except ImportError:
        raise ImportError(
            "MongoDB dependencies not installed. Install with: pip install pymongo"
        )
    except Exception as e:
        raise ConnectionError(f"Failed to connect to MongoDB: {e}")

def print_storage_info():
    """Print information about available storage options"""
    print("\n" + "="*50)
    print("TRACER Storage Configuration")
    print("="*50)

    mongodb_url = os.getenv("MONGODB_URL")
    storage_type = os.getenv("STORAGE_TYPE", "auto")

    print(f"Storage Type: {storage_type}")

    if mongodb_url:
        print(f"MongoDB URL: {mongodb_url[:30]}...")
        try:
            from .mongo_storage import MongoStorage
            print("MongoDB Support: Available")
        except ImportError:
            print("MongoDB Support: Not available (missing dependencies)")
    else:
        print("MongoDB URL: Not configured")

    print(f"JSON Storage: Available")
    print("="*50)

# Convenience function for backward compatibility
def create_storage() -> StorageInterface:
    """Create storage backend with auto-detection"""
    return get_storage_backend()