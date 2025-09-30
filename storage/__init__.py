"""
TRACER Storage Layer
Provides abstraction for different storage backends (JSON, MongoDB, etc.)
"""

from .base import StorageInterface
from .json_storage import JsonStorage
from .factory import get_storage_backend, create_storage, print_storage_info

# Try to import MongoDB storage (optional)
try:
    from .mongo_storage_sync import MongoStorageSync
    MONGODB_AVAILABLE = True
    __all__ = ['StorageInterface', 'JsonStorage', 'MongoStorageSync', 'get_storage_backend', 'create_storage', 'print_storage_info']
except ImportError:
    MONGODB_AVAILABLE = False
    __all__ = ['StorageInterface', 'JsonStorage', 'get_storage_backend', 'create_storage', 'print_storage_info']