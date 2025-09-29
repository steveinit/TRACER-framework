"""
TRACER Storage Layer
Provides abstraction for different storage backends (JSON, MongoDB, etc.)
"""

from .base import StorageInterface
from .json_storage import JsonStorage

__all__ = ['StorageInterface', 'JsonStorage']