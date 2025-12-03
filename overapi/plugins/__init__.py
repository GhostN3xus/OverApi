"""
OverApi Enterprise - Plugin System
Extensible architecture for custom security tests
"""

from .manager import PluginManager
from .base import BasePlugin

__all__ = ['PluginManager', 'BasePlugin']
