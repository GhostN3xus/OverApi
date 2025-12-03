"""
GUI module for OverApi - graphical user interface components.

This module provides the Tkinter-based GUI for interacting with OverApi
in a user-friendly way.
"""

try:
    from overapi.gui.tkinter_app import TkinterApp
    __all__ = ['TkinterApp']
except ImportError:
    # Tkinter not available on this system
    __all__ = []
