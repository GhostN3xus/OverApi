"""
OverApi - Universal API Security Scanner
A robust, modular tool for offensive and defensive API scanning.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"

from . import core, modules, scanner, utils, report

__all__ = ["core", "modules", "scanner", "utils", "report"]
