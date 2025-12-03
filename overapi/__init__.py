"""
OverApi - Universal API Security Scanner
A robust, modular tool for offensive and defensive API scanning.
"""

__version__ = "1.1.0"
__author__ = "Security Research Team"

from . import core, protocols, scanners, utils, reports, fuzzers, bypass, gui, payloads

__all__ = ["core", "protocols", "scanners", "utils", "reports", "fuzzers", "bypass", "gui", "payloads"]
