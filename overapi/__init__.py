"""
OverApi - Universal API Security Scanner
A robust, modular tool for offensive and defensive API scanning.
"""

__version__ = "2.0.0"
__version_info__ = (2, 0, 0)
__edition__ = "Enterprise"
__author__ = "GhostN3xus & OverApi Team"
__email__ = "security@overapi.dev"
__license__ = "MIT"
__url__ = "https://github.com/GhostN3xus/OverApi"

from . import core, protocols, scanners, utils, reports, fuzzers, bypass, payloads

__all__ = ["core", "protocols", "scanners", "utils", "reports", "fuzzers", "bypass", "payloads"]
