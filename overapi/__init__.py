"""
OverApi - Universal API Security Scanner
A robust, modular tool for offensive and defensive API scanning.
"""

from ._version import __version__, __version_info__, __author__, __email__, __license__, __url__

from . import core, protocols, scanners, utils, reports, fuzzers, bypass, gui, payloads

__all__ = ["core", "protocols", "scanners", "utils", "reports", "fuzzers", "bypass", "gui", "payloads"]
