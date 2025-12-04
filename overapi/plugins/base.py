"""
Plugin System for OverApi
Base classes and plugin loader for extensibility
"""

import importlib
import inspect
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Type
import logging


logger = logging.getLogger(__name__)


class VulnerabilityPlugin(ABC):
    """
    Base class for vulnerability detection plugins.

    All custom vulnerability scanners should inherit from this class
    and implement the detect() method.
    """

    def __init__(self, config=None, logger=None):
        """
        Initialize plugin.

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.author = "Unknown"
        self.description = "No description"
        self.enabled = True

    @abstractmethod
    def detect(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in an endpoint.

        Args:
            endpoint: Dictionary containing endpoint information:
                - url: str - The endpoint URL
                - method: str - HTTP method (GET, POST, etc.)
                - params: dict - Query parameters
                - headers: dict - Request headers
                - data: dict - Request body data

        Returns:
            List of vulnerability dictionaries:
                - type: str - Vulnerability type
                - severity: str - CRITICAL, HIGH, MEDIUM, LOW, INFO
                - endpoint: str - Affected endpoint
                - method: str - HTTP method
                - description: str - Detailed description
                - evidence: str - Proof of vulnerability
                - remediation: str - How to fix
                - cwe: str - CWE identifier
                - owasp: str - OWASP category
        """
        pass

    def get_info(self) -> Dict[str, str]:
        """Get plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'enabled': self.enabled
        }

    def enable(self):
        """Enable the plugin."""
        self.enabled = True
        self.logger.info(f"Plugin {self.name} enabled")

    def disable(self):
        """Disable the plugin."""
        self.enabled = False
        self.logger.info(f"Plugin {self.name} disabled")


class ProtocolPlugin(ABC):
    """
    Base class for protocol handler plugins.

    Use this to add support for new API protocols.
    """

    def __init__(self, config=None, logger=None):
        """Initialize protocol plugin."""
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.name = self.__class__.__name__
        self.protocol_name = "unknown"
        self.enabled = True

    @abstractmethod
    def detect(self, url: str, headers: Dict[str, str]) -> bool:
        """
        Detect if target uses this protocol.

        Args:
            url: Target URL
            headers: Response headers

        Returns:
            True if protocol detected, False otherwise
        """
        pass

    @abstractmethod
    def discover_endpoints(self, url: str) -> List[Dict[str, Any]]:
        """
        Discover API endpoints for this protocol.

        Args:
            url: Target URL

        Returns:
            List of endpoint dictionaries
        """
        pass

    def get_info(self) -> Dict[str, str]:
        """Get protocol plugin information."""
        return {
            'name': self.name,
            'protocol': self.protocol_name,
            'enabled': self.enabled
        }


class ReportPlugin(ABC):
    """
    Base class for report generator plugins.

    Use this to add new report formats.
    """

    def __init__(self, config=None, logger=None):
        """Initialize report plugin."""
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.name = self.__class__.__name__
        self.format = "unknown"
        self.enabled = True

    @abstractmethod
    def generate(self, results: Any, output_path: str) -> str:
        """
        Generate report.

        Args:
            results: Scan results object
            output_path: Output file path

        Returns:
            Path to generated report
        """
        pass

    def get_info(self) -> Dict[str, str]:
        """Get report plugin information."""
        return {
            'name': self.name,
            'format': self.format,
            'enabled': self.enabled
        }


class PluginLoader:
    """
    Plugin loader and manager.

    Discovers, loads, and manages plugins from the plugins directory.
    """

    def __init__(self, plugin_dir: Optional[Path] = None, logger=None):
        """
        Initialize plugin loader.

        Args:
            plugin_dir: Directory containing plugins (default: overapi/plugins/installed)
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

        if plugin_dir is None:
            # Default to installed plugins directory
            plugin_dir = Path(__file__).parent / "installed"

        self.plugin_dir = Path(plugin_dir)
        self.vulnerability_plugins: List[VulnerabilityPlugin] = []
        self.protocol_plugins: List[ProtocolPlugin] = []
        self.report_plugins: List[ReportPlugin] = []

    def discover_plugins(self) -> Dict[str, int]:
        """
        Discover all plugins in the plugin directory.

        Returns:
            Dictionary with counts of each plugin type
        """
        if not self.plugin_dir.exists():
            self.logger.warning(f"Plugin directory does not exist: {self.plugin_dir}")
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            return {'vulnerability': 0, 'protocol': 0, 'report': 0}

        discovered = {'vulnerability': 0, 'protocol': 0, 'report': 0}

        # Scan for Python files
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue

            try:
                # Import module
                module_name = f"overapi.plugins.installed.{plugin_file.stem}"
                module = importlib.import_module(module_name)

                # Find plugin classes
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Skip base classes
                    if obj in [VulnerabilityPlugin, ProtocolPlugin, ReportPlugin]:
                        continue

                    # Check if it's a plugin
                    if issubclass(obj, VulnerabilityPlugin) and obj != VulnerabilityPlugin:
                        self.logger.info(f"Discovered vulnerability plugin: {name}")
                        discovered['vulnerability'] += 1
                    elif issubclass(obj, ProtocolPlugin) and obj != ProtocolPlugin:
                        self.logger.info(f"Discovered protocol plugin: {name}")
                        discovered['protocol'] += 1
                    elif issubclass(obj, ReportPlugin) and obj != ReportPlugin:
                        self.logger.info(f"Discovered report plugin: {name}")
                        discovered['report'] += 1

            except Exception as e:
                self.logger.error(f"Error loading plugin {plugin_file}: {e}")

        return discovered

    def load_plugins(self, config=None) -> Dict[str, int]:
        """
        Load all discovered plugins.

        Args:
            config: Configuration object to pass to plugins

        Returns:
            Dictionary with counts of loaded plugins
        """
        loaded = {'vulnerability': 0, 'protocol': 0, 'report': 0}

        if not self.plugin_dir.exists():
            self.logger.warning(f"Plugin directory does not exist: {self.plugin_dir}")
            return loaded

        # Clear existing plugins
        self.vulnerability_plugins.clear()
        self.protocol_plugins.clear()
        self.report_plugins.clear()

        # Load plugins
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue

            try:
                # Import module
                module_name = f"overapi.plugins.installed.{plugin_file.stem}"
                module = importlib.import_module(module_name)

                # Find and instantiate plugin classes
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Skip base classes
                    if obj in [VulnerabilityPlugin, ProtocolPlugin, ReportPlugin]:
                        continue

                    try:
                        # Instantiate plugin
                        if issubclass(obj, VulnerabilityPlugin) and obj != VulnerabilityPlugin:
                            plugin = obj(config=config, logger=self.logger)
                            self.vulnerability_plugins.append(plugin)
                            loaded['vulnerability'] += 1
                            self.logger.info(f"Loaded vulnerability plugin: {name}")

                        elif issubclass(obj, ProtocolPlugin) and obj != ProtocolPlugin:
                            plugin = obj(config=config, logger=self.logger)
                            self.protocol_plugins.append(plugin)
                            loaded['protocol'] += 1
                            self.logger.info(f"Loaded protocol plugin: {name}")

                        elif issubclass(obj, ReportPlugin) and obj != ReportPlugin:
                            plugin = obj(config=config, logger=self.logger)
                            self.report_plugins.append(plugin)
                            loaded['report'] += 1
                            self.logger.info(f"Loaded report plugin: {name}")

                    except Exception as e:
                        self.logger.error(f"Error instantiating plugin {name}: {e}")

            except Exception as e:
                self.logger.error(f"Error loading plugin module {plugin_file}: {e}")

        return loaded

    def get_vulnerability_plugins(self) -> List[VulnerabilityPlugin]:
        """Get all loaded vulnerability plugins."""
        return [p for p in self.vulnerability_plugins if p.enabled]

    def get_protocol_plugins(self) -> List[ProtocolPlugin]:
        """Get all loaded protocol plugins."""
        return [p for p in self.protocol_plugins if p.enabled]

    def get_report_plugins(self) -> List[ReportPlugin]:
        """Get all loaded report plugins."""
        return [p for p in self.report_plugins if p.enabled]

    def get_all_plugins(self) -> List[Any]:
        """Get all loaded plugins."""
        return (self.vulnerability_plugins +
                self.protocol_plugins +
                self.report_plugins)

    def get_plugin_info(self) -> Dict[str, List[Dict[str, str]]]:
        """Get information about all loaded plugins."""
        return {
            'vulnerability': [p.get_info() for p in self.vulnerability_plugins],
            'protocol': [p.get_info() for p in self.protocol_plugins],
            'report': [p.get_info() for p in self.report_plugins]
        }
