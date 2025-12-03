"""
Plugin Manager for OverApi Enterprise
Handles plugin loading, execution, and lifecycle
"""

import os
import importlib
import importlib.util
from typing import Dict, List, Any, Optional
from pathlib import Path

from .base import BasePlugin, VulnerabilityPlugin, ReporterPlugin, IntegrationPlugin


class PluginManager:
    """
    Manages plugins for OverApi Enterprise

    Features:
    - Dynamic plugin loading
    - Plugin lifecycle management
    - Plugin dependencies
    - Hot-reload support
    """

    def __init__(self, plugin_dir: str = None):
        """
        Initialize plugin manager

        Args:
            plugin_dir: Directory containing plugins
        """
        self.plugin_dir = plugin_dir or os.path.join(os.path.dirname(__file__), 'installed')
        self.plugins: Dict[str, BasePlugin] = {}
        self.loaded_plugins: Dict[str, Any] = {}

        # Create plugin directory if it doesn't exist
        os.makedirs(self.plugin_dir, exist_ok=True)

    def discover_plugins(self) -> List[str]:
        """
        Discover available plugins

        Returns:
            List of plugin names
        """
        plugins = []

        if not os.path.exists(self.plugin_dir):
            return plugins

        for file in os.listdir(self.plugin_dir):
            if file.endswith('.py') and not file.startswith('__'):
                plugin_name = file[:-3]
                plugins.append(plugin_name)

        return plugins

    def load_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """
        Load a plugin by name

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin instance or None if loading failed
        """
        try:
            # Check if already loaded
            if plugin_name in self.plugins:
                return self.plugins[plugin_name]

            # Load plugin module
            plugin_path = os.path.join(self.plugin_dir, f"{plugin_name}.py")

            if not os.path.exists(plugin_path):
                print(f"Plugin not found: {plugin_name}")
                return None

            # Import plugin module
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find plugin class
                plugin_class = None
                for item_name in dir(module):
                    item = getattr(module, item_name)
                    if (isinstance(item, type) and
                        issubclass(item, BasePlugin) and
                        item != BasePlugin and
                        item not in [VulnerabilityPlugin, ReporterPlugin, IntegrationPlugin]):
                        plugin_class = item
                        break

                if plugin_class:
                    # Instantiate plugin
                    plugin = plugin_class()

                    # Initialize plugin
                    if plugin.initialize():
                        self.plugins[plugin_name] = plugin
                        self.loaded_plugins[plugin_name] = module
                        print(f"Plugin loaded successfully: {plugin_name}")
                        return plugin
                    else:
                        print(f"Plugin initialization failed: {plugin_name}")
                        return None
                else:
                    print(f"No valid plugin class found in: {plugin_name}")
                    return None

        except Exception as e:
            print(f"Error loading plugin {plugin_name}: {str(e)}")
            return None

    def load_all_plugins(self) -> int:
        """
        Load all available plugins

        Returns:
            Number of plugins loaded
        """
        plugins = self.discover_plugins()
        loaded = 0

        for plugin_name in plugins:
            if self.load_plugin(plugin_name):
                loaded += 1

        print(f"Loaded {loaded}/{len(plugins)} plugins")
        return loaded

    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin

        Args:
            plugin_name: Name of the plugin

        Returns:
            Success status
        """
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            plugin.cleanup()
            del self.plugins[plugin_name]
            if plugin_name in self.loaded_plugins:
                del self.loaded_plugins[plugin_name]
            print(f"Plugin unloaded: {plugin_name}")
            return True
        return False

    def execute_plugin(self, plugin_name: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Execute a specific plugin

        Args:
            plugin_name: Name of the plugin
            context: Execution context

        Returns:
            Plugin results or None if execution failed
        """
        if plugin_name not in self.plugins:
            print(f"Plugin not loaded: {plugin_name}")
            return None

        plugin = self.plugins[plugin_name]

        if not plugin.enabled:
            print(f"Plugin disabled: {plugin_name}")
            return None

        try:
            results = plugin.execute(context)
            return results
        except Exception as e:
            print(f"Error executing plugin {plugin_name}: {str(e)}")
            return None

    def execute_all_plugins(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute all loaded plugins

        Args:
            context: Execution context

        Returns:
            Combined results from all plugins
        """
        results = {}

        for plugin_name, plugin in self.plugins.items():
            if plugin.enabled:
                try:
                    plugin_results = plugin.execute(context)
                    results[plugin_name] = plugin_results
                except Exception as e:
                    print(f"Error executing plugin {plugin_name}: {str(e)}")
                    results[plugin_name] = {'error': str(e)}

        return results

    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """
        Get a loaded plugin

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin instance or None
        """
        return self.plugins.get(plugin_name)

    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all loaded plugins

        Returns:
            List of plugin information
        """
        return [plugin.get_info() for plugin in self.plugins.values()]

    def enable_plugin(self, plugin_name: str) -> bool:
        """
        Enable a plugin

        Args:
            plugin_name: Name of the plugin

        Returns:
            Success status
        """
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = True
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """
        Disable a plugin

        Args:
            plugin_name: Name of the plugin

        Returns:
            Success status
        """
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = False
            return True
        return False

    def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a plugin (hot-reload)

        Args:
            plugin_name: Name of the plugin

        Returns:
            Success status
        """
        if plugin_name in self.plugins:
            self.unload_plugin(plugin_name)

        return self.load_plugin(plugin_name) is not None

    def get_vulnerability_plugins(self) -> List[VulnerabilityPlugin]:
        """Get all vulnerability detection plugins"""
        return [
            plugin for plugin in self.plugins.values()
            if isinstance(plugin, VulnerabilityPlugin) and plugin.enabled
        ]

    def get_reporter_plugins(self) -> List[ReporterPlugin]:
        """Get all reporter plugins"""
        return [
            plugin for plugin in self.plugins.values()
            if isinstance(plugin, ReporterPlugin) and plugin.enabled
        ]

    def get_integration_plugins(self) -> List[IntegrationPlugin]:
        """Get all integration plugins"""
        return [
            plugin for plugin in self.plugins.values()
            if isinstance(plugin, IntegrationPlugin) and plugin.enabled
        ]


# Example plugin templates
EXAMPLE_VULNERABILITY_PLUGIN = """
from overapi.plugins.base import VulnerabilityPlugin
from typing import Dict, List, Any


class CustomVulnerabilityPlugin(VulnerabilityPlugin):
    def __init__(self):
        super().__init__()
        self.name = "CustomVulnerabilityPlugin"
        self.version = "1.0.0"
        self.description = "Custom vulnerability detection plugin"
        self.author = "Your Name"

    def initialize(self) -> bool:
        # Initialize plugin resources
        return True

    def detect_vulnerabilities(self, endpoint: Dict, config: Any) -> List[Dict]:
        vulnerabilities = []

        # Your custom detection logic here
        # Example:
        # if some_condition:
        #     vulnerabilities.append({
        #         'type': 'Custom Vulnerability',
        #         'severity': 'High',
        #         'endpoint': endpoint.get('path'),
        #         'evidence': 'Description of the vulnerability'
        #     })

        return vulnerabilities

    def cleanup(self):
        # Cleanup resources
        pass
"""


def create_example_plugin(plugin_dir: str, plugin_name: str = "example_plugin"):
    """
    Create an example plugin file

    Args:
        plugin_dir: Directory to create plugin in
        plugin_name: Name of the plugin
    """
    os.makedirs(plugin_dir, exist_ok=True)
    plugin_path = os.path.join(plugin_dir, f"{plugin_name}.py")

    with open(plugin_path, 'w') as f:
        f.write(EXAMPLE_VULNERABILITY_PLUGIN)

    print(f"Example plugin created: {plugin_path}")
