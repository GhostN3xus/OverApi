"""
Preferences Manager for OverApi
"""

import json
import os
from typing import Dict, Any

class Preferences:
    """
    Manages global application preferences.
    """

    def __init__(self, config_path: str = None):
        self.config_path = config_path or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception:
                return self._get_defaults()
        return self._get_defaults()

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "scan": {
                "timeout": 30,
                "max_threads": 10,
                "verify_ssl": True,
                "user_agent": "OverApi/2.0 Enterprise",
                "proxy": ""
            },
            "gui": {
                "theme": "dark",
                "font_size": 10
            },
            "plugins": {
                "auto_load": True,
                "directory": "plugins"
            }
        }

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value: Any):
        """Set a configuration value."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self.save()

    def save(self):
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving preferences: {e}")
