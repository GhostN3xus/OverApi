"""
Base plugin class for OverApi Enterprise
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BasePlugin(ABC):
    """
    Base class for all OverApi plugins

    Plugins can extend the functionality of OverApi by:
    - Adding custom vulnerability detection rules
    - Implementing protocol-specific tests
    - Custom reporting formats
    - Integration with external tools
    """

    def __init__(self):
        """Initialize plugin"""
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "Base plugin"
        self.author = "Unknown"
        self.enabled = True

    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize plugin

        Returns:
            Success status
        """
        pass

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute plugin logic

        Args:
            context: Scan context with configuration and state

        Returns:
            Plugin results
        """
        pass

    def cleanup(self):
        """Cleanup plugin resources"""
        pass

    def get_info(self) -> Dict[str, str]:
        """Get plugin information"""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'enabled': self.enabled
        }


class VulnerabilityPlugin(BasePlugin):
    """
    Plugin for custom vulnerability detection
    """

    @abstractmethod
    def detect_vulnerabilities(self, endpoint: Dict, config: Any) -> List[Dict]:
        """
        Detect vulnerabilities in endpoint

        Args:
            endpoint: Endpoint information
            config: Scan configuration

        Returns:
            List of vulnerabilities found
        """
        pass

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute vulnerability detection"""
        endpoints = context.get('endpoints', [])
        config = context.get('config')
        vulnerabilities = []

        for endpoint in endpoints:
            vulns = self.detect_vulnerabilities(endpoint, config)
            vulnerabilities.extend(vulns)

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities)
        }


class ReporterPlugin(BasePlugin):
    """
    Plugin for custom report generation
    """

    @abstractmethod
    def generate_report(self, scan_data: Dict[str, Any], output_path: str) -> bool:
        """
        Generate custom report

        Args:
            scan_data: Scan results
            output_path: Output file path

        Returns:
            Success status
        """
        pass

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute report generation"""
        scan_data = context.get('scan_data', {})
        output_path = context.get('output_path', 'report.txt')

        success = self.generate_report(scan_data, output_path)

        return {
            'success': success,
            'output_path': output_path
        }


class IntegrationPlugin(BasePlugin):
    """
    Plugin for integration with external tools
    """

    @abstractmethod
    def send_results(self, scan_data: Dict[str, Any]) -> bool:
        """
        Send results to external system

        Args:
            scan_data: Scan results

        Returns:
            Success status
        """
        pass

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute integration"""
        scan_data = context.get('scan_data', {})
        success = self.send_results(scan_data)

        return {
            'success': success,
            'integration': self.name
        }
