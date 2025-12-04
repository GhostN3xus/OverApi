"""
Example Vulnerability Plugin

This is an example plugin showing how to create custom vulnerability scanners.
"""

from typing import List, Dict, Any
from overapi.plugins.base import VulnerabilityPlugin


class CustomHeaderInjectionPlugin(VulnerabilityPlugin):
    """
    Example plugin to detect custom header injection vulnerabilities.

    This plugin demonstrates how to create a custom vulnerability scanner
    by extending the VulnerabilityPlugin base class.
    """

    def __init__(self, config=None, logger=None):
        """Initialize the plugin."""
        super().__init__(config, logger)

        # Plugin metadata
        self.name = "Custom Header Injection Scanner"
        self.version = "1.0.0"
        self.author = "OverApi Team"
        self.description = "Detects custom header injection vulnerabilities"

        # Test payloads
        self.test_payloads = [
            "\r\nX-Injected-Header: injected",
            "\nX-Injected-Header: injected",
            "%0d%0aX-Injected-Header: injected",
            "%0aX-Injected-Header: injected"
        ]

    def detect(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect header injection vulnerabilities.

        Args:
            endpoint: Endpoint information dictionary

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Skip if plugin is disabled
        if not self.enabled:
            return vulnerabilities

        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        params = endpoint.get('params', {})

        self.logger.debug(f"Testing {method} {url} for header injection")

        # Test each parameter with injection payloads
        for param_name, param_value in params.items():
            for payload in self.test_payloads:
                # Simulate testing (in real plugin, you would make HTTP request)
                # For this example, we'll detect based on patterns
                if self._test_injection(url, method, param_name, payload):
                    vulnerability = {
                        'type': 'Custom Header Injection',
                        'severity': 'HIGH',
                        'endpoint': url,
                        'method': method,
                        'description': (
                            f"The parameter '{param_name}' is vulnerable to header injection. "
                            f"An attacker can inject arbitrary HTTP headers, potentially leading to "
                            f"HTTP response splitting, cache poisoning, or session hijacking."
                        ),
                        'evidence': f"Injected payload: {payload}",
                        'parameter': param_name,
                        'payload': payload,
                        'remediation': (
                            "1. Validate and sanitize all user input\n"
                            "2. Remove or encode CRLF characters (\\r\\n)\n"
                            "3. Use parameterized responses\n"
                            "4. Implement proper output encoding"
                        ),
                        'cwe': 'CWE-113',
                        'owasp': 'API8:2023 - Security Misconfiguration',
                        'cvss_score': 7.5,
                        'plugin': self.name
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"Found header injection in {url} parameter {param_name}")

        return vulnerabilities

    def _test_injection(self, url: str, method: str, param: str, payload: str) -> bool:
        """
        Test if injection is possible (simulated for example).

        In a real plugin, this would make actual HTTP requests and
        analyze responses.

        Args:
            url: Target URL
            method: HTTP method
            param: Parameter name
            payload: Injection payload

        Returns:
            True if vulnerability detected, False otherwise
        """
        # This is a simplified example
        # In real implementation, you would:
        # 1. Make HTTP request with injected payload
        # 2. Analyze response headers
        # 3. Detect if injection succeeded

        # For example purposes, randomly detect (replace with real logic)
        import random
        return random.random() < 0.05  # 5% detection rate for demo


class DebugModePlugin(VulnerabilityPlugin):
    """
    Example plugin to detect debug mode enabled.

    Checks if application is running in debug mode by analyzing
    responses for debug information disclosure.
    """

    def __init__(self, config=None, logger=None):
        """Initialize the plugin."""
        super().__init__(config, logger)

        self.name = "Debug Mode Detection"
        self.version = "1.0.0"
        self.author = "OverApi Team"
        self.description = "Detects applications running in debug mode"

        # Debug indicators
        self.debug_indicators = [
            'DEBUG=True',
            'debug mode',
            'X-Debug-Token',
            'Symfony Profiler',
            'Laravel Debugbar',
            'Django Debug Toolbar',
            'Stack Trace',
            'Traceback'
        ]

    def detect(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect debug mode enabled.

        Args:
            endpoint: Endpoint information

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        if not self.enabled:
            return vulnerabilities

        url = endpoint.get('url', '')
        response_body = endpoint.get('response_body', '')
        response_headers = endpoint.get('response_headers', {})

        # Check headers for debug indicators
        for header, value in response_headers.items():
            for indicator in self.debug_indicators:
                if indicator.lower() in header.lower() or indicator.lower() in str(value).lower():
                    vulnerability = {
                        'type': 'Debug Mode Enabled',
                        'severity': 'MEDIUM',
                        'endpoint': url,
                        'method': endpoint.get('method', 'GET'),
                        'description': (
                            f"The application appears to be running in debug mode. "
                            f"Debug indicator '{indicator}' was found in response headers. "
                            f"This may expose sensitive information about the application."
                        ),
                        'evidence': f"Header: {header} = {value}",
                        'remediation': (
                            "1. Disable debug mode in production\n"
                            "2. Remove debug headers from responses\n"
                            "3. Use environment-specific configurations\n"
                            "4. Implement proper error handling"
                        ),
                        'cwe': 'CWE-489',
                        'owasp': 'API8:2023 - Security Misconfiguration',
                        'cvss_score': 5.3,
                        'plugin': self.name
                    }
                    vulnerabilities.append(vulnerability)

        # Check body for debug indicators
        for indicator in self.debug_indicators:
            if indicator.lower() in response_body.lower():
                vulnerability = {
                    'type': 'Debug Information Disclosure',
                    'severity': 'MEDIUM',
                    'endpoint': url,
                    'method': endpoint.get('method', 'GET'),
                    'description': (
                        f"Debug information was found in the response body. "
                        f"The indicator '{indicator}' suggests the application is "
                        f"exposing sensitive debugging information."
                    ),
                    'evidence': f"Found: {indicator}",
                    'remediation': (
                        "1. Disable debug mode in production\n"
                        "2. Use custom error pages\n"
                        "3. Log errors securely server-side\n"
                        "4. Never expose stack traces to users"
                    ),
                    'cwe': 'CWE-215',
                    'owasp': 'API8:2023 - Security Misconfiguration',
                    'cvss_score': 5.3,
                    'plugin': self.name
                }
                vulnerabilities.append(vulnerability)
                break  # Only report once per endpoint

        return vulnerabilities
