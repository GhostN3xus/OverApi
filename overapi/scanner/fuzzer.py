"""Intelligent fuzzer for API endpoints."""

from typing import Dict, List, Any, Optional
from urllib.parse import urljoin
import time

from ..core.logger import Logger
from ..core.config import Config
from ..utils.http_client import HTTPClient
from ..utils.wordlist_loader import WordlistLoader


class Fuzzer:
    """Intelligent fuzzer for API testing."""

    def __init__(self, logger: Logger = None, verify_ssl: bool = True,
                 custom_ca_path: Optional[str] = None):
        """
        Initialize fuzzer with SSL configuration.

        Args:
            logger: Logger instance
            verify_ssl: Verify SSL certificates (default: True)
            custom_ca_path: Path to custom CA certificate bundle
        """
        self.logger = logger or Logger(__name__)
        self.verify_ssl = verify_ssl
        self.custom_ca_path = custom_ca_path
        self.http_client = HTTPClient(
            logger=self.logger,
            verify_ssl=verify_ssl,
            custom_ca_path=custom_ca_path
        )
        self.wordlist = WordlistLoader()

    def fuzz_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Fuzz endpoint with various payloads.

        Args:
            endpoint: Endpoint to fuzz
            config: Configuration

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Fuzz with common parameters
            for param in self.wordlist.get_parameters():
                vulns = self._fuzz_parameter(url, param, config)
                vulnerabilities.extend(vulns)

            # Fuzz with wordlist endpoints
            vulns = self._fuzz_paths(config.url, config)
            vulnerabilities.extend(vulns)

        except Exception as e:
            self.logger.debug(f"Fuzzing error on {url}: {str(e)}")

        return vulnerabilities

    def _fuzz_parameter(self, url: str, param: str, config: Config) -> List[Dict]:
        """
        Fuzz specific parameter.

        Args:
            url: Target URL
            param: Parameter name
            config: Configuration

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        try:
            # Test with null/empty values
            params = {param: ""}
            resp = self.http_client.get(url, params=params, timeout=config.timeout)

            if resp.status_code == 500:
                vulnerabilities.append({
                    "type": "Server Error on Parameter Fuzzing",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": param,
                    "evidence": f"Server error with empty {param}"
                })

            # Test with numeric values
            params = {param: "999"}
            resp = self.http_client.get(url, params=params, timeout=config.timeout)

        except Exception as e:
            self.logger.debug(f"Parameter fuzzing error: {str(e)}")

        return vulnerabilities

    def _fuzz_paths(self, base_url: str, config: Config) -> List[Dict]:
        """
        Fuzz paths with wordlist.

        Args:
            base_url: Base URL
            config: Configuration

        Returns:
            List of findings
        """
        vulnerabilities = []
        endpoints = self.wordlist.get_endpoints(limit=50)  # Limit for performance

        for endpoint in endpoints:
            try:
                url = urljoin(base_url, endpoint)
                resp = self.http_client.get(url, timeout=config.timeout)

                if resp.status_code in [200, 201]:
                    vulnerabilities.append({
                        "type": "Exposed Endpoint",
                        "severity": "Low",
                        "endpoint": url,
                        "status_code": resp.status_code,
                        "evidence": f"Endpoint found with status {resp.status_code}"
                    })

            except Exception as e:
                self.logger.debug(f"Path fuzzing error: {str(e)}")

        return vulnerabilities
