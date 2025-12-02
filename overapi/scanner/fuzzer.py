
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.logger import Logger
from ..core.config import Config
from ..utils.http_client import HTTPClient
from ..utils.wordlist_loader import WordlistLoader


class Fuzzer:
    """Advanced intelligent fuzzer for API testing with robustness features."""

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
    # Retry configuration
    MAX_RETRIES = 3
    RETRY_BACKOFF = [0.5, 1.0, 2.0]  # Exponential backoff in seconds

    # Timing configuration (in seconds)
    RATE_LIMIT_DELAY = 0.1
    ADAPTIVE_DELAY = True
    MIN_DELAY = 0.05
    MAX_DELAY = 2.0

    # Detection patterns for common vulnerabilities
    VULN_PATTERNS = {
        "sqli": [
            r"syntax error",
            r"SQL error",
            r"MySQL",
            r"PostgreSQL",
            r"Microsoft SQL Server",
            r"ORA-\d+",
            r"SQLState",
        ],
        "xss": [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe",
        ],
        "xxe": [
            r"XML",
            r"DOCTYPE",
            r"ENTITY",
        ],
        "command_injection": [
            r"command not found",
            r"No such file or directory",
            r"Permission denied",
            r"cannot execute",
        ],
    }

    def __init__(self, wordlist_loader: Optional[WordlistLoader] = None, logger: Logger = None):
        """
        Initialize fuzzer.

        Args:
            wordlist_loader: Custom wordlist loader
            logger: Logger instance
        """
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(logger=self.logger)
        self.wordlist = wordlist_loader or WordlistLoader()
        self.payloads = self._load_all_payloads()
        self.request_history = []
        self.last_request_time = 0

    def _load_all_payloads(self) -> Dict[str, List[str]]:
        """Load all payloads from wordlist."""
        return {
            "sqli": self.wordlist.get_payloads("sqli"),
            "xss": self.wordlist.get_payloads("xss"),
            "nosqli": self.wordlist.get_payloads("nosqli"),
            "command_injection": self.wordlist.get_payloads("command_injection"),
            "xxe": self.wordlist.get_payloads("xxe"),
            "path_traversal": self.wordlist.get_payloads("path_traversal"),
            "lfi": self.wordlist.get_payloads("lfi"),
        }

    def _adaptive_delay(self):
        """Apply adaptive rate limiting with jitter."""
        if not self.ADAPTIVE_DELAY:
            return

        elapsed = time.time() - self.last_request_time
        target_delay = self.RATE_LIMIT_DELAY

        # Add jitter to avoid detection
        jitter = random.uniform(0, target_delay * 0.3)
        delay = max(self.MIN_DELAY, target_delay - elapsed + jitter)
        delay = min(delay, self.MAX_DELAY)

        if delay > 0:
            time.sleep(delay)

        self.last_request_time = time.time()

    def _make_request_with_retry(self, method: str, url: str, config: Config, **kwargs) -> Optional[Any]:
        """
        Make HTTP request with exponential backoff retry.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            config: Configuration
            **kwargs: Additional arguments for request

        Returns:
            Response object or None if failed
        """
        self._adaptive_delay()

        for attempt in range(self.MAX_RETRIES):
            try:
                if method.upper() == "GET":
                    resp = self.http_client.get(url, timeout=config.timeout, **kwargs)
                elif method.upper() == "POST":
                    resp = self.http_client.post(url, timeout=config.timeout, **kwargs)
                else:
                    resp = self.http_client.get(url, timeout=config.timeout, **kwargs)

                self.request_history.append({
                    "url": url,
                    "method": method,
                    "status": resp.status_code,
                    "timestamp": time.time()
                })

                return resp

            except Exception as e:
                if attempt < self.MAX_RETRIES - 1:
                    backoff = self.RETRY_BACKOFF[attempt]
                    self.logger.debug(f"Retry {attempt + 1}/{self.MAX_RETRIES} for {url} (backoff: {backoff}s)")
                    time.sleep(backoff)
                else:
                    self.logger.debug(f"Failed to request {url} after {self.MAX_RETRIES} attempts: {str(e)}")

        return None

    def generate_fuzzing_payloads(self, payload_type: str, limit: Optional[int] = None) -> List[str]:
        """
        Generate fuzzing payloads of specific type.

        Args:
            payload_type: Type of payloads to generate
            limit: Maximum number of payloads

        Returns:
            List of payloads
        """
        payloads = self.payloads.get(payload_type, [])
        if limit:
            return payloads[:limit]
        return payloads

    def fuzz_parameter(self, param_name: str, test_values: List[str]) -> List[Dict]:
        """
        Fuzz parameter with various values.

        Args:
            param_name: Parameter name
            test_values: Values to test

        Returns:
            List of variations
        """
        variations = []
        for value in test_values:
            variations.append({param_name: value})
        return variations

    def fuzz_endpoint_path(self, base_path: str, fuzzing_words: List[str]) -> List[str]:
        """
        Fuzz endpoint paths.

        Args:
            base_path: Base endpoint path
            fuzzing_words: Words to append/fuzz

        Returns:
            List of fuzzed paths
        """
        paths = [base_path]
        for word in fuzzing_words:
            paths.append(f"{base_path}/{word}")
            paths.append(f"{base_path}_{word}")
        return paths

    def mutate_payload(self, payload: str, count: int = 1) -> List[str]:
        """
        Mutate payload variations.

        Args:
            payload: Original payload
            count: Number of variations

        Returns:
            List of payload variations
        """
        variations = [payload]

        for _ in range(count - 1):
            # URL encoding variations
            import urllib.parse
            variations.append(urllib.parse.quote(payload))

            # Double encoding
            variations.append(urllib.parse.quote(urllib.parse.quote(payload)))

            # Case variations
            if random.random() > 0.5:
                variations.append(payload.upper())
            else:
                variations.append(payload.lower())

        return variations[:count]

    def fuzz_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Fuzz endpoint with various payloads (robust version).

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
                vulns = self._fuzz_parameter_robust(url, param, config)
                vulnerabilities.extend(vulns)

            # Fuzz with wordlist endpoints
            vulns = self._fuzz_paths_robust(config.url, config)
            vulnerabilities.extend(vulns)

        except Exception as e:
            self.logger.debug(f"Fuzzing error on {url}: {str(e)}")

        return vulnerabilities

    def _fuzz_parameter_robust(self, url: str, param: str, config: Config) -> List[Dict]:
        """
        Fuzz specific parameter with advanced detection.

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
            resp = self._make_request_with_retry("GET", url, config, params=params)

            if resp and resp.status_code == 500:
                vulnerabilities.append({
                    "type": "Server Error on Parameter Fuzzing",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": param,
                    "evidence": f"Server error with empty {param}"
                })

            # Test with SQL injection payloads
            for sqli_payload in self.payloads["sqli"][:3]:  # Limit for performance
                params = {param: sqli_payload}
                resp = self._make_request_with_retry("GET", url, config, params=params)

                if resp:
                    if self._detect_vulnerability(resp.text, "sqli"):
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "severity": "High",
                            "endpoint": url,
                            "parameter": param,
                            "payload": sqli_payload,
                            "evidence": "SQL error detected in response"
                        })
                        break  # Found vulnerability, move to next param

            # Test with XSS payloads
            for xss_payload in self.payloads["xss"][:3]:
                params = {param: xss_payload}
                resp = self._make_request_with_retry("GET", url, config, params=params)

                if resp and self._detect_vulnerability(resp.text, "xss"):
                    vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "endpoint": url,
                        "parameter": param,
                        "payload": xss_payload,
                        "evidence": "XSS payload reflected in response"
                    })
                    break

        except Exception as e:
            self.logger.debug(f"Parameter fuzzing error: {str(e)}")

        return vulnerabilities

    def _detect_vulnerability(self, response_text: str, vuln_type: str) -> bool:
        """
        Detect vulnerability based on response patterns.

        Args:
            response_text: Response body text
            vuln_type: Type of vulnerability to detect

        Returns:
            True if vulnerability detected
        """
        patterns = self.VULN_PATTERNS.get(vuln_type, [])

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _fuzz_paths_robust(self, base_url: str, config: Config) -> List[Dict]:
        """
        Fuzz paths with wordlist (robust version).

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
                resp = self._make_request_with_retry("GET", url, config)

                if resp and resp.status_code in [200, 201]:
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

    def get_request_history(self) -> List[Dict]:
        """Get request history."""
        return self.request_history.copy()

    def clear_request_history(self):
        """Clear request history."""
        self.request_history = []
