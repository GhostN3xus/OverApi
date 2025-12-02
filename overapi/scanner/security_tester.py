"""Security vulnerability tester."""

from typing import Dict, List, Any
from urllib.parse import urljoin

from ..core.logger import Logger
from ..core.config import Config
from ..utils.http_client import HTTPClient
from ..utils.wordlist_loader import WordlistLoader
from ..utils.validators import Validators


class SecurityTester:
    """Tests endpoints for OWASP API Top 10 vulnerabilities."""

    def __init__(self, logger: Logger = None):
        """Initialize security tester."""
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(logger=self.logger)
        self.wordlist = WordlistLoader()

    def test_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Test endpoint for vulnerabilities.

        Args:
            endpoint: Endpoint configuration
            config: Global config

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        try:
            # Test for broken authentication
            auth_vulns = self._test_broken_authentication(endpoint, config)
            vulnerabilities.extend(auth_vulns)

            # Test for BOLA
            bola_vulns = self._test_bola(endpoint, config)
            vulnerabilities.extend(bola_vulns)

            # Test for injection
            injection_vulns = self._test_injection(endpoint, config)
            vulnerabilities.extend(injection_vulns)

            # Test for excessive data exposure
            data_vulns = self._test_data_exposure(endpoint, config)
            vulnerabilities.extend(data_vulns)

            # Test for rate limiting
            rate_vulns = self._test_rate_limiting(endpoint, config)
            vulnerabilities.extend(rate_vulns)

        except Exception as e:
            self.logger.debug(f"Error testing endpoint {endpoint.get('path')}: {str(e)}")

        return vulnerabilities

    def _test_broken_authentication(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for broken authentication."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test without authentication
            resp = self.http_client.get(url, timeout=config.timeout)

            if resp.status_code in [200, 201]:
                vulnerabilities.append({
                    "type": "Broken Authentication",
                    "severity": "High",
                    "endpoint": url,
                    "evidence": f"Endpoint accessible without authentication (Status: {resp.status_code})",
                    "owasp_category": "API2"
                })

        except Exception as e:
            self.logger.debug(f"Auth test error: {str(e)}")

        return vulnerabilities

    def _test_bola(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for Broken Object Level Authorization."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test ID parameter variations
            test_ids = ['1', '2', '999', '-1', '0']

            for test_id in test_ids:
                test_url = url.replace('{id}', test_id)
                if '{' in test_url:
                    continue

                resp = self.http_client.get(test_url, timeout=config.timeout)

                if resp.status_code in [200, 201]:
                    vulnerabilities.append({
                        "type": "BOLA",
                        "severity": "High",
                        "endpoint": test_url,
                        "evidence": f"Object accessible with different ID (Status: {resp.status_code})",
                        "owasp_category": "API1"
                    })
                    break

        except Exception as e:
            self.logger.debug(f"BOLA test error: {str(e)}")

        return vulnerabilities

    def _test_injection(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for injection vulnerabilities."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        if config.enable_injection_tests:
            # SQL Injection
            sqli_payloads = self.wordlist.get_payloads("sqli")
            for payload in sqli_payloads[:3]:  # Limit payloads
                try:
                    resp = self.http_client.get(url, params={"id": payload}, timeout=config.timeout)
                    if Validators.is_sql_injection(resp.text, payload):
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "endpoint": url,
                            "payload": payload,
                            "evidence": resp.text[:200],
                            "owasp_category": "API8"
                        })
                        break
                except:
                    pass

            # XSS
            xss_payloads = self.wordlist.get_payloads("xss")
            for payload in xss_payloads[:2]:
                try:
                    resp = self.http_client.get(url, params={"search": payload}, timeout=config.timeout)
                    if Validators.is_xss(resp.text, payload):
                        vulnerabilities.append({
                            "type": "XSS",
                            "severity": "High",
                            "endpoint": url,
                            "payload": payload,
                            "evidence": resp.text[:200],
                            "owasp_category": "API8"
                        })
                        break
                except:
                    pass

            # Command Injection
            cmd_payloads = self.wordlist.get_payloads("command_injection")
            for payload in cmd_payloads[:2]:
                try:
                    resp = self.http_client.get(url, params={"cmd": payload}, timeout=config.timeout)
                    if Validators.is_command_injection(resp.text):
                        vulnerabilities.append({
                            "type": "Command Injection",
                            "severity": "Critical",
                            "endpoint": url,
                            "payload": payload,
                            "evidence": resp.text[:200],
                            "owasp_category": "API8"
                        })
                        break
                except:
                    pass

        return vulnerabilities

    def _test_data_exposure(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for excessive data exposure."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            resp = self.http_client.get(url, timeout=config.timeout)

            if Validators.is_sensitive_data_exposure(resp.text):
                vulnerabilities.append({
                    "type": "Excessive Data Exposure",
                    "severity": "High",
                    "endpoint": url,
                    "evidence": "Sensitive data found in response",
                    "owasp_category": "API3"
                })

        except Exception as e:
            self.logger.debug(f"Data exposure test error: {str(e)}")

        return vulnerabilities

    def _test_rate_limiting(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for lack of rate limiting."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        if config.enable_ratelimit_tests:
            try:
                # Make rapid requests
                rate_limited = False
                for i in range(10):
                    resp = self.http_client.get(url, timeout=config.timeout)
                    if Validators.is_rate_limited(resp.status_code):
                        rate_limited = True
                        break

                if not rate_limited:
                    vulnerabilities.append({
                        "type": "Lack of Rate Limiting",
                        "severity": "Medium",
                        "endpoint": url,
                        "evidence": "No rate limiting detected after 10 requests",
                        "owasp_category": "API4"
                    })

            except Exception as e:
                self.logger.debug(f"Rate limit test error: {str(e)}")

        return vulnerabilities
