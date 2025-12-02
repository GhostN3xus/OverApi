"""Enhanced security vulnerability tester."""

import json
import time
from typing import Dict, List, Any, Tuple
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

            # Test for API key/token validation
            token_vulns = self._test_token_validation(endpoint, config)
            vulnerabilities.extend(token_vulns)

            # Test for JWT vulnerabilities
            jwt_vulns = self._test_jwt_vulnerabilities(endpoint, config)
            vulnerabilities.extend(jwt_vulns)

            # Test for BOLA
            bola_vulns = self._test_bola(endpoint, config)
            vulnerabilities.extend(bola_vulns)

            # Test for privilege escalation
            priv_vulns = self._test_privilege_escalation(endpoint, config)
            vulnerabilities.extend(priv_vulns)

            # Test for injection
            injection_vulns = self._test_injection(endpoint, config)
            vulnerabilities.extend(injection_vulns)

            # Test for excessive data exposure
            data_vulns = self._test_data_exposure(endpoint, config)
            vulnerabilities.extend(data_vulns)

            # Test for rate limiting
            rate_vulns = self._test_rate_limiting(endpoint, config)
            vulnerabilities.extend(rate_vulns)

            # Test for CORS misconfiguration
            cors_vulns = self._test_cors(endpoint, config)
            vulnerabilities.extend(cors_vulns)

            # Test for missing security headers
            header_vulns = self._test_security_headers(endpoint, config)
            vulnerabilities.extend(header_vulns)

            # Test for unsafe redirects
            redirect_vulns = self._test_unsafe_redirects(endpoint, config)
            vulnerabilities.extend(redirect_vulns)

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
                    if Validators.is_rate_limited(resp.status_code, resp.headers):
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

    def _test_token_validation(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for weak API key/token validation."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test 1: Invalid token
            invalid_tokens = ["invalid", "test123", "x" * 50, ""]

            for token in invalid_tokens:
                try:
                    headers = {"Authorization": f"Bearer {token}"}
                    resp = self.http_client.get(url, headers=headers, timeout=config.timeout)

                    if resp.status_code in [200, 201]:
                        vulnerabilities.append({
                            "type": "Weak Token Validation",
                            "severity": "High",
                            "endpoint": url,
                            "evidence": f"Invalid token accepted: {token}",
                            "owasp_category": "API2"
                        })
                        break

                except:
                    pass

            # Test 2: Missing token
            try:
                resp_no_auth = self.http_client.get(url, timeout=config.timeout)

                if resp_no_auth.status_code in [200, 201]:
                    vulnerabilities.append({
                        "type": "Missing Authentication",
                        "severity": "High",
                        "endpoint": url,
                        "evidence": "Endpoint accessible without any token/authentication",
                        "owasp_category": "API2"
                    })

            except:
                pass

            # Test 3: Null byte injection
            try:
                headers = {"Authorization": "Bearer test\x00valid"}
                resp = self.http_client.get(url, headers=headers, timeout=config.timeout)

                if resp.status_code in [200, 201]:
                    vulnerabilities.append({
                        "type": "Null Byte Injection in Auth",
                        "severity": "High",
                        "endpoint": url,
                        "evidence": "Null byte bypasses authentication",
                        "owasp_category": "API2"
                    })

            except:
                pass

        except Exception as e:
            self.logger.debug(f"Token validation test error: {str(e)}")

        return vulnerabilities

    def _test_jwt_vulnerabilities(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for JWT vulnerabilities."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Extract JWT from typical locations
            jwt_tokens = self._extract_jwt_from_endpoint(endpoint, config)

            for token in jwt_tokens:
                is_vuln, vuln_types = Validators.is_jwt_vulnerable(token, "")

                for vuln_type in vuln_types:
                    vulnerabilities.append({
                        "type": "JWT Vulnerability",
                        "severity": "High",
                        "endpoint": url,
                        "evidence": vuln_type,
                        "owasp_category": "API2"
                    })

        except Exception as e:
            self.logger.debug(f"JWT test error: {str(e)}")

        return vulnerabilities

    def _test_privilege_escalation(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test with different role/permission parameters
            role_params = {
                "role": ["admin", "moderator", "superuser"],
                "is_admin": ["true", "1", "yes"],
                "permission": ["admin", "*", "all"],
                "access_level": ["admin", "root", "system"],
            }

            for param_name, param_values in role_params.items():
                for param_value in param_values:
                    try:
                        data = {param_name: param_value, "action": "test"}
                        resp = self.http_client.post(
                            url,
                            json=data,
                            timeout=config.timeout
                        )

                        if Validators.is_privilege_escalation(resp.text):
                            vulnerabilities.append({
                                "type": "Privilege Escalation",
                                "severity": "Critical",
                                "endpoint": url,
                                "payload": data,
                                "evidence": resp.text[:200],
                                "owasp_category": "API5"
                            })
                            break

                    except:
                        pass

        except Exception as e:
            self.logger.debug(f"Privilege escalation test error: {str(e)}")

        return vulnerabilities

    def _test_cors(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for CORS misconfiguration."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test with different origins
            test_origins = [
                "https://attacker.com",
                "https://evil.com",
                "*",
            ]

            for origin in test_origins:
                try:
                    headers = {"Origin": origin}
                    resp = self.http_client.get(url, headers=headers, timeout=config.timeout)

                    is_misconfig, vuln_type = Validators.is_cors_misconfigured(resp.headers, origin)

                    if is_misconfig:
                        vulnerabilities.append({
                            "type": "CORS Misconfiguration",
                            "severity": "High",
                            "endpoint": url,
                            "evidence": vuln_type,
                            "owasp_category": "API7"
                        })
                        break

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"CORS test error: {str(e)}")

        return vulnerabilities

    def _test_security_headers(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for missing security headers."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            resp = self.http_client.get(url, timeout=config.timeout)

            has_missing, missing_headers = Validators.is_missing_security_header(resp.headers)

            if has_missing:
                for missing in missing_headers:
                    vulnerabilities.append({
                        "type": "Missing Security Header",
                        "severity": "Medium",
                        "endpoint": url,
                        "evidence": missing,
                        "owasp_category": "API7"
                    })

        except Exception as e:
            self.logger.debug(f"Security headers test error: {str(e)}")

        return vulnerabilities

    def _test_unsafe_redirects(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for unsafe redirects."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test with redirect parameter
            redirect_params = ["redirect", "return_url", "next", "url", "target"]

            for param in redirect_params:
                try:
                    test_url = f"{url}?{param}=javascript:alert(1)"
                    resp = self.http_client.get(
                        test_url,
                        timeout=config.timeout,
                        allow_redirects=False
                    )

                    location = resp.headers.get("Location", "")

                    if Validators.is_unsafe_redirect(location, url):
                        vulnerabilities.append({
                            "type": "Unsafe Redirect",
                            "severity": "Medium",
                            "endpoint": test_url,
                            "evidence": f"Redirect to: {location}",
                            "owasp_category": "API7"
                        })

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Unsafe redirect test error: {str(e)}")

        return vulnerabilities

    def _extract_jwt_from_endpoint(self, endpoint: Dict, config: Config) -> List[str]:
        """Extract JWT tokens from endpoint responses."""
        tokens = []

        try:
            url = urljoin(config.url, endpoint.get('path', ''))
            resp = self.http_client.get(url, timeout=config.timeout)

            # Check response for JWT patterns
            import re

            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*'
            matches = re.findall(jwt_pattern, resp.text)

            tokens.extend(matches[:5])  # Limit to 5 tokens

        except Exception as e:
            self.logger.debug(f"JWT extraction error: {str(e)}")

        return tokens
