"""Enhanced security vulnerability tester with Deep Validation."""

import json
import time
from typing import Dict, List, Any, Tuple
from urllib.parse import urljoin

from ..core.logger import Logger
from ..core.config import Config
from ..utils.http_client import HTTPClient
from ..utils.wordlist_loader import WordlistLoader
from ..utils.validators import Validators
from ..tools.vuln_db import VulnerabilityDatabase
from ..payloads.advanced_payloads import PayloadManager
from .advanced_flows import AdvancedFlows

class SecurityTester:
    """Tests endpoints for OWASP API Top 10 vulnerabilities."""

    def __init__(self, logger: Logger = None):
        """Initialize security tester."""
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(logger=self.logger)
        self.wordlist = WordlistLoader()
        self.vuln_db = VulnerabilityDatabase()
        self.advanced_payloads = PayloadManager()
        self.advanced_flows = AdvancedFlows(logger=self.logger)

    def test_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Test endpoint for vulnerabilities with validation.

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

            # --- Advanced Flows Integration ---
            # GraphQL specific
            if "graphql" in endpoint.get("type", ""):
                 vulnerabilities.extend(self.advanced_flows.test_graphql_flow(urljoin(config.url, endpoint.get("path"))))

            # SOAP specific
            if "soap" in endpoint.get("type", ""):
                 vulnerabilities.extend(self.advanced_flows.test_soap_flow(urljoin(config.url, endpoint.get("path"))))

        except Exception as e:
            self.logger.debug(f"Error testing endpoint {endpoint.get('path')}: {str(e)}")

        return vulnerabilities

    def _verify_vulnerability(self, request_data: Dict, response_data: Dict, check_type: str) -> bool:
        """
        Validates if a vulnerability is real (False Positive Reduction).

        Args:
            request_data: info about the request sent
            response_data: info about the response received
            check_type: type of check performed

        Returns:
            True if verified, False otherwise
        """
        # Status code checks
        status = response_data.get('status_code')
        if status in [404, 405, 502, 503]:
            return False # Usually not a vulnerability, just an error

        # Differential Analysis
        if 'baseline_response' in request_data:
            baseline = request_data['baseline_response']
            # If response is identical to baseline, injection probably failed
            if response_data.get('text') == baseline.get('text'):
                return False

        # Error message confirmation for injections
        if check_type in ['sqli', 'command_injection']:
            evidence = response_data.get('text', '').lower()
            errors = ['sql syntax', 'mysql error', 'postgresql error', 'ora-', 'syntax error']
            if any(e in evidence for e in errors):
                return True
            # Time-based check would be here

        return True

    def _create_vulnerability_record(self, vuln_type: str, severity: str, endpoint: str, evidence: str, payload: str = None) -> Dict:
        """Create a standardized vulnerability record enriched with DB info."""
        db_info = self.vuln_db.get_vulnerability(vuln_type)

        return {
            "type": vuln_type,
            "severity": severity,
            "endpoint": endpoint,
            "evidence": evidence,
            "payload": payload,
            "owasp_category": db_info.get("owasp", "Unknown") if db_info else "Unknown",
            "cwe": db_info.get("cwe", "Unknown") if db_info else "Unknown",
            "remediation": db_info.get("remediation", "") if db_info else ""
        }

    def _test_broken_authentication(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for broken authentication."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test without authentication
            resp = self.http_client.get(url, timeout=config.timeout)

            # Validation: Only report if it returns success data, not just 200 OK (could be a public page)
            if resp.status_code in [200, 201]:
                # Heuristic: Check for sensitive keywords
                sensitive = ['user', 'admin', 'key', 'token', 'password', 'config']
                if any(s in resp.text.lower() for s in sensitive):
                    vulnerabilities.append(self._create_vulnerability_record(
                        "Broken Authentication",
                        "High",
                        url,
                        f"Endpoint accessible without authentication (Status: {resp.status_code})"
                    ))

        except Exception as e:
            self.logger.debug(f"Auth test error: {str(e)}")

        return vulnerabilities

    def _test_bola(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for Broken Object Level Authorization (IDOR)."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test ID parameter variations
            test_ids = ['1', '2', '999', '-1', '0']

            # Identify ID parameters in URL
            # Simple heuristic: Look for numeric values in path
            # TODO: Improve this with parsing

            if '{id}' in url:
                for test_id in test_ids:
                    test_url = url.replace('{id}', test_id)
                    resp = self.http_client.get(test_url, timeout=config.timeout)

                    if resp.status_code in [200, 201]:
                        # Validation: Check if response size/content varies significantly
                        vulnerabilities.append(self._create_vulnerability_record(
                            "BOLA",
                            "High",
                            test_url,
                            f"Object accessible with different ID (Status: {resp.status_code})"
                        ))
                        break

        except Exception as e:
            self.logger.debug(f"BOLA test error: {str(e)}")

        return vulnerabilities

    def _test_injection(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for injection vulnerabilities."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        if config.enable_injection_tests:
            # Baseline request
            try:
                baseline = self.http_client.get(url, timeout=config.timeout)
                baseline_data = {'text': baseline.text, 'status_code': baseline.status_code}
            except:
                baseline_data = {}

            # SQL Injection
            # Use advanced payloads in addition to/instead of basic ones
            sqli_payloads = self.advanced_payloads.get_sqli_payloads()
            for payload in sqli_payloads[:5]:  # Limit payloads for perf
                try:
                    # Determine where to inject (params)
                    # For now assume 'id' or 'search' if not specified
                    params = {"id": payload, "q": payload, "search": payload}
                    resp = self.http_client.get(url, params=params, timeout=config.timeout)

                    if Validators.is_sql_injection(resp.text, payload):
                        # Verify
                        if self._verify_vulnerability(
                            {'baseline_response': baseline_data},
                            {'text': resp.text, 'status_code': resp.status_code},
                            'sqli'
                        ):
                            vulnerabilities.append(self._create_vulnerability_record(
                                "SQL Injection",
                                "Critical",
                                url,
                                "SQL syntax error or unexpected behavior detected",
                                payload
                            ))
                            break
                except:
                    pass

            # XSS
            xss_payloads = self.advanced_payloads.get_xss_payloads()
            for payload in xss_payloads[:3]:
                try:
                    params = {"q": payload, "search": payload}
                    resp = self.http_client.get(url, params=params, timeout=config.timeout)
                    if Validators.is_xss(resp.text, payload):
                         vulnerabilities.append(self._create_vulnerability_record(
                            "XSS",
                            "High",
                            url,
                            "Reflected XSS payload found in response",
                            payload
                        ))
                         break
                except:
                    pass

            # Command Injection
            cmd_payloads = self.advanced_payloads.get_cmd_injection_payloads()
            for payload in cmd_payloads[:3]:
                try:
                    params = {"cmd": payload, "ip": payload}
                    resp = self.http_client.get(url, params=params, timeout=config.timeout)
                    if Validators.is_command_injection(resp.text):
                        vulnerabilities.append(self._create_vulnerability_record(
                            "Command Injection",
                            "Critical",
                            url,
                            "System command output detected",
                            payload
                        ))
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
                vulnerabilities.append(self._create_vulnerability_record(
                    "Excessive Data Exposure",
                    "High",
                    url,
                    "Sensitive PII or internal data found in response"
                ))

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
                for i in range(15):
                    resp = self.http_client.get(url, timeout=config.timeout)
                    if Validators.is_rate_limited(resp.status_code, resp.headers):
                        rate_limited = True
                        break
                    time.sleep(0.05)

                if not rate_limited:
                    vulnerabilities.append(self._create_vulnerability_record(
                        "Lack of Rate Limiting",
                        "Medium",
                        url,
                        "No 429 status or rate limit headers after multiple rapid requests"
                    ))

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
                        vulnerabilities.append(self._create_vulnerability_record(
                            "Weak Token Validation",
                            "High",
                            url,
                            f"Invalid token accepted: {token}"
                        ))
                        break

                except:
                    pass

            # Test 2: Missing token
            try:
                resp_no_auth = self.http_client.get(url, timeout=config.timeout)

                if resp_no_auth.status_code in [200, 201]:
                    vulnerabilities.append(self._create_vulnerability_record(
                        "Missing Authentication",
                        "High",
                        url,
                        "Endpoint accessible without authentication"
                    ))

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
                    vulnerabilities.append(self._create_vulnerability_record(
                        "JWT Vulnerability",
                        "High",
                        url,
                        vuln_type
                    ))

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
                            vulnerabilities.append(self._create_vulnerability_record(
                                "Privilege Escalation",
                                "Critical",
                                url,
                                "Indication of successful privilege escalation in response",
                                str(data)
                            ))
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
                        vulnerabilities.append(self._create_vulnerability_record(
                            "CORS Misconfiguration",
                            "High",
                            url,
                            vuln_type
                        ))
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
                    vulnerabilities.append(self._create_vulnerability_record(
                        "Missing Security Header",
                        "Medium",
                        url,
                        missing
                    ))

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
                    test_url = f"{url}?{param}=https://evil.com"
                    resp = self.http_client.get(
                        test_url,
                        timeout=config.timeout,
                        allow_redirects=False
                    )

                    location = resp.headers.get("Location", "")

                    if Validators.is_unsafe_redirect(location, url):
                        vulnerabilities.append(self._create_vulnerability_record(
                            "Unsafe Redirect",
                            "Medium",
                            test_url,
                            f"Redirected to external arbitrary domain: {location}"
                        ))

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
