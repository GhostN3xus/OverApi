"""Enhanced security vulnerability tester with Deep Validation."""

import json
import re
import time
import difflib
import hashlib
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urljoin

from ..core.logger import Logger
from ..core.config import Config
from ..core.constants import (
    DEFAULT_SQLI_PAYLOAD_LIMIT,
    DEFAULT_XSS_PAYLOAD_LIMIT,
    DEFAULT_CMD_INJECTION_PAYLOAD_LIMIT,
    RATE_LIMIT_TEST_REQUESTS,
    RATE_LIMIT_TEST_DELAY,
    NON_VULNERABILITY_STATUS_CODES,
    SENSITIVE_KEYWORDS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM
)
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
        self._baseline_cache = {}  # Cache for baseline responses

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

    def _get_baseline_response(self, url: str, config: Config, method: str = 'GET') -> Optional[Dict]:
        """
        Get and cache baseline response for an endpoint.

        Args:
            url: URL to test
            config: Configuration
            method: HTTP method

        Returns:
            Dict with baseline response data or None
        """
        cache_key = hashlib.md5(f"{method}:{url}".encode()).hexdigest()

        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        try:
            if method == 'GET':
                resp = self.http_client.get(url, timeout=config.timeout)
            elif method == 'POST':
                resp = self.http_client.post(url, timeout=config.timeout)
            else:
                return None

            baseline = {
                'status_code': resp.status_code,
                'text': resp.text,
                'length': len(resp.text),
                'headers': dict(resp.headers)
            }

            self._baseline_cache[cache_key] = baseline
            return baseline

        except Exception as e:
            self.logger.debug(f"Failed to get baseline: {str(e)}")
            return None

    def _calculate_response_similarity(self, resp1: str, resp2: str) -> float:
        """
        Calculate similarity ratio between two responses.

        Args:
            resp1: First response text
            resp2: Second response text

        Returns:
            Similarity ratio (0.0 to 1.0)
        """
        return difflib.SequenceMatcher(None, resp1, resp2).ratio()

    def _responses_are_similar(self, resp1: str, resp2: str, threshold: float = 0.95) -> bool:
        """
        Check if two responses are similar enough to be considered the same.

        Args:
            resp1: First response text
            resp2: Second response text
            threshold: Similarity threshold (default 0.95 = 95%)

        Returns:
            True if responses are similar
        """
        # Handle empty responses
        if not resp1 and not resp2:
            return True
        if not resp1 or not resp2:
            return False

        # Length difference check - if very different, likely different
        len_ratio = min(len(resp1), len(resp2)) / max(len(resp1), len(resp2))
        if len_ratio < 0.5:
            return False

        # Calculate text similarity
        similarity = self._calculate_response_similarity(resp1, resp2)
        return similarity >= threshold

    def _test_broken_authentication(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for broken authentication with improved validation."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test without authentication
            resp_unauth = self.http_client.get(url, timeout=config.timeout)

            # Only report if it returns success AND contains actual sensitive data
            if resp_unauth.status_code in [200, 201]:
                # More sophisticated detection of sensitive data
                response_lower = resp_unauth.text.lower()

                # Check for sensitive JSON keys (not just keywords in text)
                sensitive_json_keys = []
                try:
                    data = json.loads(resp_unauth.text)
                    if isinstance(data, dict):
                        keys = list(data.keys())
                        sensitive_json_keys = [k for k in keys if any(
                            s in k.lower() for s in ['password', 'secret', 'api_key', 'token', 'private']
                        )]
                except:
                    pass

                # Check for structured sensitive data patterns
                has_sensitive_pattern = any([
                    # API responses with user/admin data structures
                    re.search(r'"(user|admin)"\s*:\s*{[^}]*"(id|email|password|token)"', response_lower),
                    # Authentication tokens in JSON
                    re.search(r'"(access_token|auth_token|api_key)"\s*:\s*"[^"]{20,}"', response_lower),
                    # Admin/configuration endpoints
                    re.search(r'"(is_admin|role)"\s*:\s*(true|"admin")', response_lower),
                    # Private/internal configuration
                    re.search(r'"(database|db_|config)"\s*:\s*{', response_lower),
                ])

                # Only report if we found actual sensitive structures or keys
                if sensitive_json_keys or has_sensitive_pattern:
                    # Additional check: verify it's not just documentation
                    is_documentation = any([
                        'example' in response_lower and 'api' in response_lower,
                        'documentation' in response_lower,
                        'swagger' in response_lower,
                        '<html' in response_lower  # HTML documentation page
                    ])

                    if not is_documentation:
                        evidence = f"Endpoint returns sensitive data without authentication (Status: {resp_unauth.status_code})"
                        if sensitive_json_keys:
                            evidence += f". Found sensitive keys: {', '.join(sensitive_json_keys[:3])}"

                        vulnerabilities.append(self._create_vulnerability_record(
                            "Broken Authentication",
                            "High",
                            url,
                            evidence
                        ))

        except Exception as e:
            self.logger.debug(f"Auth test error: {str(e)}")

        return vulnerabilities

    def _test_bola(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for Broken Object Level Authorization (IDOR) with response comparison."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # Test ID parameter variations
            test_ids = ['1', '2', '999', '12345', '-1']

            # Identify ID parameters in URL or query string
            has_id_param = any(param in url.lower() for param in ['{id}', '{user_id}', '{userid}', 'id='])

            if has_id_param or re.search(r'/\d+/?$', url):
                responses = {}

                # Collect responses for different IDs
                for test_id in test_ids:
                    try:
                        # Replace various ID patterns
                        test_url = url
                        test_url = test_url.replace('{id}', test_id)
                        test_url = test_url.replace('{user_id}', test_id)
                        test_url = test_url.replace('{userId}', test_id)
                        test_url = re.sub(r'/\d+/?$', f'/{test_id}', test_url)

                        resp = self.http_client.get(test_url, timeout=config.timeout)

                        if resp.status_code in [200, 201]:
                            responses[test_id] = {
                                'text': resp.text,
                                'length': len(resp.text),
                                'status': resp.status_code
                            }

                    except Exception as e:
                        self.logger.debug(f"BOLA ID test error for {test_id}: {str(e)}")
                        continue

                # Analyze responses - if we get different content for different IDs, it's BOLA
                if len(responses) >= 2:
                    response_list = list(responses.values())
                    first_resp = response_list[0]
                    different_responses = 0

                    for resp in response_list[1:]:
                        # Check if responses are significantly different
                        if not self._responses_are_similar(first_resp['text'], resp['text'], threshold=0.9):
                            different_responses += 1

                    # If we got different data for different IDs, it's likely BOLA
                    # But verify it's not just a "not found" vs "found" scenario
                    has_valid_data = any(
                        len(r['text']) > 50 and r['text'] != first_resp['text']
                        for r in response_list
                    )

                    if different_responses > 0 and has_valid_data:
                        vulnerabilities.append(self._create_vulnerability_record(
                            "BOLA (Broken Object Level Authorization)",
                            "High",
                            url,
                            f"Endpoint returns different user/object data for different IDs without authorization check. "
                            f"Tested {len(responses)} IDs, {different_responses + 1} returned different data."
                        ))

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
            except Exception as e:
                self.logger.debug(f"Baseline request failed: {str(e)}")
                baseline_data = {}

            # SQL Injection - Error-based and Time-based
            sqli_payloads = self.advanced_payloads.get_sqli_payloads()

            # Test with error-based payloads first (faster)
            error_based_payloads = [p for p in sqli_payloads if "'" in p or '"' in p][:5]

            for payload in error_based_payloads:
                try:
                    # Try common parameter names
                    param_names = ["id", "user_id", "q", "search", "filter"]

                    for param_name in param_names:
                        params = {param_name: payload}
                        start_time = time.time()
                        resp = self.http_client.get(url, params=params, timeout=config.timeout)
                        response_time = time.time() - start_time

                        # Check for SQL errors in response
                        if Validators.is_sql_injection(resp.text, payload, response_time):
                            # Verify it's different from baseline
                            if baseline_data and not self._responses_are_similar(
                                baseline_data.get('text', ''),
                                resp.text,
                                threshold=0.95
                            ):
                                # Extract specific error message for evidence
                                error_match = re.search(
                                    r'(SQL syntax|mysql|postgresql|ORA-\d+|syntax error)[^\n]{0,100}',
                                    resp.text,
                                    re.IGNORECASE
                                )
                                error_detail = error_match.group(0) if error_match else "SQL error detected"

                                vulnerabilities.append(self._create_vulnerability_record(
                                    "SQL Injection",
                                    "Critical",
                                    url,
                                    f"SQL error-based injection in parameter '{param_name}': {error_detail}",
                                    payload
                                ))
                                break  # Stop testing this endpoint

                        # Short delay between parameter tests
                        time.sleep(0.1)

                    if vulnerabilities:
                        break  # Already found SQLi

                except Exception as e:
                    self.logger.debug(f"SQLi test error: {str(e)}")

            # If no error-based SQLi found, try time-based blind SQLi (only 2 payloads)
            if not vulnerabilities and len(sqli_payloads) > 5:
                time_based_payloads = [
                    "1' AND SLEEP(5)--",
                    "1'; WAITFOR DELAY '0:0:5'--"
                ]

                for payload in time_based_payloads:
                    try:
                        params = {"id": payload}
                        start_time = time.time()
                        resp = self.http_client.get(url, params=params, timeout=10)
                        response_time = time.time() - start_time

                        # If response took significantly longer (>4 seconds), likely time-based SQLi
                        if response_time > 4.5:
                            vulnerabilities.append(self._create_vulnerability_record(
                                "SQL Injection (Time-based Blind)",
                                "Critical",
                                url,
                                f"Time-based blind SQL injection detected. Response delayed by {response_time:.2f}s",
                                payload
                            ))
                            break

                    except Exception as e:
                        self.logger.debug(f"Time-based SQLi test error: {str(e)}")

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
                except Exception as e:
                    self.logger.debug(f"XSS test error: {str(e)}")

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
                except Exception as e:
                    self.logger.debug(f"Command injection test error: {str(e)}")

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
        """Test for lack of rate limiting with aggressive testing."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        if config.enable_ratelimit_tests:
            try:
                # Make rapid requests - 30 requests with minimal delay
                rate_limited = False
                success_count = 0

                for i in range(30):
                    try:
                        resp = self.http_client.get(url, timeout=config.timeout)

                        # Check if rate limited
                        if Validators.is_rate_limited(resp.status_code, resp.headers):
                            rate_limited = True
                            break

                        # Count successful responses
                        if resp.status_code in [200, 201]:
                            success_count += 1

                        # Very short delay (100 req/sec)
                        time.sleep(0.01)

                    except Exception as e:
                        # Network errors don't indicate rate limiting
                        self.logger.debug(f"Request {i} failed: {str(e)}")
                        continue

                # Only report if we successfully made many requests without rate limiting
                if not rate_limited and success_count >= 20:
                    vulnerabilities.append(self._create_vulnerability_record(
                        "Lack of Rate Limiting",
                        "Medium",
                        url,
                        f"No rate limiting detected after {success_count} rapid requests (100 req/sec). "
                        f"Endpoint may be vulnerable to brute force or DoS attacks."
                    ))

            except Exception as e:
                self.logger.debug(f"Rate limit test error: {str(e)}")

        return vulnerabilities

    def _test_token_validation(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test for weak API key/token validation with improved detection."""
        vulnerabilities = []
        url = urljoin(config.url, endpoint.get('path', ''))

        try:
            # First, establish baseline - check if endpoint normally requires auth
            resp_no_auth = self.http_client.get(url, timeout=config.timeout)

            # If endpoint is publicly accessible (200/201 without auth), it doesn't require token validation
            # This is normal for public endpoints, not a vulnerability
            if resp_no_auth.status_code in [200, 201]:
                # Skip token validation tests for public endpoints
                return vulnerabilities

            # If we get 401/403, endpoint requires authentication - test token validation
            if resp_no_auth.status_code in [401, 403]:
                baseline_unauth_response = resp_no_auth.text

                # Test with invalid tokens
                invalid_tokens = ["invalid", "test123", "x" * 50, "Bearer invalid"]

                for token in invalid_tokens:
                    try:
                        headers = {"Authorization": f"Bearer {token}" if not token.startswith("Bearer") else token}
                        resp_invalid = self.http_client.get(url, headers=headers, timeout=config.timeout)

                        # If invalid token gives 200/201, that's weak validation
                        if resp_invalid.status_code in [200, 201]:
                            # Verify response is different from unauthenticated request
                            if not self._responses_are_similar(baseline_unauth_response, resp_invalid.text):
                                vulnerabilities.append(self._create_vulnerability_record(
                                    "Weak Token Validation",
                                    "High",
                                    url,
                                    f"Endpoint accepts invalid authentication token and returns data. "
                                    f"Expected 401/403 but got {resp_invalid.status_code}"
                                ))
                                break

                    except Exception as e:
                        self.logger.debug(f"Invalid token test error: {str(e)}")

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

                    except Exception as e:
                        self.logger.debug(f"Privilege escalation test error: {str(e)}")

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

                except Exception as e:
                    self.logger.debug(f"CORS test error: {str(e)}")

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

                except Exception as e:
                    self.logger.debug(f"Unsafe redirect test error: {str(e)}")

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
