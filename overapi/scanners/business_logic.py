"""Business Logic Vulnerability Scanner for OverApi."""

import asyncio
import logging
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
import requests
from concurrent.futures import ThreadPoolExecutor


class BusinessLogicVulnerabilityType(Enum):
    """Business logic vulnerability types."""
    RACE_CONDITION = "race_condition"
    MASS_ASSIGNMENT = "mass_assignment"
    PRICE_MANIPULATION = "price_manipulation"
    WORKFLOW_BYPASS = "workflow_bypass"
    RATE_LIMIT_EVASION = "rate_limit_evasion"
    INTEGER_OVERFLOW = "integer_overflow"
    REFERRAL_ABUSE = "referral_abuse"
    DUPLICATE_TRANSACTION = "duplicate_transaction"
    INSUFFICIENT_VALIDATION = "insufficient_validation"
    STATE_INCONSISTENCY = "state_inconsistency"


@dataclass
class BusinessLogicVulnerability:
    """Business logic vulnerability finding."""
    vuln_type: BusinessLogicVulnerabilityType
    severity: str  # critical, high, medium, low
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    impact: str = ""
    poc_script: str = ""
    endpoint: str = ""
    method: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'type': self.vuln_type.value,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'impact': self.impact,
            'poc_script': self.poc_script,
            'endpoint': self.endpoint,
            'method': self.method,
        }


class BusinessLogicScanner:
    """Advanced business logic vulnerability scanner."""

    def __init__(self, target_url: str, headers: Dict[str, str] = None,
                 proxies: Dict[str, str] = None, timeout: int = 30,
                 config: Dict[str, Any] = None):
        """
        Initialize Business Logic Scanner.

        Args:
            target_url: Target API URL
            headers: Custom HTTP headers
            proxies: Proxy configuration
            timeout: Request timeout
            config: Configuration dictionary
        """
        self.target_url = target_url
        self.headers = headers or {}
        self.proxies = proxies
        self.timeout = timeout
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[BusinessLogicVulnerability] = []
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)

    async def scan(self, test_endpoints: List[Dict[str, Any]] = None) -> List[BusinessLogicVulnerability]:
        """
        Execute comprehensive business logic scan.

        Args:
            test_endpoints: List of endpoints to test

        Returns:
            List of vulnerabilities found
        """
        self.logger.info("Starting business logic vulnerability scan...")

        if not test_endpoints:
            test_endpoints = self._get_default_test_endpoints()

        # Run tests
        tests = [
            self.test_race_conditions(test_endpoints),
            self.test_mass_assignment(test_endpoints),
            self.test_price_manipulation(test_endpoints),
            self.test_workflow_bypass(test_endpoints),
            self.test_rate_limit_evasion(test_endpoints),
            self.test_integer_overflow(test_endpoints),
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)

        for result in results:
            if isinstance(result, BusinessLogicVulnerability):
                self.vulnerabilities.append(result)

        self.logger.info(f"Found {len(self.vulnerabilities)} business logic vulnerabilities")
        return self.vulnerabilities

    async def test_race_conditions(self, test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """
        Test for race condition vulnerabilities.

        Sends parallel requests to identify race-based vulnerabilities like:
        - Duplicate voucher redemption
        - Balance over-withdrawal
        - Inventory over-selling
        """
        try:
            critical_endpoints = [
                e for e in test_endpoints
                if any(keyword in e.get('path', '').lower()
                       for keyword in ['wallet', 'withdraw', 'coupon', 'redeem', 'order', 'purchase', 'balance'])
            ]

            for endpoint in critical_endpoints[:5]:  # Test top 5
                vulnerability = await self._test_endpoint_for_race(endpoint)
                if vulnerability:
                    return vulnerability

        except Exception as e:
            self.logger.error(f"Race condition test error: {str(e)}")

        return None

    async def _test_endpoint_for_race(self, endpoint: Dict[str, Any]) -> Optional[BusinessLogicVulnerability]:
        """Test single endpoint for race condition."""
        try:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'POST').upper()

            # Prepare test payload
            test_payload = self._prepare_test_payload(endpoint)

            # Send N parallel requests
            num_requests = self.config.get('race_conditions', {}).get('parallel_requests', 50)

            async def send_request():
                try:
                    url = f"{self.target_url}{path}".rstrip('/')
                    response = self.session.request(
                        method=method,
                        url=url,
                        json=test_payload,
                        headers=self.headers,
                        timeout=self.timeout,
                    )
                    return response
                except Exception:
                    return None

            # Execute parallel requests
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(None, send_request) for _ in range(num_requests)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze responses
            successful = [r for r in responses if r and hasattr(r, 'status_code') and r.status_code == 200]

            if len(successful) > 1:
                # Multiple successful responses indicate race condition
                return BusinessLogicVulnerability(
                    vuln_type=BusinessLogicVulnerabilityType.RACE_CONDITION,
                    severity="critical",
                    title="Race Condition Vulnerability",
                    description=f"Endpoint {path} vulnerable to race conditions. Multiple parallel requests succeeded when only one should.",
                    evidence={
                        'endpoint': path,
                        'method': method,
                        'parallel_requests_sent': num_requests,
                        'successful_responses': len(successful),
                        'expected_successes': 1,
                    },
                    remediation="Implement locking mechanism. Use database transactions. Add atomic operations.",
                    cvss_score=8.2,
                    cwe_id="CWE-362",
                    owasp_category="API8:2023 Security Misconfiguration",
                    impact="Business logic bypass, financial loss, inventory inconsistency",
                    endpoint=path,
                    method=method,
                )

        except Exception as e:
            self.logger.debug(f"Race condition test error for {endpoint}: {str(e)}")

        return None

    async def test_mass_assignment(self, test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """
        Test for mass assignment vulnerabilities.

        Attempts to set unauthorized fields in POST/PUT requests.
        """
        try:
            post_endpoints = [e for e in test_endpoints if e.get('method', '').upper() in ['POST', 'PUT', 'PATCH']]

            for endpoint in post_endpoints[:5]:
                vulnerability = await self._test_endpoint_for_mass_assignment(endpoint)
                if vulnerability:
                    return vulnerability

        except Exception as e:
            self.logger.error(f"Mass assignment test error: {str(e)}")

        return None

    async def _test_endpoint_for_mass_assignment(self, endpoint: Dict[str, Any]) -> Optional[BusinessLogicVulnerability]:
        """Test single endpoint for mass assignment."""
        try:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'POST').upper()

            # Prepare base payload
            base_payload = self._prepare_test_payload(endpoint)

            # Test various unauthorized fields
            unauthorized_fields = [
                'role', 'admin', 'is_admin', 'permissions', 'is_verified',
                'balance', 'credit', 'credits', 'points', 'level',
                'status', 'is_active', 'is_premium', 'subscription_type',
            ]

            for field in unauthorized_fields:
                test_payload = {**base_payload, field: True}

                url = f"{self.target_url}{path}".rstrip('/')
                response = self.session.request(
                    method=method,
                    url=url,
                    json=test_payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )

                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        if field in json.dumps(response_data).lower():
                            return BusinessLogicVulnerability(
                                vuln_type=BusinessLogicVulnerabilityType.MASS_ASSIGNMENT,
                                severity="high",
                                title="Mass Assignment Vulnerability",
                                description=f"Endpoint accepts unauthorized field '{field}' in request",
                                evidence={
                                    'endpoint': path,
                                    'method': method,
                                    'unauthorized_field': field,
                                    'response_status': response.status_code,
                                },
                                remediation="Use allowlist of permitted fields. Explicitly define which fields can be set by users.",
                                cvss_score=7.5,
                                cwe_id="CWE-915",
                                owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows",
                                impact="Privilege escalation, account takeover, data manipulation",
                                endpoint=path,
                                method=method,
                            )
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            self.logger.debug(f"Mass assignment test error: {str(e)}")

        return None

    async def test_price_manipulation(self, test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """
        Test for price/amount manipulation vulnerabilities.

        Tests negative prices, zero prices, overflow, and decimal precision.
        """
        try:
            e_commerce_endpoints = [
                e for e in test_endpoints
                if any(keyword in e.get('path', '').lower()
                       for keyword in ['price', 'amount', 'payment', 'order', 'cart', 'checkout'])
            ]

            for endpoint in e_commerce_endpoints[:5]:
                vulnerability = await self._test_endpoint_for_price_manipulation(endpoint)
                if vulnerability:
                    return vulnerability

        except Exception as e:
            self.logger.error(f"Price manipulation test error: {str(e)}")

        return None

    async def _test_endpoint_for_price_manipulation(self, endpoint: Dict[str, Any]) -> Optional[BusinessLogicVulnerability]:
        """Test single endpoint for price manipulation."""
        try:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'POST').upper()

            test_cases = [
                ({'price': -100, 'amount': 100}, "Negative price"),
                ({'price': 0, 'amount': 100}, "Zero price"),
                ({'price': 0.001, 'amount': 100}, "Decimal precision"),
                ({'price': 2147483647, 'amount': 100}, "Integer overflow"),
                ({'price': -2147483648, 'amount': 100}, "Negative overflow"),
            ]

            for payload_update, description in test_cases:
                test_payload = self._prepare_test_payload(endpoint)
                test_payload.update(payload_update)

                url = f"{self.target_url}{path}".rstrip('/')
                response = self.session.request(
                    method=method,
                    url=url,
                    json=test_payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )

                if response.status_code == 200:
                    return BusinessLogicVulnerability(
                        vuln_type=BusinessLogicVulnerabilityType.PRICE_MANIPULATION,
                        severity="critical",
                        title="Price Manipulation Vulnerability",
                        description=f"Endpoint allows {description} in payment/order endpoint",
                        evidence={
                            'endpoint': path,
                            'method': method,
                            'test_case': description,
                            'payload': payload_update,
                            'response_status': response.status_code,
                        },
                        remediation="Validate all price/amount fields. Ensure values are positive. Implement server-side price calculation.",
                        cvss_score=9.0,
                        cwe_id="CWE-129",
                        owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        impact="Financial fraud, free services, negative charges",
                        endpoint=path,
                        method=method,
                    )

        except Exception as e:
            self.logger.debug(f"Price manipulation test error: {str(e)}")

        return None

    async def test_workflow_bypass(self, test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """
        Test for workflow bypass vulnerabilities.

        Attempts to skip required steps in multi-step processes.
        """
        try:
            # Define workflow patterns
            workflows = [
                {
                    'name': 'checkout',
                    'steps': ['cart', 'address', 'payment', 'confirm'],
                    'test_skip': ['address', 'payment'],  # Skip to confirm
                },
                {
                    'name': 'registration',
                    'steps': ['signup', 'verify_email', 'complete_profile'],
                    'test_skip': ['verify_email'],  # Skip email verification
                },
                {
                    'name': 'approval',
                    'steps': ['request', 'review', 'approve'],
                    'test_skip': ['review'],  # Skip review step
                },
            ]

            for workflow in workflows:
                vulnerability = await self._test_workflow_bypass(workflow, test_endpoints)
                if vulnerability:
                    return vulnerability

        except Exception as e:
            self.logger.error(f"Workflow bypass test error: {str(e)}")

        return None

    async def _test_workflow_bypass(self, workflow: Dict[str, Any],
                                   test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """Test workflow for bypass opportunities."""
        try:
            workflow_name = workflow['name']
            steps = workflow['steps']

            # Try to access final step directly, skipping intermediate steps
            final_step = steps[-1]

            # Find endpoint for final step
            for endpoint in test_endpoints:
                path = endpoint.get('path', '').lower()
                if final_step in path:
                    test_payload = self._prepare_test_payload(endpoint)
                    # Try with minimal data (skipping previous steps)
                    test_payload['workflow_step'] = final_step
                    test_payload['skip_verification'] = True

                    url = f"{self.target_url}{endpoint['path']}".rstrip('/')
                    response = self.session.request(
                        method=endpoint.get('method', 'POST').upper(),
                        url=url,
                        json=test_payload,
                        headers=self.headers,
                        timeout=self.timeout,
                    )

                    if response.status_code == 200:
                        return BusinessLogicVulnerability(
                            vuln_type=BusinessLogicVulnerabilityType.WORKFLOW_BYPASS,
                            severity="critical",
                            title="Workflow Bypass Vulnerability",
                            description=f"{workflow_name} workflow can be bypassed by skipping intermediate steps",
                            evidence={
                                'workflow': workflow_name,
                                'bypassed_steps': workflow['test_skip'],
                                'endpoint': endpoint['path'],
                                'response_status': response.status_code,
                            },
                            remediation="Enforce sequential workflow. Validate all required steps completed. Use state machines.",
                            cvss_score=8.5,
                            cwe_id="CWE-862",
                            owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            impact="Unauthorized transactions, unverified users, skipped approvals",
                            endpoint=endpoint['path'],
                            method=endpoint.get('method', 'POST'),
                        )

        except Exception as e:
            self.logger.debug(f"Workflow bypass test error: {str(e)}")

        return None

    async def test_rate_limit_evasion(self, test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """
        Test for rate limit evasion techniques.

        Tests header manipulation, URL encoding, method variations.
        """
        try:
            for endpoint in test_endpoints[:10]:
                vulnerability = await self._test_endpoint_for_rate_limit_evasion(endpoint)
                if vulnerability:
                    return vulnerability

        except Exception as e:
            self.logger.error(f"Rate limit evasion test error: {str(e)}")

        return None

    async def _test_endpoint_for_rate_limit_evasion(self, endpoint: Dict[str, Any]) -> Optional[BusinessLogicVulnerability]:
        """Test single endpoint for rate limit bypass."""
        try:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'POST').upper()

            # Evasion techniques
            evasion_payloads = [
                ({'headers': {'X-Forwarded-For': '192.168.1.1'}}, 'X-Forwarded-For spoofing'),
                ({'headers': {'X-Real-IP': '10.0.0.1'}}, 'X-Real-IP spoofing'),
                ({'path': f"{path}%00"}, 'Null byte injection'),
                ({'path': f"{path}?cache_buster={time.time()}"}, 'Cache buster parameter'),
            ]

            for payload_update, technique_name in evasion_payloads:
                url = f"{self.target_url}{path}".rstrip('/')

                if 'path' in payload_update:
                    url = f"{self.target_url}{payload_update['path']}".rstrip('/')

                test_headers = {**self.headers}
                if 'headers' in payload_update:
                    test_headers.update(payload_update['headers'])

                # Send multiple rapid requests
                responses = []
                for _ in range(10):
                    try:
                        response = self.session.request(
                            method=method,
                            url=url,
                            headers=test_headers,
                            timeout=self.timeout,
                        )
                        responses.append(response.status_code)
                    except:
                        pass

                # If we got successful responses when we should be rate limited
                successful_count = sum(1 for sc in responses if sc == 200)
                if successful_count >= 5:  # At least 5 successful requests
                    return BusinessLogicVulnerability(
                        vuln_type=BusinessLogicVulnerabilityType.RATE_LIMIT_EVASION,
                        severity="high",
                        title="Rate Limit Evasion",
                        description=f"Rate limiting can be bypassed using {technique_name}",
                        evidence={
                            'endpoint': path,
                            'evasion_technique': technique_name,
                            'successful_requests': successful_count,
                            'total_requests': 10,
                        },
                        remediation="Implement rate limiting on server-side IPs, not headers. Use API keys or JWTs.",
                        cvss_score=6.5,
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption",
                        impact="Brute force attacks, DoS, resource exhaustion",
                        endpoint=path,
                        method=method,
                    )

        except Exception as e:
            self.logger.debug(f"Rate limit evasion test error: {str(e)}")

        return None

    async def test_integer_overflow(self, test_endpoints: List[Dict[str, Any]]) -> Optional[BusinessLogicVulnerability]:
        """
        Test for integer overflow/underflow vulnerabilities.

        Tests with large positive/negative numbers.
        """
        try:
            for endpoint in test_endpoints[:5]:
                vulnerability = await self._test_endpoint_for_integer_overflow(endpoint)
                if vulnerability:
                    return vulnerability

        except Exception as e:
            self.logger.error(f"Integer overflow test error: {str(e)}")

        return None

    async def _test_endpoint_for_integer_overflow(self, endpoint: Dict[str, Any]) -> Optional[BusinessLogicVulnerability]:
        """Test single endpoint for integer overflow."""
        try:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'POST').upper()

            test_values = [
                -1, 0, -100, 2147483647, 2147483648, 9223372036854775807, -9223372036854775808
            ]

            for value in test_values:
                test_payload = self._prepare_test_payload(endpoint)

                # Try common numeric field names
                for field in ['quantity', 'amount', 'count', 'id', 'value', 'price']:
                    if field in test_payload:
                        test_payload[field] = value
                        break
                else:
                    # Add to payload if not found
                    test_payload['quantity'] = value

                url = f"{self.target_url}{path}".rstrip('/')
                response = self.session.request(
                    method=method,
                    url=url,
                    json=test_payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )

                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        # Check if value was accepted or caused unexpected behavior
                        if 'error' not in json.dumps(response_data).lower():
                            return BusinessLogicVulnerability(
                                vuln_type=BusinessLogicVulnerabilityType.INTEGER_OVERFLOW,
                                severity="medium",
                                title="Integer Overflow Vulnerability",
                                description=f"Endpoint accepts extreme integer values ({value}) without proper validation",
                                evidence={
                                    'endpoint': path,
                                    'test_value': value,
                                    'response_status': response.status_code,
                                },
                                remediation="Validate numeric inputs. Use range checks. Consider using unsigned integers when appropriate.",
                                cvss_score=5.3,
                                cwe_id="CWE-190",
                                owasp_category="API3:2023 Broken Object Level Authorization",
                                impact="Unexpected behavior, data corruption, bypass of business logic",
                                endpoint=path,
                                method=method,
                            )
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            self.logger.debug(f"Integer overflow test error: {str(e)}")

        return None

    def _prepare_test_payload(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a test payload for endpoint."""
        # Extract parameter information if available
        params = endpoint.get('parameters', {})

        payload = {}

        # Add common test values for known parameter types
        if 'id' in params or 'user_id' in params:
            payload['user_id'] = 1
        if 'name' in params:
            payload['name'] = 'Test'
        if 'email' in params:
            payload['email'] = 'test@test.com'
        if 'price' in params or 'amount' in params:
            payload['price'] = 100
        if 'quantity' in params:
            payload['quantity'] = 1

        return payload

    def _get_default_test_endpoints(self) -> List[Dict[str, Any]]:
        """Get default endpoints to test."""
        return [
            {'path': '/api/wallet/withdraw', 'method': 'POST'},
            {'path': '/api/coupon/redeem', 'method': 'POST'},
            {'path': '/api/order/create', 'method': 'POST'},
            {'path': '/api/order/checkout', 'method': 'POST'},
            {'path': '/api/payment/process', 'method': 'POST'},
            {'path': '/api/user/register', 'method': 'POST'},
            {'path': '/api/user/update', 'method': 'PUT'},
            {'path': '/api/transfer', 'method': 'POST'},
            {'path': '/api/refund', 'method': 'POST'},
            {'path': '/api/discount/apply', 'method': 'POST'},
        ]

    def generate_poc(self, vulnerability: BusinessLogicVulnerability) -> str:
        """Generate PoC for vulnerability."""
        poc_template = """#!/usr/bin/env python3
# PoC for {title}
# Target: {target}

import requests
import json
import time

TARGET = "{target}"
ENDPOINT = "{endpoint}"

def exploit():
    headers = {{
        "User-Agent": "OverApi-PoC/1.0"
    }}

    payload = {{
        # Add payload based on vulnerability type
    }}

    try:
        response = requests.post(
            f"{{TARGET}}{{ENDPOINT}}",
            json=payload,
            headers=headers,
            timeout=10
        )

        print(f"[*] Status: {{response.status_code}}")
        print(f"[*] Response: {{response.text[:500]}}")

        if response.status_code == 200:
            print("[+] VULNERABILITY CONFIRMED!")
        else:
            print("[-] Target appears patched")

    except Exception as e:
        print(f"[!] Error: {{e}}")

if __name__ == "__main__":
    exploit()
"""

        return poc_template.format(
            title=vulnerability.title,
            target=self.target_url,
            endpoint=vulnerability.endpoint,
        )
