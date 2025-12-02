"""Webhook API scanner module."""

import json
import hmac
import hashlib
import time
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse

from ...core.logger import Logger
from ...core.config import Config
from ...utils.http_client import HTTPClient
from ...utils.validators import Validators


class WebhookScanner:
    """Scanner for Webhook APIs."""

    def __init__(self, logger: Logger = None):
        """Initialize Webhook scanner."""
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(logger=self.logger)

    def discover(self, url: str, config: Config) -> List[Dict[str, Any]]:
        """
        Discover Webhook endpoints.

        Args:
            url: Target URL
            config: Configuration object

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Try to find webhook endpoints
            endpoints.extend(self._scan_webhook_endpoints(url, config))

            # Try to get webhook configuration from API
            endpoints.extend(self._scan_webhook_config(url, config))

        except Exception as e:
            self.logger.debug(f"Error discovering webhook endpoints: {str(e)}")

        return endpoints

    def _scan_webhook_endpoints(self, url: str, config: Config) -> List[Dict]:
        """Scan for common webhook endpoints."""
        endpoints = []
        common_endpoints = [
            "/webhooks",
            "/webhook",
            "/hooks",
            "/api/webhooks",
            "/api/webhook",
            "/v1/webhooks",
            "/webhooks/list",
            "/webhooks/create",
            "/webhooks/events",
            "/webhook/events",
            "/notifications/webhooks",
            "/settings/webhooks",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in common_endpoints:
            try:
                test_url = base_url + endpoint

                # Try GET request
                resp = self.http_client.get(test_url, timeout=config.timeout)

                if resp.status_code != 404:
                    endpoints.append({
                        "path": endpoint,
                        "method": "GET",
                        "type": "Webhook",
                        "status": resp.status_code,
                        "accessible": resp.status_code in [200, 400]
                    })

                # Try POST request for webhook creation
                resp_post = self.http_client.post(
                    test_url,
                    json={"url": "http://attacker.com/webhook"},
                    timeout=config.timeout
                )

                if resp_post.status_code not in [404, 405]:
                    endpoints.append({
                        "path": endpoint,
                        "method": "POST",
                        "type": "Webhook",
                        "status": resp_post.status_code,
                        "accessible": True,
                        "description": "Webhook creation/registration endpoint"
                    })

            except Exception as e:
                self.logger.debug(f"Webhook endpoint scan error: {str(e)}")

        return endpoints

    def _scan_webhook_config(self, url: str, config: Config) -> List[Dict]:
        """Scan for webhook configuration endpoints."""
        endpoints = []

        try:
            config_endpoints = [
                "/api/webhooks/config",
                "/api/webhooks/events",
                "/webhooks/events",
                "/api/events",
                "/events",
            ]

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for endpoint in config_endpoints:
                try:
                    resp = self.http_client.get(
                        base_url + endpoint,
                        timeout=config.timeout
                    )

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            endpoints.append({
                                "path": endpoint,
                                "method": "GET",
                                "type": "Webhook",
                                "status": resp.status_code,
                                "events": data.get("events", []),
                                "accessible": True
                            })
                        except:
                            pass

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Webhook config scan error: {str(e)}")

        return endpoints

    def test_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Test webhook endpoint for vulnerabilities.

        Args:
            endpoint: Endpoint configuration
            config: Configuration object

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        try:
            # Test for authentication bypass
            if self._test_unauthenticated_access(endpoint, config):
                vulnerabilities.append({
                    "type": "Unauthenticated Webhook",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Webhook endpoint accessible without authentication",
                    "owasp_category": "API2"
                })

            # Test for insecure signature verification
            if self._test_insecure_signature(endpoint, config):
                vulnerabilities.append({
                    "type": "Insecure Webhook Signature",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Webhook signature verification is weak or missing",
                    "owasp_category": "API2"
                })

            # Test for SSRF via webhook URL
            if self._test_ssrf_via_webhook(endpoint, config):
                vulnerabilities.append({
                    "type": "Webhook SSRF",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Server-side request forgery possible via webhook URL",
                    "owasp_category": "API8"
                })

            # Test for webhook replay attacks
            if self._test_replay_attack(endpoint, config):
                vulnerabilities.append({
                    "type": "Webhook Replay Attack",
                    "severity": "Medium",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Webhook messages are replayed without nonce validation",
                    "owasp_category": "API4"
                })

            # Test for webhook enumeration
            if self._test_webhook_enumeration(endpoint, config):
                vulnerabilities.append({
                    "type": "Webhook Enumeration",
                    "severity": "Medium",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Webhooks can be enumerated to discover other users/services",
                    "owasp_category": "API9"
                })

        except Exception as e:
            self.logger.debug(f"Error testing webhook endpoint: {str(e)}")

        return vulnerabilities

    def _test_unauthenticated_access(self, endpoint: Dict, config: Config) -> bool:
        """Test if webhook endpoint is accessible without authentication."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            resp = self.http_client.get(url, timeout=config.timeout)

            # If we get 200/201 without auth, it's accessible
            if resp.status_code in [200, 201]:
                return True

            # If we can POST without auth
            resp_post = self.http_client.post(
                url,
                json={"url": "http://test.com"},
                timeout=config.timeout
            )

            return resp_post.status_code in [200, 201, 400]

        except Exception as e:
            self.logger.debug(f"Unauthenticated access test error: {str(e)}")

        return False

    def _test_insecure_signature(self, endpoint: Dict, config: Config) -> bool:
        """Test for insecure webhook signature verification."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            # Create test payload
            payload = json.dumps({"event": "test", "data": {}})

            # Test 1: Send without signature
            resp1 = self.http_client.post(
                url,
                data=payload,
                timeout=config.timeout,
                headers={"Content-Type": "application/json"}
            )

            # Test 2: Send with invalid signature
            fake_sig = hashlib.sha256(b"wrong").hexdigest()
            headers = {
                "Content-Type": "application/json",
                "X-Webhook-Signature": fake_sig
            }

            resp2 = self.http_client.post(
                url,
                data=payload,
                timeout=config.timeout,
                headers=headers
            )

            # If both work, signature is not properly validated
            if resp1.status_code in [200, 201] or resp2.status_code in [200, 201]:
                return True

        except Exception as e:
            self.logger.debug(f"Signature test error: {str(e)}")

        return False

    def _test_ssrf_via_webhook(self, endpoint: Dict, config: Config) -> bool:
        """Test for SSRF vulnerability in webhook URL."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            # Test with internal URLs
            ssrf_payloads = [
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://169.254.169.254/latest/meta-data",  # AWS metadata
                "http://metadata.google.internal/computeMetadata",  # GCP metadata
                "file:///etc/passwd",
                "http://[::1]:80",  # IPv6 localhost
            ]

            for ssrf_url in ssrf_payloads:
                try:
                    resp = self.http_client.post(
                        url,
                        json={"url": ssrf_url},
                        timeout=config.timeout
                    )

                    # Check if server tried to access the URL
                    if resp.status_code in [200, 201]:
                        return True

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"SSRF test error: {str(e)}")

        return False

    def _test_replay_attack(self, endpoint: Dict, config: Config) -> bool:
        """Test for webhook replay attack vulnerability."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            # Create test payload with timestamp
            payload = json.dumps({
                "event": "test",
                "timestamp": int(time.time()),
                "data": {"test": "data"}
            })

            # Send same payload twice
            resp1 = self.http_client.post(
                url,
                data=payload,
                timeout=config.timeout,
                headers={"Content-Type": "application/json"}
            )

            time.sleep(0.5)

            resp2 = self.http_client.post(
                url,
                data=payload,
                timeout=config.timeout,
                headers={"Content-Type": "application/json"}
            )

            # If both succeed with same payload, replay is possible
            if resp1.status_code in [200, 201] and resp2.status_code in [200, 201]:
                return True

        except Exception as e:
            self.logger.debug(f"Replay test error: {str(e)}")

        return False

    def _test_webhook_enumeration(self, endpoint: Dict, config: Config) -> bool:
        """Test for webhook enumeration vulnerability."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            # Try to enumerate webhooks
            test_ids = ["1", "2", "3", "admin", "test"]

            for webhook_id in test_ids:
                try:
                    enum_url = f"{url}/{webhook_id}"

                    resp = self.http_client.get(
                        enum_url,
                        timeout=config.timeout
                    )

                    # If we get different responses for different IDs
                    if resp.status_code in [200, 201]:
                        return True

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Enumeration test error: {str(e)}")

        return False
