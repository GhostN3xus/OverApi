"""WebSocket API scanner module."""

import json
import time
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin

from ...core.logger import Logger
from ...core.config import Config
from ...utils.http_client import HTTPClient
from ...utils.validators import Validators


class WebSocketScanner:
    """Scanner for WebSocket APIs."""

    def __init__(self, logger: Logger = None):
        """Initialize WebSocket scanner."""
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(logger=self.logger)

    def discover(self, url: str, config: Config) -> List[Dict[str, Any]]:
        """
        Discover WebSocket endpoints.

        Args:
            url: Target URL
            config: Configuration object

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Convert HTTP URL to WS URL
            ws_url = self._convert_to_ws(url)
            parsed = urlparse(ws_url)

            # Try to detect WebSocket endpoints
            endpoints.extend(self._scan_common_ws_endpoints(url, config))

            # Try to get OpenAPI/Swagger spec for WebSocket endpoints
            endpoints.extend(self._scan_from_api_spec(url, config))

        except Exception as e:
            self.logger.debug(f"Error discovering WebSocket endpoints: {str(e)}")

        return endpoints

    def _convert_to_ws(self, url: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        if url.startswith("ws://") or url.startswith("wss://"):
            return url

        if url.startswith("https://"):
            return url.replace("https://", "wss://", 1)

        if url.startswith("http://"):
            return url.replace("http://", "ws://", 1)

        return f"ws://{url}"

    def _scan_common_ws_endpoints(self, url: str, config: Config) -> List[Dict]:
        """Scan for common WebSocket endpoints."""
        endpoints = []
        common_endpoints = [
            "/ws",
            "/websocket",
            "/socket",
            "/socket.io",
            "/api/ws",
            "/api/websocket",
            "/v1/ws",
            "/chat",
            "/notifications",
            "/events",
            "/streaming",
            "/realtime",
            "/live",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in common_endpoints:
            try:
                test_url = base_url + endpoint

                # Try GET request first to see if endpoint exists
                resp = self.http_client.get(test_url, timeout=config.timeout)

                if resp.status_code in [200, 400, 403, 404, 500]:
                    # Check for upgrade headers
                    has_upgrade_header = "upgrade" in str(resp.headers).lower()

                    endpoints.append({
                        "path": endpoint,
                        "method": "GET",
                        "type": "WebSocket",
                        "status": resp.status_code,
                        "upgradable": has_upgrade_header or resp.status_code != 404,
                        "headers": dict(resp.headers)
                    })

            except Exception as e:
                self.logger.debug(f"WebSocket endpoint scan error: {str(e)}")

        return endpoints

    def _scan_from_api_spec(self, url: str, config: Config) -> List[Dict]:
        """Scan API specification for WebSocket endpoints."""
        endpoints = []

        try:
            spec_urls = [
                "/swagger.json",
                "/api/swagger.json",
                "/openapi.json",
                "/api/openapi.json",
                "/docs/swagger.json",
                "/.well-known/openapi.json",
            ]

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for spec_url in spec_urls:
                try:
                    resp = self.http_client.get(base_url + spec_url, timeout=config.timeout)

                    if resp.status_code == 200:
                        spec = resp.json()

                        # Look for WebSocket paths
                        if "paths" in spec:
                            for path, path_def in spec["paths"].items():
                                for method in ["get", "post", "ws"]:
                                    if method in path_def:
                                        operation = path_def[method]

                                        # Check for WebSocket upgrade
                                        if operation.get("x-protocol") == "websocket" or \
                                           "websocket" in operation.get("description", "").lower():
                                            endpoints.append({
                                                "path": path,
                                                "method": "GET",
                                                "type": "WebSocket",
                                                "protocol": "websocket",
                                                "description": operation.get("description")
                                            })

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"API spec scan error: {str(e)}")

        return endpoints

    def test_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Test WebSocket endpoint for vulnerabilities.

        Args:
            endpoint: Endpoint configuration
            config: Configuration object

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        try:
            # Test for unauthenticated access
            if self._test_unauthenticated_access(endpoint, config):
                vulnerabilities.append({
                    "type": "Unauthenticated WebSocket",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "WebSocket connection allowed without authentication",
                    "owasp_category": "API2"
                })

            # Test for injection vulnerabilities
            injection_vulns = self._test_injection(endpoint, config)
            vulnerabilities.extend(injection_vulns)

            # Test for CORS bypass
            if self._test_cors_bypass(endpoint, config):
                vulnerabilities.append({
                    "type": "CORS Bypass",
                    "severity": "Medium",
                    "endpoint": endpoint.get("path"),
                    "evidence": "WebSocket may be accessible from any origin",
                    "owasp_category": "API7"
                })

            # Test for message reflection (XSS)
            if self._test_message_reflection(endpoint, config):
                vulnerabilities.append({
                    "type": "Message Reflection/XSS",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Messages reflected without sanitization",
                    "owasp_category": "API8"
                })

        except Exception as e:
            self.logger.debug(f"Error testing WebSocket endpoint: {str(e)}")

        return vulnerabilities

    def _test_unauthenticated_access(self, endpoint: Dict, config: Config) -> bool:
        """Test if WebSocket is accessible without authentication."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            # Try simple GET request
            resp = self.http_client.get(url, timeout=config.timeout)

            # If we get response without auth headers, likely accessible
            if resp.status_code not in [401, 403]:
                return True

        except Exception as e:
            self.logger.debug(f"Unauthenticated access test error: {str(e)}")

        return False

    def _test_injection(self, endpoint: Dict, config: Config) -> List[Dict]:
        """Test WebSocket for injection vulnerabilities."""
        vulnerabilities = []

        injection_payloads = {
            "xss": "<img src=x onerror='alert(1)'>",
            "sql": "' OR '1'='1",
            "cmd": "$(whoami)",
            "json": "{\"x\": {\"$where\": \"return true\"}}",
        }

        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            for injection_type, payload in injection_payloads.items():
                try:
                    # Send JSON message
                    message = json.dumps({"msg": payload})

                    resp = self.http_client.post(
                        url,
                        data=message,
                        timeout=config.timeout,
                        headers={"Content-Type": "application/json"}
                    )

                    if resp.status_code == 200:
                        if Validators.is_xss(resp.text, payload) and injection_type == "xss":
                            vulnerabilities.append({
                                "type": f"WebSocket {injection_type.upper()} Injection",
                                "severity": "High",
                                "endpoint": endpoint.get("path"),
                                "payload": payload,
                                "evidence": resp.text[:200],
                                "owasp_category": "API8"
                            })
                        elif Validators.is_sql_injection(resp.text, payload) and injection_type == "sql":
                            vulnerabilities.append({
                                "type": f"WebSocket {injection_type.upper()} Injection",
                                "severity": "Critical",
                                "endpoint": endpoint.get("path"),
                                "payload": payload,
                                "evidence": resp.text[:200],
                                "owasp_category": "API8"
                            })

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Injection test error: {str(e)}")

        return vulnerabilities

    def _test_cors_bypass(self, endpoint: Dict, config: Config) -> bool:
        """Test for CORS bypass in WebSocket."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            # Send request with different origin
            headers = {"Origin": "https://attacker.com"}

            resp = self.http_client.get(url, headers=headers, timeout=config.timeout)

            cors_origin = resp.headers.get("Access-Control-Allow-Origin")

            # Check for wildcard or reflection
            if cors_origin == "*" or cors_origin == headers["Origin"]:
                return True

        except Exception as e:
            self.logger.debug(f"CORS test error: {str(e)}")

        return False

    def _test_message_reflection(self, endpoint: Dict, config: Config) -> bool:
        """Test if WebSocket reflects messages without sanitization."""
        try:
            test_payload = f"test_{int(time.time())}"
            url = config.url.rstrip("/") + endpoint.get("path", "")

            message = json.dumps({"msg": test_payload})

            resp = self.http_client.post(
                url,
                data=message,
                timeout=config.timeout,
                headers={"Content-Type": "application/json"}
            )

            # Check if payload is reflected
            if test_payload in resp.text:
                return True

        except Exception as e:
            self.logger.debug(f"Message reflection test error: {str(e)}")

        return False
