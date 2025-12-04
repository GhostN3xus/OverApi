"""WebSocket API scanner module with real WebSocket connection support."""

import json
import time
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin

from ...core.logger import Logger
from ...core.config import Config
from ...core.context import ScanContext, Endpoint
from ...utils.http_client import HTTPClient
from ...utils.validators import Validators

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


class WebSocketScanner:
    """Scanner for WebSocket APIs with real connection support."""

    def __init__(self, context: ScanContext = None, config: Config = None, logger: Logger = None):
        """
        Initialize WebSocket scanner.

        Args:
            context: Scan context (optional for backward compatibility)
            config: Configuration object
            logger: Logger instance
        """
        self.context = context
        self.config = config
        self.logger = logger or Logger(__name__)
        verify_ssl = config.verify_ssl if config else True
        custom_ca_path = config.custom_ca_path if config else None
        self.http_client = HTTPClient(
            logger=self.logger,
            verify_ssl=verify_ssl,
            custom_ca_path=custom_ca_path
        )

    async def discover_endpoints(self) -> List[Endpoint]:
        """
        Discover WebSocket endpoints asynchronously (wrapper for sync method).

        Returns:
            List of discovered endpoints
        """
        return await asyncio.to_thread(self._discover_endpoints_sync)

    def _discover_endpoints_sync(self) -> List[Endpoint]:
        """
        Discover WebSocket endpoints (synchronous implementation).

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            url = self.config.url if self.config else None
            if not url:
                self.logger.warning("No URL provided for WebSocket scanning")
                return endpoints

            # Try to detect WebSocket endpoints
            common = self._scan_common_ws_endpoints(url, self.config)
            for ep in common:
                endpoint = Endpoint(
                    path=ep.get("path", ""),
                    method="WEBSOCKET",
                    metadata={
                        "type": "websocket",
                        "ws_url": ep.get("ws_url", ""),
                        "status": ep.get("status", 0),
                        "accessible": ep.get("accessible", False)
                    }
                )
                endpoints.append(endpoint)

                if self.context:
                    self.context.add_endpoint(endpoint)

            # Try to get OpenAPI/Swagger spec for WebSocket endpoints
            spec_endpoints = self._scan_from_api_spec(url, self.config)
            for ep in spec_endpoints:
                endpoint = Endpoint(
                    path=ep.get("path", ""),
                    method="WEBSOCKET",
                    metadata={
                        "type": "websocket",
                        "ws_url": ep.get("ws_url", ""),
                        "source": "api_spec"
                    }
                )
                endpoints.append(endpoint)

                if self.context:
                    self.context.add_endpoint(endpoint)

            self.logger.debug(f"Discovered {len(endpoints)} WebSocket endpoints")

        except Exception as e:
            self.logger.error(f"WebSocket endpoint discovery failed: {str(e)}")

        return endpoints

    def discover(self, url: str, config: Config) -> List[Dict[str, Any]]:
        """
        Discover WebSocket endpoints (legacy method).

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

    # ============ Real WebSocket Connection Methods ============

    async def connect_websocket_async(self, ws_url: str, timeout: int = 10) -> Optional[Dict]:
        """
        Establish a real WebSocket connection asynchronously.

        Args:
            ws_url: WebSocket URL (ws:// or wss://)
            timeout: Connection timeout in seconds

        Returns:
            Connection info dict or None if failed
        """
        if not WEBSOCKETS_AVAILABLE:
            self.logger.warning("websockets library not available, skipping real WS connection")
            return None

        try:
            async with websockets.connect(ws_url, open_timeout=timeout) as ws:
                return {
                    "connected": True,
                    "url": ws_url,
                    "protocol": ws.subprotocol or "unknown",
                    "server": ws.response_headers.get("server", "unknown") if hasattr(ws, 'response_headers') else "unknown",
                    "headers": dict(ws.response_headers) if hasattr(ws, 'response_headers') else {}
                }
        except asyncio.TimeoutError:
            self.logger.debug(f"WebSocket connection timeout: {ws_url}")
            return {"connected": False, "url": ws_url, "error": "timeout"}
        except Exception as e:
            self.logger.debug(f"WebSocket connection failed: {str(e)}")
            return {"connected": False, "url": ws_url, "error": str(e)}

    async def send_and_receive_async(self, ws_url: str, message: str, timeout: int = 10) -> Optional[Dict]:
        """
        Send a message and receive response via WebSocket.

        Args:
            ws_url: WebSocket URL
            message: Message to send
            timeout: Operation timeout

        Returns:
            Response info dict or None
        """
        if not WEBSOCKETS_AVAILABLE:
            return None

        try:
            async with websockets.connect(ws_url, open_timeout=timeout) as ws:
                await ws.send(message)
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    return {
                        "sent": message,
                        "received": response,
                        "url": ws_url,
                        "success": True
                    }
                except asyncio.TimeoutError:
                    return {"sent": message, "received": None, "url": ws_url, "success": False, "error": "recv timeout"}
        except Exception as e:
            return {"sent": message, "received": None, "url": ws_url, "success": False, "error": str(e)}

    async def test_websocket_injection_async(self, ws_url: str, payloads: List[str], timeout: int = 10) -> List[Dict]:
        """
        Test WebSocket for injection vulnerabilities with real connections.

        Args:
            ws_url: WebSocket URL
            payloads: List of injection payloads
            timeout: Operation timeout

        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []

        if not WEBSOCKETS_AVAILABLE:
            self.logger.warning("websockets library not available")
            return vulnerabilities

        for payload in payloads:
            try:
                result = await self.send_and_receive_async(ws_url, payload, timeout)
                if result and result.get("success"):
                    response = result.get("received", "")

                    # Check for SQL injection indicators
                    if Validators.is_sql_injection(str(response), payload):
                        vulnerabilities.append({
                            "type": "WebSocket SQL Injection",
                            "severity": "Critical",
                            "url": ws_url,
                            "payload": payload,
                            "response": str(response)[:500],
                            "owasp_category": "API8:2023 - Security Misconfiguration",
                            "cwe": "CWE-89"
                        })

                    # Check for XSS reflection
                    if payload in str(response) and any(c in payload for c in ['<', '>', '"', "'"]):
                        vulnerabilities.append({
                            "type": "WebSocket XSS Reflection",
                            "severity": "High",
                            "url": ws_url,
                            "payload": payload,
                            "response": str(response)[:500],
                            "owasp_category": "API8:2023 - Security Misconfiguration",
                            "cwe": "CWE-79"
                        })

                    # Check for command injection indicators
                    if Validators.is_command_injection(str(response), payload):
                        vulnerabilities.append({
                            "type": "WebSocket Command Injection",
                            "severity": "Critical",
                            "url": ws_url,
                            "payload": payload,
                            "response": str(response)[:500],
                            "owasp_category": "API8:2023 - Security Misconfiguration",
                            "cwe": "CWE-78"
                        })

            except Exception as e:
                self.logger.debug(f"WebSocket injection test error: {str(e)}")

        return vulnerabilities

    async def test_websocket_dos_async(self, ws_url: str, timeout: int = 10) -> List[Dict]:
        """
        Test WebSocket for denial of service vulnerabilities.

        Args:
            ws_url: WebSocket URL
            timeout: Operation timeout

        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []

        if not WEBSOCKETS_AVAILABLE:
            return vulnerabilities

        try:
            # Test 1: Large message
            large_message = "A" * 10000000  # 10MB
            try:
                result = await self.send_and_receive_async(ws_url, large_message, timeout)
                if result and result.get("success"):
                    vulnerabilities.append({
                        "type": "WebSocket Large Message Accepted",
                        "severity": "Medium",
                        "url": ws_url,
                        "evidence": "Server accepted very large WebSocket message (10MB)",
                        "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
                        "cwe": "CWE-770"
                    })
            except:
                pass

            # Test 2: Rapid messages (rate limiting)
            async with websockets.connect(ws_url, open_timeout=timeout) as ws:
                start_time = time.time()
                messages_sent = 0

                for _ in range(100):
                    try:
                        await asyncio.wait_for(ws.send("test"), timeout=1)
                        messages_sent += 1
                    except:
                        break

                elapsed = time.time() - start_time

                if messages_sent == 100 and elapsed < 1:
                    vulnerabilities.append({
                        "type": "WebSocket No Rate Limiting",
                        "severity": "Medium",
                        "url": ws_url,
                        "evidence": f"Server accepted {messages_sent} messages in {elapsed:.2f}s without rate limiting",
                        "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
                        "cwe": "CWE-770"
                    })

        except Exception as e:
            self.logger.debug(f"WebSocket DoS test error: {str(e)}")

        return vulnerabilities

    def run_async_tests(self, ws_url: str) -> List[Dict]:
        """
        Run all async WebSocket tests synchronously (wrapper).

        Args:
            ws_url: WebSocket URL to test

        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []

        if not WEBSOCKETS_AVAILABLE:
            self.logger.warning("websockets library not installed. Install with: pip install websockets")
            return vulnerabilities

        try:
            # Get or create event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Injection payloads
            injection_payloads = [
                '{"msg": "\' OR 1=1--"}',
                '{"msg": "<script>alert(1)</script>"}',
                '{"msg": "$(whoami)"}',
                '{"msg": "{{7*7}}"}',
                '{"data": {"$gt": ""}}',
            ]

            # Run injection tests
            injection_vulns = loop.run_until_complete(
                self.test_websocket_injection_async(ws_url, injection_payloads)
            )
            vulnerabilities.extend(injection_vulns)

            # Run DoS tests
            dos_vulns = loop.run_until_complete(
                self.test_websocket_dos_async(ws_url)
            )
            vulnerabilities.extend(dos_vulns)

        except Exception as e:
            self.logger.error(f"Async WebSocket test error: {str(e)}")

        return vulnerabilities
