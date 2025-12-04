"""Automatic API type detection module with SSL/TLS configuration."""

import re
import asyncio
from typing import Dict, List, Tuple, Optional
import requests
from urllib.parse import urljoin, urlparse

from .logger import Logger
from .exceptions import APIDetectionError


class APIDetector:
    """Detects API type based on heuristics and direct testing."""

    GRAPHQL_ENDPOINTS = ["/graphql", "/.graphql", "/api/graphql", "/graphql/query", "/v1/graphql"]
    REST_INDICATORS = ["/api/v1", "/api/v2", "/api/", "/rest/", "/v1/", "/v2/", "/api/v3"]
    SOAP_ENDPOINTS = ["/soap", "/ws", "/webservice", "/service", "/SoapService"]
    GRPC_INDICATORS = [".proto", "/grpc", "/rpc"]
    SWAGGER_ENDPOINTS = ["/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
                         "/openapi", "/openapi.json", "/openapi.yaml", "/v2/api-docs", "/v3/api-docs"]

    def __init__(self, logger: Logger = None, verify_ssl: bool = True,
                 custom_ca_path: Optional[str] = None):
        """
        Initialize detector with SSL configuration.

        Args:
            logger: Logger instance
            verify_ssl: Verify SSL certificates (default: True)
            custom_ca_path: Path to custom CA certificate bundle
        """
        self.logger = logger or Logger(__name__)
        self.verify_ssl = verify_ssl
        self.custom_ca_path = custom_ca_path

        self.session = requests.Session()
        self._configure_ssl()

        self.detected_types = []

    def _configure_ssl(self) -> None:
        """Configure SSL/TLS settings for the session."""
        if self.verify_ssl:
            try:
                import certifi
                self.session.verify = self.custom_ca_path or certifi.where()
            except Exception as e:
                self.logger.warning(f"Failed to configure CA bundle: {str(e)}")
                self.session.verify = True
        else:
            self.session.verify = False
            self.logger.warning("SSL verification disabled in API detector - this is insecure!")
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    async def detect(self, url: str, timeout: int = 10) -> Tuple[List[str], Dict]:
        """
        Detect API type for given URL asynchronously (wrapper for sync method).

        Args:
            url: Target URL
            timeout: Request timeout

        Returns:
            Tuple of (detected_types, detection_details)
        """
        return await asyncio.to_thread(self._detect_sync, url, timeout)

    def _detect_sync(self, url: str, timeout: int = 10) -> Tuple[List[str], Dict]:
        """
        Detect API type for given URL (synchronous implementation).

        Args:
            url: Target URL
            timeout: Request timeout

        Returns:
            Tuple of (detected_types, detection_details)
        """
        try:
            self.logger.info(f"Detecting API type for: {url}")
            details = {
                "graphql": False,
                "rest": False,
                "soap": False,
                "grpc": False,
                "websocket": False,
                "openapi": False,
                "evidence": {}
            }
            self.detected_types = []

            # Basic connectivity check
            try:
                base_resp = self.session.get(url, timeout=timeout)
                details["base_status"] = base_resp.status_code
                details["server_header"] = base_resp.headers.get("Server", "Unknown")
            except requests.RequestException as e:
                self.logger.error(f"Could not connect to target: {e}")
                return [], {"error": str(e)}

            # Test WebSocket (Schema check first)
            if self._test_websocket(url):
                details["websocket"] = True
                self.detected_types.append("websocket")

            # Test GraphQL
            if self._test_graphql(url, timeout):
                details["graphql"] = True
                self.detected_types.append("graphql")

            # Test SOAP
            if self._test_soap(url, timeout):
                details["soap"] = True
                self.detected_types.append("soap")

            # Test OpenAPI/Swagger
            if self._test_openapi(url, timeout):
                details["openapi"] = True
                self.detected_types.append("openapi")

            # Test gRPC
            if self._test_grpc(url, timeout):
                details["grpc"] = True
                self.detected_types.append("grpc")

            # Test REST (Last resort usually, or if specific indicators found)
            if self._test_rest(url, timeout, base_resp):
                details["rest"] = True
                if "rest" not in self.detected_types:
                    self.detected_types.append("rest")

            if not self.detected_types:
                self.logger.warning("No API type detected, assuming REST (blind scan)")
                self.detected_types.append("rest")

            self.logger.success(f"Detected API types: {', '.join(self.detected_types)}")
            return self.detected_types, details

        except Exception as e:
            self.logger.error(f"Detection error: {str(e)}")
            self.logger.warning("Falling back to REST (blind scan)")
            return ["rest"], {"error": str(e)}

    def _test_graphql(self, url: str, timeout: int) -> bool:
        """Test for GraphQL API."""
        try:
            # Check for introspection
            introspection_query = """
            query {
                __schema {
                    types {
                        name
                    }
                }
            }
            """

            # 1. Test standard endpoints
            for endpoint in self.GRAPHQL_ENDPOINTS:
                test_url = urljoin(url, endpoint)
                try:
                    # Method 1: GET with query param
                    resp = self.session.get(test_url, params={"query": "{__typename}"}, timeout=timeout)
                    if resp.status_code == 200 and "data" in resp.json():
                        self.logger.debug(f"GraphQL GET detected at: {test_url}")
                        return True

                    # Method 2: POST with JSON
                    payload = {"query": "{__typename}"}
                    resp = self.session.post(test_url, json=payload, timeout=timeout)
                    if resp.status_code == 200 and ("data" in resp.text or "errors" in resp.text):
                        # Verify it's JSON
                        try:
                            resp.json()
                            self.logger.debug(f"GraphQL POST detected at: {test_url}")
                            return True
                        except ValueError:
                            pass
                except:
                    continue

            # 2. Test root URL if it looks like an API endpoint
            payload = {"query": "{__typename}"}
            resp = self.session.post(url, json=payload, timeout=timeout)
            if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                 if "data" in resp.text or "errors" in resp.text:
                     self.logger.debug("GraphQL detected at root URL")
                     return True

        except Exception as e:
            self.logger.debug(f"GraphQL test failed: {str(e)}")

        return False

    def _test_rest(self, url: str, timeout: int, base_resp=None) -> bool:
        """Test for REST API."""
        try:
            # 1. Check for REST indicators in URL
            if any(indicator in url.lower() for indicator in self.REST_INDICATORS):
                self.logger.debug("REST indicators found in URL")
                return True

            # 2. Check for JSON responses
            if base_resp and "application/json" in base_resp.headers.get("Content-Type", ""):
                self.logger.debug("JSON response detected")
                return True

            # 3. Check for common HTTP methods support (OPTIONS)
            try:
                resp = self.session.options(url, timeout=timeout)
                allow_header = resp.headers.get("Allow", "")
                if "GET" in allow_header and "POST" in allow_header:
                    self.logger.debug("REST methods detected via OPTIONS")
                    return True
            except:
                pass

            # 4. Heuristic: URL path structure
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) > 1 and path_parts[-1].isdigit():
                 # likely /users/123
                 self.logger.debug("REST resource pattern detected")
                 return True

        except Exception as e:
            self.logger.debug(f"REST test failed: {str(e)}")

        return False

    def _test_soap(self, url: str, timeout: int) -> bool:
        """Test for SOAP API."""
        try:
            # Test for WSDL
            wsdl_url = urljoin(url, "?wsdl")
            resp = self.session.get(wsdl_url, timeout=timeout)

            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                if "wsdl:definitions" in resp.text or "definitions" in resp.text:
                    self.logger.debug("WSDL detected")
                    return True

            # Test for SOAP endpoints
            for endpoint in self.SOAP_ENDPOINTS:
                test_url = urljoin(url, endpoint)
                try:
                    resp = self.session.get(test_url, timeout=timeout)
                    # SOAP 1.1/1.2 content types
                    ct = resp.headers.get("Content-Type", "").lower()
                    if "text/xml" in ct or "application/soap+xml" in ct:
                         self.logger.debug(f"SOAP Content-Type detected at: {test_url}")
                         return True
                except:
                    continue

            # Test with SOAP envelope
            soap_payload = '''<?xml version="1.0"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body/>
            </soap:Envelope>'''

            resp = self.session.post(url, data=soap_payload, timeout=timeout,
                                   headers={"Content-Type": "text/xml", "SOAPAction": ""})

            if resp.status_code == 200 or resp.status_code == 500: # SOAP faults are 500
                if "soap:Envelope" in resp.text or "soap:Fault" in resp.text:
                    self.logger.debug("SOAP detected via envelope test")
                    return True

        except Exception as e:
            self.logger.debug(f"SOAP test failed: {str(e)}")

        return False

    def _test_openapi(self, url: str, timeout: int) -> bool:
        """Test for OpenAPI/Swagger documentation."""
        try:
            for endpoint in self.SWAGGER_ENDPOINTS:
                test_url = urljoin(url, endpoint)
                try:
                    resp = self.session.get(test_url, timeout=timeout)
                    if resp.status_code == 200:
                        if "swagger" in resp.text.lower() or "openapi" in resp.text.lower():
                            self.logger.debug(f"OpenAPI detected at: {test_url}")
                            return True
                        # Check JSON structure for openapi key
                        try:
                            data = resp.json()
                            if "openapi" in data or "swagger" in data:
                                return True
                        except:
                            pass
                except:
                    continue

        except Exception as e:
            self.logger.debug(f"OpenAPI test failed: {str(e)}")

        return False

    def _test_grpc(self, url: str, timeout: int) -> bool:
        """Test for gRPC API."""
        try:
            # gRPC detection is limited without proper client, check for indicators
            if ".proto" in url or "/grpc" in url:
                self.logger.debug("gRPC indicators found in URL")
                return True

            # Try to detect via HTTP/2 or specific headers
            # Note: Requests library doesn't support HTTP/2 natively easily without extras
            for endpoint in self.GRPC_INDICATORS:
                test_url = urljoin(url, endpoint)
                try:
                    resp = self.session.post(test_url, timeout=timeout, headers={"Content-Type": "application/grpc"})
                    if resp.status_code == 200 and "application/grpc" in resp.headers.get("Content-Type", ""):
                        return True
                    # gRPC often returns trailers, which requests might handle differently
                except:
                    pass

        except Exception as e:
            self.logger.debug(f"gRPC test failed: {str(e)}")

        return False

    def _test_websocket(self, url: str) -> bool:
        """Test for WebSocket API."""
        try:
            # Check if URL uses ws:// or wss://
            if url.startswith("ws://") or url.startswith("wss://"):
                self.logger.debug("WebSocket URL detected")
                return True

        except Exception as e:
            self.logger.debug(f"WebSocket test failed: {str(e)}")

        return False
