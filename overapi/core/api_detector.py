"""Automatic API type detection module."""

import re
from typing import Dict, List, Tuple, Optional
import requests
from urllib.parse import urljoin

from .logger import Logger
from .exceptions import APIDetectionError


class APIDetector:
    """Detects API type based on heuristics and direct testing."""

    GRAPHQL_ENDPOINTS = ["/graphql", "/.graphql", "/api/graphql", "/graphql/query"]
    REST_INDICATORS = ["/api/v1", "/api/v2", "/api/", "/rest/", "/v1/", "/v2/"]
    SOAP_ENDPOINTS = ["/soap", "/ws", "/webservice", "/service"]
    GRPC_INDICATORS = [".proto", "/grpc", "/rpc"]
    SWAGGER_ENDPOINTS = ["/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
                         "/openapi", "/openapi.json", "/openapi.yaml"]

    def __init__(self, logger: Logger = None):
        """Initialize detector."""
        self.logger = logger or Logger(__name__)
        self.session = requests.Session()
        self.session.verify = False
        self.detected_types = []

    def detect(self, url: str, timeout: int = 10) -> Tuple[List[str], Dict]:
        """
        Detect API type for given URL.

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

            # Test GraphQL
            if self._test_graphql(url, timeout):
                details["graphql"] = True
                self.detected_types.append("graphql")

            # Test REST
            if self._test_rest(url, timeout):
                details["rest"] = True
                self.detected_types.append("rest")

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

            # Test WebSocket
            if self._test_websocket(url):
                details["websocket"] = True
                self.detected_types.append("websocket")

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
            # Test standard GraphQL endpoints
            for endpoint in self.GRAPHQL_ENDPOINTS:
                test_url = urljoin(url, endpoint)
                payload = {"query": "{__typename}"}
                resp = self.session.post(test_url, json=payload, timeout=timeout)

                if resp.status_code in [200, 400] and ("data" in resp.text or "errors" in resp.text):
                    self.logger.debug(f"GraphQL detected at: {test_url}")
                    return True

            # Test root URL for GraphQL
            payload = {"query": "{__typename}"}
            resp = self.session.post(url, json=payload, timeout=timeout)
            if resp.status_code in [200, 400] and ("data" in resp.text or "errors" in resp.text):
                self.logger.debug("GraphQL detected at root URL")
                return True

        except Exception as e:
            self.logger.debug(f"GraphQL test failed: {str(e)}")

        return False

    def _test_rest(self, url: str, timeout: int) -> bool:
        """Test for REST API."""
        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=True)

            # Check for REST indicators in URL
            if any(indicator in url.lower() for indicator in self.REST_INDICATORS):
                self.logger.debug("REST indicators found in URL")
                return True

            # Check for JSON responses
            if "application/json" in resp.headers.get("Content-Type", ""):
                self.logger.debug("JSON response detected")
                return True

            # Check for common REST status codes and response patterns
            if resp.status_code in [200, 400, 404] and len(resp.text) > 0:
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

            if resp.status_code == 200 and "wsdl" in resp.text.lower():
                self.logger.debug("WSDL detected")
                return True

            # Test for SOAP endpoints
            for endpoint in self.SOAP_ENDPOINTS:
                test_url = urljoin(url, endpoint)
                resp = self.session.get(test_url, timeout=timeout)
                if resp.status_code == 200 and ("soap" in resp.text.lower() or "wsdl" in resp.text.lower()):
                    self.logger.debug(f"SOAP detected at: {test_url}")
                    return True

            # Test with SOAP envelope
            soap_payload = '''<?xml version="1.0"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body/>
            </soap:Envelope>'''

            resp = self.session.post(url, data=soap_payload, timeout=timeout,
                                   headers={"Content-Type": "text/xml"})
            if "soap" in resp.text.lower():
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
                resp = self.session.get(test_url, timeout=timeout)

                if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                    self.logger.debug(f"OpenAPI detected at: {test_url}")
                    return True

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
            for endpoint in self.GRPC_INDICATORS:
                test_url = urljoin(url, endpoint)
                try:
                    resp = self.session.get(test_url, timeout=timeout)
                    if resp.status_code == 200:
                        return True
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
