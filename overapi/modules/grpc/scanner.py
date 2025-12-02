"""gRPC API scanner module."""

import json
from typing import Dict, List, Any
from urllib.parse import urlparse

from ...core.logger import Logger
from ...core.config import Config
from ...utils.http_client import HTTPClient


class GrpcScanner:
    """Scanner for gRPC APIs with reflection support."""

    def __init__(self, config: Config = None, logger: Logger = None):
        """
        Initialize gRPC scanner.

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or Logger(__name__)
        verify_ssl = config.verify_ssl if config else True
        custom_ca_path = config.custom_ca_path if config else None
        self.http_client = HTTPClient(
            logger=self.logger,
            verify_ssl=verify_ssl,
            custom_ca_path=custom_ca_path
        )

    def discover(self, url: str, config: Config) -> List[Dict[str, Any]]:
        """
        Discover gRPC services and methods using reflection.

        Args:
            url: Target URL
            config: Configuration object

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Try gRPC reflection via HTTP/2
            services = self._get_reflection_services(url, config)

            if services:
                for service in services:
                    endpoints.extend(self._extract_methods(service, url))
            else:
                # Fallback: common gRPC endpoints
                endpoints.extend(self._scan_common_endpoints(url, config))

        except Exception as e:
            self.logger.debug(f"Error discovering gRPC services: {str(e)}")

        return endpoints

    def _get_reflection_services(self, url: str, config: Config) -> List[Dict]:
        """
        Get gRPC services via reflection API.

        Args:
            url: Target URL
            config: Configuration object

        Returns:
            List of service information
        """
        services = []

        try:
            # Try standard reflection endpoint
            reflection_url = self._build_reflection_url(url)

            resp = self.http_client.post(
                reflection_url,
                json={"service": ""},
                timeout=config.timeout,
                headers={"content-type": "application/grpc+proto"}
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "fileDescriptorProto" in data:
                        services = self._parse_proto_response(data)
                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Reflection API error: {str(e)}")

        return services

    def _build_reflection_url(self, url: str) -> str:
        """Build gRPC reflection endpoint URL."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        reflection_endpoints = [
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/.well-known/grpc-gateway.swagger.json",
            "/api/v1/describe",
        ]

        return base_url + reflection_endpoints[0]

    def _parse_proto_response(self, data: Dict) -> List[Dict]:
        """Parse protobuf response from reflection API."""
        services = []

        try:
            if "fileDescriptorProto" in data:
                for file_desc in data["fileDescriptorProto"]:
                    if "service" in file_desc:
                        for service in file_desc["service"]:
                            services.append({
                                "name": service.get("name"),
                                "methods": service.get("method", []),
                                "package": file_desc.get("package")
                            })
        except Exception as e:
            self.logger.debug(f"Proto parsing error: {str(e)}")

        return services

    def _extract_methods(self, service: Dict, base_url: str) -> List[Dict]:
        """
        Extract gRPC methods from service descriptor.

        Args:
            service: Service descriptor
            base_url: Base URL

        Returns:
            List of endpoint dictionaries
        """
        endpoints = []
        service_name = service.get("name", "Unknown")
        package = service.get("package", "")
        full_service_name = f"{package}.{service_name}" if package else service_name

        methods = service.get("methods", [])
        for method in methods:
            method_name = method.get("name", "")

            endpoint = {
                "path": f"/{full_service_name}/{method_name}",
                "method": "POST",
                "type": "gRPC",
                "input_type": method.get("input_type"),
                "output_type": method.get("output_type"),
                "client_streaming": method.get("client_streaming", False),
                "server_streaming": method.get("server_streaming", False),
                "full_name": f"{full_service_name}/{method_name}"
            }

            endpoints.append(endpoint)

        return endpoints

    def _scan_common_endpoints(self, url: str, config: Config) -> List[Dict]:
        """
        Scan for common gRPC endpoints without reflection.

        Args:
            url: Target URL
            config: Configuration object

        Returns:
            List of discovered endpoints
        """
        endpoints = []
        common_endpoints = [
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "/google.protobuf.FileDescriptorSet",
            "/health",
            "/health/status",
            "/.well-known/grpc-gateway.swagger.json",
            "/api/v1/describe",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in common_endpoints:
            try:
                test_url = base_url + endpoint

                # Try to access the endpoint
                resp = self.http_client.post(
                    test_url,
                    timeout=config.timeout,
                    headers={"content-type": "application/grpc"}
                )

                if resp.status_code != 404:
                    endpoints.append({
                        "path": endpoint,
                        "method": "POST",
                        "type": "gRPC",
                        "status": resp.status_code,
                        "accessible": resp.status_code in [200, 400, 500]
                    })

            except Exception as e:
                self.logger.debug(f"Endpoint scan error for {endpoint}: {str(e)}")

        return endpoints

    def test_endpoint(self, endpoint: Dict, config: Config) -> List[Dict]:
        """
        Test gRPC endpoint for vulnerabilities.

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
                    "type": "Unauthenticated gRPC Access",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "gRPC method accessible without authentication",
                    "owasp_category": "API2"
                })

            # Test for insecure deserialization
            if self._test_insecure_deserialization(endpoint, config):
                vulnerabilities.append({
                    "type": "Insecure Deserialization",
                    "severity": "High",
                    "endpoint": endpoint.get("path"),
                    "evidence": "Potential code execution via deserialization",
                    "owasp_category": "API8"
                })

            # Test for reflection information disclosure
            if endpoint.get("path", "").endswith("ServerReflectionInfo"):
                vulnerabilities.append({
                    "type": "Information Disclosure",
                    "severity": "Medium",
                    "endpoint": endpoint.get("path"),
                    "evidence": "gRPC reflection enabled - service schema exposed",
                    "owasp_category": "API9"
                })

        except Exception as e:
            self.logger.debug(f"Error testing gRPC endpoint: {str(e)}")

        return vulnerabilities

    def _test_unauthenticated_access(self, endpoint: Dict, config: Config) -> bool:
        """Test if gRPC endpoint is accessible without authentication."""
        try:
            url = config.url.rstrip("/") + endpoint.get("path", "")

            resp = self.http_client.post(
                url,
                timeout=config.timeout,
                headers={"content-type": "application/grpc"}
            )

            # Success codes (200, 400 bad request, 500 server error)
            # indicate the endpoint exists and doesn't require auth
            return resp.status_code in [200, 400, 500]

        except Exception as e:
            self.logger.debug(f"Auth test error: {str(e)}")
            return False

    def _test_insecure_deserialization(self, endpoint: Dict, config: Config) -> bool:
        """Test for insecure deserialization vulnerabilities."""
        try:
            # Create malicious protobuf payload
            malicious_payloads = [
                b'\x08\x96\x01',  # Potential gadget chains
                b'\x0a\x00',      # Empty message
                b'\x12\x00',      # Empty embedded message
            ]

            url = config.url.rstrip("/") + endpoint.get("path", "")

            for payload in malicious_payloads:
                try:
                    resp = self.http_client.post(
                        url,
                        data=payload,
                        timeout=config.timeout,
                        headers={"content-type": "application/grpc"}
                    )

                    # Check for error messages indicating deserialization
                    if "deserialize" in resp.text.lower() or \
                       "codec" in resp.text.lower():
                        return True

                except:
                    pass

        except Exception as e:
            self.logger.debug(f"Deserialization test error: {str(e)}")

        return False
