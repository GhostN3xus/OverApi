"""Async HTTP client for API communication with advanced SSL/TLS handling."""

import httpx
import ssl
from typing import Dict, Optional, Any
from urllib.parse import urljoin
import json
import asyncio

from ..core.logger import Logger
from ..core.exceptions import NetworkError
from .certificate_manager import CertificateManager


class HTTPClient:
    """Robust async HTTP client with retry logic and error handling."""

    def __init__(self, logger: Logger = None, timeout: int = 30,
                 verify_ssl: bool = True, proxy: Optional[Dict] = None,
                 custom_ca_path: Optional[str] = None,
                 certificate_pinning: Optional[Dict] = None,
                 suppress_warnings: bool = False):
        """
        Initialize async HTTP client with advanced SSL/TLS configuration.

        Args:
            logger: Logger instance
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates (default: True)
            proxy: Proxy configuration
            custom_ca_path: Path to custom CA certificate bundle
            certificate_pinning: Certificate pinning configuration
            suppress_warnings: Suppress InsecureRequestWarning (use carefully)
        """
        self.logger = logger or Logger(__name__)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.custom_ca_path = custom_ca_path
        self.certificate_pinning = certificate_pinning or {}

        # Initialize certificate manager
        self.cert_manager = CertificateManager(logger=self.logger)

        # Suppress warnings if requested (development/testing only)
        if suppress_warnings:
            self.cert_manager.suppress_insecure_warnings(suppress=True)

        # Configure SSL verification
        if self.verify_ssl:
            self.verify = self.custom_ca_path or self.cert_manager.get_ca_bundle()
        else:
            self.verify = False
            self.logger.warning("SSL verification disabled - this is insecure!")

        self.proxies = proxy
        self.max_retries = 3
        self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async client instance."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self.verify,
                proxies=self.proxies,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                limits=httpx.Limits(max_keepalive_connections=100, max_connections=1000)
            )
        return self._client

    async def get(self, url: str, headers: Dict[str, str] = None,
            params: Dict[str, str] = None, **kwargs) -> httpx.Response:
        """Make async GET request."""
        return await self._request("GET", url, headers=headers, params=params, **kwargs)

    async def post(self, url: str, headers: Dict[str, str] = None,
             data: Any = None, json_data: Dict = None, **kwargs) -> httpx.Response:
        """Make async POST request."""
        return await self._request("POST", url, headers=headers, data=data, json=json_data, **kwargs)

    async def put(self, url: str, headers: Dict[str, str] = None,
            data: Any = None, json_data: Dict = None, **kwargs) -> httpx.Response:
        """Make async PUT request."""
        return await self._request("PUT", url, headers=headers, data=data, json=json_data, **kwargs)

    async def patch(self, url: str, headers: Dict[str, str] = None,
              data: Any = None, json_data: Dict = None, **kwargs) -> httpx.Response:
        """Make async PATCH request."""
        return await self._request("PATCH", url, headers=headers, data=data, json=json_data, **kwargs)

    async def delete(self, url: str, headers: Dict[str, str] = None, **kwargs) -> httpx.Response:
        """Make async DELETE request."""
        return await self._request("DELETE", url, headers=headers, **kwargs)

    async def head(self, url: str, headers: Dict[str, str] = None, **kwargs) -> httpx.Response:
        """Make async HEAD request."""
        return await self._request("HEAD", url, headers=headers, **kwargs)

    async def options(self, url: str, headers: Dict[str, str] = None, **kwargs) -> httpx.Response:
        """Make async OPTIONS request."""
        return await self._request("OPTIONS", url, headers=headers, **kwargs)

    async def _request(self, method: str, url: str, headers: Dict[str, str] = None,
                 retry: int = 0, **kwargs) -> httpx.Response:
        """
        Make async HTTP request with advanced retry logic and SSL error handling.

        Args:
            method: HTTP method
            url: Target URL
            headers: Custom headers
            retry: Current retry attempt
            **kwargs: Additional arguments for httpx

        Returns:
            Response object

        Raises:
            NetworkError: For network-related failures
        """
        try:
            client = await self._get_client()
            response = await client.request(method, url, headers=headers, **kwargs)
            return response

        except httpx.ConnectError as e:
            if "certificate verify failed" in str(e).lower() or "ssl" in str(e).lower():
                error_msg = f"SSL certificate verification failed for {url}: {str(e)}"
                self.logger.error(error_msg)
                raise NetworkError(f"Certificate verification failed: {error_msg}")

            if retry < self.max_retries:
                self.logger.warning(f"Connection error on {method} {url}, retrying... ({retry + 1}/{self.max_retries})")
                await asyncio.sleep(0.5 * (retry + 1))  # Exponential backoff
                return await self._request(method, url, headers=headers, retry=retry + 1, **kwargs)
            raise NetworkError(f"Connection error on {method} {url} after {self.max_retries} retries: {str(e)}")

        except httpx.TimeoutException:
            if retry < self.max_retries:
                self.logger.warning(f"Timeout on {method} {url}, retrying... ({retry + 1}/{self.max_retries})")
                await asyncio.sleep(0.5 * (retry + 1))
                return await self._request(method, url, headers=headers, retry=retry + 1, **kwargs)
            raise NetworkError(f"Timeout on {method} {url} after {self.max_retries} retries")

        except httpx.HTTPError as e:
            raise NetworkError(f"HTTP request failed for {method} {url}: {str(e)}")

        except Exception as e:
            raise NetworkError(f"Unexpected error during HTTP request to {url}: {str(e)}")

    async def close(self):
        """Close async client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
