"""HTTP client for API communication with advanced SSL/TLS handling."""

import requests
import ssl
from typing import Dict, Optional, Any, Tuple
from urllib.parse import urljoin
import json

from ..core.logger import Logger
from ..core.exceptions import NetworkError
from .certificate_manager import CertificateManager


class HTTPClient:
    """Robust HTTP client with retry logic and error handling."""

    def __init__(self, logger: Logger = None, timeout: int = 30,
                 verify_ssl: bool = True, proxy: Optional[Dict] = None,
                 custom_ca_path: Optional[str] = None,
                 certificate_pinning: Optional[Dict] = None,
                 suppress_warnings: bool = False):
        """
        Initialize HTTP client with advanced SSL/TLS configuration.

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

        # Setup session with SSL configuration
        self.session = requests.Session()
        self._configure_ssl()

        if proxy:
            self.session.proxies.update(proxy)

        self.max_retries = 3

    def _configure_ssl(self) -> None:
        """Configure SSL/TLS settings for the session."""
        if self.verify_ssl:
            # Use custom CA bundle if provided, otherwise use certifi
            self.session.verify = self.custom_ca_path or self.cert_manager.get_ca_bundle()
        else:
            self.session.verify = False
            self.logger.warning("SSL verification disabled - this is insecure!")

    def get(self, url: str, headers: Dict[str, str] = None,
            params: Dict[str, str] = None, **kwargs) -> requests.Response:
        """Make GET request."""
        return self._request("GET", url, headers=headers, params=params, **kwargs)

    def post(self, url: str, headers: Dict[str, str] = None,
             data: Any = None, json_data: Dict = None, **kwargs) -> requests.Response:
        """Make POST request."""
        return self._request("POST", url, headers=headers, data=data, json=json_data, **kwargs)

    def put(self, url: str, headers: Dict[str, str] = None,
            data: Any = None, json_data: Dict = None, **kwargs) -> requests.Response:
        """Make PUT request."""
        return self._request("PUT", url, headers=headers, data=data, json=json_data, **kwargs)

    def patch(self, url: str, headers: Dict[str, str] = None,
              data: Any = None, json_data: Dict = None, **kwargs) -> requests.Response:
        """Make PATCH request."""
        return self._request("PATCH", url, headers=headers, data=data, json=json_data, **kwargs)

    def delete(self, url: str, headers: Dict[str, str] = None, **kwargs) -> requests.Response:
        """Make DELETE request."""
        return self._request("DELETE", url, headers=headers, **kwargs)

    def head(self, url: str, headers: Dict[str, str] = None, **kwargs) -> requests.Response:
        """Make HEAD request."""
        return self._request("HEAD", url, headers=headers, **kwargs)

    def options(self, url: str, headers: Dict[str, str] = None, **kwargs) -> requests.Response:
        """Make OPTIONS request."""
        return self._request("OPTIONS", url, headers=headers, **kwargs)

    def _request(self, method: str, url: str, headers: Dict[str, str] = None,
                 retry: int = 0, **kwargs) -> requests.Response:
        """
        Make HTTP request with advanced retry logic and SSL error handling.

        Args:
            method: HTTP method
            url: Target URL
            headers: Custom headers
            retry: Current retry attempt
            **kwargs: Additional arguments for requests

        Returns:
            Response object

        Raises:
            NetworkError: For network-related failures
        """
        try:
            kwargs['timeout'] = kwargs.get('timeout', self.timeout)
            kwargs['allow_redirects'] = kwargs.get('allow_redirects', True)

            response = self.session.request(method, url, headers=headers, **kwargs)
            return response

        except requests.exceptions.SSLError as e:
            error_msg = f"SSL certificate verification failed for {url}: {str(e)}"
            self.logger.error(error_msg)

            # Check if it's a certificate pinning failure
            if "certificate verify failed" in str(e).lower():
                raise NetworkError(f"Certificate verification failed: {error_msg}")

            # For self-signed or expired certs
            if "self signed certificate" in str(e).lower() or "certificate verify failed" in str(e).lower():
                raise NetworkError(f"Invalid certificate: {error_msg}")

            raise NetworkError(error_msg)

        except requests.exceptions.Timeout:
            if retry < self.max_retries:
                self.logger.warning(f"Timeout on {method} {url}, retrying... ({retry + 1}/{self.max_retries})")
                return self._request(method, url, headers=headers, retry=retry + 1, **kwargs)
            raise NetworkError(f"Timeout on {method} {url} after {self.max_retries} retries")

        except requests.exceptions.ConnectionError as e:
            if retry < self.max_retries:
                self.logger.warning(f"Connection error on {method} {url}, retrying... ({retry + 1}/{self.max_retries})")
                return self._request(method, url, headers=headers, retry=retry + 1, **kwargs)
            raise NetworkError(f"Connection error on {method} {url} after {self.max_retries} retries: {str(e)}")

        except requests.exceptions.RequestException as e:
            raise NetworkError(f"HTTP request failed for {method} {url}: {str(e)}")

        except Exception as e:
            raise NetworkError(f"Unexpected error during HTTP request to {url}: {str(e)}")

    def close(self):
        """Close session."""
        self.session.close()
