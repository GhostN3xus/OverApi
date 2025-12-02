"""HTTP client for API communication."""

import requests
from typing import Dict, Optional, Any, Tuple
from urllib.parse import urljoin
import json

from ..core.logger import Logger
from ..core.exceptions import NetworkError


class HTTPClient:
    """Robust HTTP client with retry logic and error handling."""

    def __init__(self, logger: Logger = None, timeout: int = 30,
                 verify_ssl: bool = False, proxy: Optional[Dict] = None):
        """
        Initialize HTTP client.

        Args:
            logger: Logger instance
            timeout: Request timeout
            verify_ssl: Verify SSL certificates
            proxy: Proxy configuration
        """
        self.logger = logger or Logger(__name__)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if proxy:
            self.session.proxies.update(proxy)

        self.max_retries = 3

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
        Make HTTP request with retry logic.

        Args:
            method: HTTP method
            url: Target URL
            headers: Custom headers
            retry: Current retry attempt
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        try:
            kwargs['timeout'] = kwargs.get('timeout', self.timeout)
            kwargs['allow_redirects'] = kwargs.get('allow_redirects', True)

            response = self.session.request(method, url, headers=headers, **kwargs)
            return response

        except requests.exceptions.Timeout:
            if retry < self.max_retries:
                self.logger.warning(f"Timeout on {method} {url}, retrying... ({retry + 1}/{self.max_retries})")
                return self._request(method, url, headers=headers, retry=retry + 1, **kwargs)
            raise NetworkError(f"Timeout on {method} {url}")

        except requests.exceptions.ConnectionError:
            if retry < self.max_retries:
                self.logger.warning(f"Connection error on {method} {url}, retrying... ({retry + 1}/{self.max_retries})")
                return self._request(method, url, headers=headers, retry=retry + 1, **kwargs)
            raise NetworkError(f"Connection error on {method} {url}")

        except Exception as e:
            raise NetworkError(f"HTTP request failed: {str(e)}")

    def close(self):
        """Close session."""
        self.session.close()
