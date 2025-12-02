"""REST API scanner."""

from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import json

from ...core.logger import Logger
from ...core.config import Config
from ...utils.http_client import HTTPClient
from ...utils.wordlist_loader import WordlistLoader


class RestScanner:
    """Scanner for REST APIs."""

    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    def __init__(self, config: Config, logger: Logger = None):
        """
        Initialize REST scanner.

        Args:
            config: Configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(
            logger=self.logger,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
            proxy=config.proxy.get_proxies() if config.proxy else None,
            custom_ca_path=config.custom_ca_path
        )
        self.wordlist = WordlistLoader(config.wordlist)

    def discover_endpoints(self) -> List[Dict[str, Any]]:
        """
        Discover REST endpoints.

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Check for OpenAPI/Swagger documentation
            swagger_endpoints = self._discover_from_swagger()
            endpoints.extend(swagger_endpoints)
            self.logger.debug(f"Discovered {len(swagger_endpoints)} endpoints from Swagger")

            # Wordlist-based discovery
            wordlist_endpoints = self._discover_from_wordlist()
            endpoints.extend(wordlist_endpoints)
            self.logger.debug(f"Discovered {len(wordlist_endpoints)} endpoints from wordlist")

            # Remove duplicates
            seen = set()
            unique_endpoints = []
            for ep in endpoints:
                key = (ep.get('path'), tuple(sorted(ep.get('methods', []))))
                if key not in seen:
                    seen.add(key)
                    unique_endpoints.append(ep)

            return unique_endpoints[:self.config.max_endpoints]

        except Exception as e:
            self.logger.error(f"Endpoint discovery failed: {str(e)}")
            return endpoints

    def _discover_from_swagger(self) -> List[Dict[str, Any]]:
        """
        Discover endpoints from Swagger/OpenAPI documentation.

        Returns:
            List of endpoints
        """
        endpoints = []
        swagger_urls = [
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
            "/api/swagger.json",
            "/api/docs/swagger.json",
        ]

        for url in swagger_urls:
            try:
                full_url = urljoin(self.config.url, url)
                resp = self.http_client.get(full_url)

                if resp.status_code == 200:
                    data = resp.json()

                    # Extract paths from OpenAPI/Swagger
                    if "paths" in data:
                        for path, methods in data["paths"].items():
                            endpoint = {
                                "path": path,
                                "methods": list(methods.keys()),
                                "source": "swagger",
                                "full_url": urljoin(self.config.url, path)
                            }
                            endpoints.append(endpoint)

            except Exception as e:
                self.logger.debug(f"Swagger discovery failed for {url}: {str(e)}")

        return endpoints

    def _discover_from_wordlist(self) -> List[Dict[str, Any]]:
        """
        Discover endpoints using wordlist fuzzing.

        Returns:
            List of endpoints
        """
        endpoints = []
        wordlist = self.wordlist.get_endpoints()

        for path in wordlist:
            try:
                url = urljoin(self.config.url, path)

                # Try different HTTP methods
                for method in self.HTTP_METHODS:
                    try:
                        if method == "GET":
                            resp = self.http_client.get(url, timeout=self.config.timeout)
                        elif method == "HEAD":
                            resp = self.http_client.head(url, timeout=self.config.timeout)
                        elif method == "OPTIONS":
                            resp = self.http_client.options(url, timeout=self.config.timeout)
                        else:
                            continue

                        # Check if endpoint exists
                        if resp.status_code not in [404, 405, 501, 502, 503]:
                            endpoints.append({
                                "path": path,
                                "methods": [method],
                                "status_code": resp.status_code,
                                "source": "wordlist",
                                "full_url": url
                            })
                            break

                    except Exception:
                        pass

            except Exception as e:
                self.logger.debug(f"Error testing path {path}: {str(e)}")

        return endpoints
