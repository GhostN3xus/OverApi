"""REST API scanner."""

from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
import json

from overapi.core.logger import Logger
from overapi.core.config import Config
from overapi.core.context import ScanContext, Endpoint
from overapi.utils.http_client import HTTPClient
from overapi.utils.wordlist_loader import WordlistLoader


class RestScanner:
    """Scanner for REST APIs."""

    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    def __init__(self, context: ScanContext, config: Config, logger: Logger = None):
        """
        Initialize REST scanner.

        Args:
            context: Scan context
            config: Configuration
            logger: Logger instance
        """
        self.context = context
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

    def discover_endpoints(self) -> List[Endpoint]:
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
            if self.config.enable_fuzzing:
                wordlist_endpoints = self._discover_from_wordlist()
                endpoints.extend(wordlist_endpoints)
                self.logger.debug(f"Discovered {len(wordlist_endpoints)} endpoints from wordlist")

            # Remove duplicates
            seen: Set[str] = set()
            unique_endpoints = []
            for ep in endpoints:
                key = f"{ep.method} {ep.path}"
                if key not in seen:
                    seen.add(key)
                    unique_endpoints.append(ep)
                    self.context.add_endpoint(ep)

            return unique_endpoints[:self.config.max_endpoints]

        except Exception as e:
            self.logger.error(f"Endpoint discovery failed: {str(e)}")
            return endpoints

    def _discover_from_swagger(self) -> List[Endpoint]:
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
            "/v2/api-docs",
            "/v3/api-docs"
        ]

        for url in swagger_urls:
            try:
                full_url = urljoin(self.config.url, url)
                resp = self.http_client.get(full_url)

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except ValueError:
                        continue # Not JSON

                    # Extract paths from OpenAPI/Swagger
                    if "paths" in data:
                        for path, methods in data["paths"].items():
                            for method in methods.keys():
                                if method.upper() in self.HTTP_METHODS:
                                    endpoint = Endpoint(
                                        path=path,
                                        method=method.upper()
                                    )
                                    endpoints.append(endpoint)

            except Exception as e:
                self.logger.debug(f"Swagger discovery failed for {url}: {str(e)}")

        return endpoints

    def _discover_from_wordlist(self) -> List[Endpoint]:
        """
        Discover endpoints using wordlist fuzzing.

        Returns:
            List of endpoints
        """
        endpoints = []
        wordlist = self.wordlist.get_endpoints()

        for path in wordlist:
            try:
                # Ensure path starts with /
                if not path.startswith('/'):
                    path = '/' + path

                url = urljoin(self.config.url, path)

                # Try common methods
                for method in ["GET", "POST"]:
                    try:
                        if method == "GET":
                            resp = self.http_client.get(url, timeout=self.config.timeout)
                        else:
                            resp = self.http_client.post(url, timeout=self.config.timeout)

                        # Check if endpoint exists (200, 401, 403, 405)
                        # 404 usually means not found.
                        # 5xx might be interesting but maybe not "discovered" in the sense of existing endpoint to test further unless we want to fuzz error handling.
                        if resp.status_code not in [404, 501, 502, 503]:
                            endpoints.append(Endpoint(
                                path=path,
                                method=method
                            ))
                            # If we found it with GET, maybe no need to check POST for discovery unless specific need
                            if method == "GET":
                                break

                    except Exception:
                        pass

            except Exception as e:
                self.logger.debug(f"Error testing path {path}: {str(e)}")

        return endpoints
