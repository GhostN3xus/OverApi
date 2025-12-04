"""REST API scanner - Async version."""

from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
import json

from overapi.core.logger import Logger
from overapi.core.config import Config
from overapi.core.context import ScanContext, Endpoint
from overapi.utils.http_client import HTTPClient
from overapi.utils.wordlist_loader import WordlistLoader


class RestScanner:
    """Async scanner for REST APIs."""

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

    async def discover_endpoints(self) -> List[Endpoint]:
        """
        Discover REST endpoints asynchronously.

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Check for OpenAPI/Swagger documentation
            swagger_endpoints = await self._discover_from_swagger()
            endpoints.extend(swagger_endpoints)
            self.logger.debug(f"Discovered {len(swagger_endpoints)} endpoints from Swagger")

            # Wordlist-based discovery
            if self.config.enable_fuzzing:
                wordlist_endpoints = await self._discover_from_wordlist()
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

    async def _discover_from_swagger(self) -> List[Endpoint]:
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
                resp = await self.http_client.get(full_url)

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

    async def _discover_from_wordlist(self) -> List[Endpoint]:
        """
        Discover endpoints using wordlist fuzzing with wildcard detection.

        Returns:
            List of endpoints
        """
        endpoints = []
        wordlist = self.wordlist.get_endpoints()

        # First, detect wildcard/catch-all behavior
        wildcard_signature = await self._get_wildcard_signature()

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
                            resp = await self.http_client.get(url)
                        else:
                            resp = await self.http_client.post(url)

                        # Check if endpoint exists (200, 401, 403, 405)
                        if resp.status_code not in [404, 501, 502, 503]:
                            # Verify it's not a wildcard match
                            if not self._is_wildcard_match(resp, wildcard_signature):
                                endpoints.append(Endpoint(
                                    path=path,
                                    method=method
                                ))
                                # If we found it with GET, maybe no need to check POST
                                if method == "GET":
                                    break

                    except Exception:
                        pass

            except Exception as e:
                self.logger.debug(f"Error testing path {path}: {str(e)}")

        return endpoints

    async def _get_wildcard_signature(self) -> dict:
        """
        Get signature of wildcard/catch-all responses by testing random paths.

        Returns:
            Dict with wildcard signature (status, length, content_type)
        """
        import random
        import string

        # Test 3 random paths that likely don't exist
        signatures = []

        for _ in range(3):
            random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=20))
            try:
                url = urljoin(self.config.url, random_path)
                resp = await self.http_client.get(url)

                if resp.status_code == 200:
                    signatures.append({
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'content_type': resp.headers.get('Content-Type', ''),
                        'text': resp.text[:500]  # First 500 chars for comparison
                    })
            except Exception:
                pass

        # If all 3 random paths returned similar 200 responses, it's a wildcard
        if len(signatures) == 3:
            # Check if all signatures are similar
            first_sig = signatures[0]
            all_similar = all(
                abs(sig['length'] - first_sig['length']) < 100 and
                sig['status'] == first_sig['status']
                for sig in signatures
            )

            if all_similar:
                return first_sig

        return {}

    def _is_wildcard_match(self, response, wildcard_signature: dict) -> bool:
        """
        Check if response matches wildcard signature.

        Args:
            response: HTTP response
            wildcard_signature: Signature from _get_wildcard_signature

        Returns:
            True if response matches wildcard pattern
        """
        if not wildcard_signature:
            return False

        # Check if response is similar to wildcard signature
        return (
            response.status_code == wildcard_signature['status'] and
            abs(len(response.text) - wildcard_signature['length']) < 100 and
            response.headers.get('Content-Type', '') == wildcard_signature['content_type']
        )
