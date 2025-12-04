"""GraphQL API scanner."""

from typing import List, Dict, Any
from urllib.parse import urljoin
import json
import asyncio

from ...core.logger import Logger
from ...core.config import Config
from ...core.context import ScanContext, Endpoint
from ...utils.http_client import HTTPClient


class GraphQLScanner:
    """Scanner for GraphQL APIs."""

    GRAPHQL_ENDPOINTS = ["/graphql", "/.graphql", "/api/graphql", "/graphql/query"]

    def __init__(self, context: ScanContext = None, config: Config = None, logger: Logger = None):
        """
        Initialize GraphQL scanner.

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

    async def discover_endpoints(self) -> List[Endpoint]:
        """
        Discover GraphQL endpoints asynchronously (wrapper for sync method).

        Returns:
            List of discovered endpoints
        """
        # Temporary: wrap sync method to avoid blocking
        return await asyncio.to_thread(self._discover_endpoints_sync)

    def _discover_endpoints_sync(self) -> List[Endpoint]:
        """
        Discover GraphQL endpoints (synchronous implementation).

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Find GraphQL endpoint
            graphql_url = self._find_graphql_endpoint()

            if not graphql_url:
                self.logger.warning("GraphQL endpoint not found")
                return endpoints

            # Perform introspection
            schema = self._introspect(graphql_url)

            if schema:
                fields = self._extract_fields(schema, graphql_url)

                # Convert fields to Endpoint objects
                for field in fields:
                    endpoint = Endpoint(
                        path=field.get("path", ""),
                        method="POST",
                        metadata={
                            "type": "graphql",
                            "field_type": field.get("type", ""),
                            "graphql_endpoint": graphql_url
                        }
                    )
                    endpoints.append(endpoint)

                    # Add to context if available
                    if self.context:
                        self.context.add_endpoint(endpoint)

                self.logger.debug(f"Discovered {len(endpoints)} GraphQL fields")

            return endpoints

        except Exception as e:
            self.logger.error(f"GraphQL endpoint discovery failed: {str(e)}")
            return endpoints

    def discover_fields(self) -> List[Dict[str, Any]]:
        """
        Discover GraphQL fields via introspection (legacy method).

        Returns:
            List of discovered fields
        """
        fields = []

        try:
            # Find GraphQL endpoint
            endpoint = self._find_graphql_endpoint()

            if not endpoint:
                self.logger.warning("GraphQL endpoint not found")
                return fields

            # Perform introspection
            schema = self._introspect(endpoint)

            if schema:
                fields = self._extract_fields(schema, endpoint)
                self.logger.debug(f"Extracted {len(fields)} fields from GraphQL schema")

            return fields

        except Exception as e:
            self.logger.error(f"GraphQL field discovery failed: {str(e)}")
            return fields

    def _find_graphql_endpoint(self) -> str:
        """
        Find GraphQL endpoint.

        Returns:
            GraphQL endpoint URL or None
        """
        for endpoint in self.GRAPHQL_ENDPOINTS:
            try:
                url = urljoin(self.config.url, endpoint)
                payload = {"query": "{__typename}"}
                resp = self.http_client.post(url, json_data=payload)

                if resp.status_code in [200, 400]:
                    self.logger.debug(f"GraphQL endpoint found at: {url}")
                    return url

            except Exception:
                pass

        # Try root URL
        try:
            payload = {"query": "{__typename}"}
            resp = self.http_client.post(self.config.url, json_data=payload)

            if resp.status_code in [200, 400]:
                self.logger.debug(f"GraphQL endpoint found at root URL")
                return self.config.url

        except Exception:
            pass

        return None

    def _introspect(self, endpoint: str) -> Dict:
        """
        Perform GraphQL introspection.

        Args:
            endpoint: GraphQL endpoint

        Returns:
            Schema dictionary
        """
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                            type {
                                name
                                kind
                            }
                        }
                    }
                }
            }
            """
        }

        try:
            resp = self.http_client.post(endpoint, json_data=introspection_query)

            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {})

        except Exception as e:
            self.logger.debug(f"Introspection failed: {str(e)}")

        return {}

    def _extract_fields(self, schema: Dict, endpoint: str) -> List[Dict[str, Any]]:
        """
        Extract fields from GraphQL schema.

        Args:
            schema: GraphQL schema
            endpoint: GraphQL endpoint

        Returns:
            List of fields
        """
        fields = []

        try:
            schema_types = schema.get("__schema", {}).get("types", [])

            for type_def in schema_types:
                type_name = type_def.get("name", "")
                type_fields = type_def.get("fields", [])

                for field in type_fields:
                    field_name = field.get("name", "")
                    field_type = field.get("type", {}).get("name", "")

                    fields.append({
                        "path": f"{type_name}.{field_name}",
                        "type": field_type,
                        "source": "graphql",
                        "endpoint": endpoint,
                        "full_url": endpoint
                    })

        except Exception as e:
            self.logger.debug(f"Field extraction failed: {str(e)}")

        return fields

    def test_introspection_enabled(self, endpoint: str) -> bool:
        """
        Test if introspection is enabled.

        Args:
            endpoint: GraphQL endpoint

        Returns:
            True if introspection is enabled
        """
        try:
            payload = {"query": "{__typename}"}
            resp = self.http_client.post(endpoint, json_data=payload)

            return resp.status_code == 200 and "data" in resp.text

        except Exception:
            return False

    def test_batching(self, endpoint: str) -> bool:
        """
        Test for query batching vulnerability.

        Args:
            endpoint: GraphQL endpoint

        Returns:
            True if batching is allowed
        """
        try:
            # Try to send multiple queries
            payload = [
                {"query": "{__typename}"},
                {"query": "{__typename}"}
            ]
            resp = self.http_client.post(endpoint, json_data=payload)

            return resp.status_code == 200

        except Exception:
            return False
