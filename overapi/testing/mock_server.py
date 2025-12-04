"""Mock HTTP server for testing, inspired by HTTP Workbench PoC hosting."""

import asyncio
import json
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from aiohttp import web
from threading import Thread
import time


@dataclass
class MockEndpoint:
    """Mock endpoint configuration."""

    path: str
    method: str
    response_body: Any
    status_code: int = 200
    headers: Optional[Dict[str, str]] = None
    delay: float = 0.0  # Response delay in seconds


class MockHTTPServer:
    """
    Mock HTTP server for testing API interactions.

    Inspired by HTTP Workbench's PoC hosting capabilities:
    - Host temporary endpoints for testing
    - Configure custom responses
    - Log incoming requests
    - Simulate various HTTP scenarios (delays, errors, etc.)
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8888):
        """
        Initialize mock server.

        Args:
            host: Server host
            port: Server port
        """
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner = None
        self.site = None
        self.endpoints: List[MockEndpoint] = []
        self.request_log: List[Dict] = []
        self._server_task = None

    def add_endpoint(
        self,
        path: str,
        method: str = "GET",
        response_body: Any = None,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        delay: float = 0.0
    ):
        """
        Add mock endpoint.

        Args:
            path: Endpoint path (e.g., "/api/users")
            method: HTTP method
            response_body: Response body (dict, str, or bytes)
            status_code: HTTP status code
            headers: Response headers
            delay: Response delay in seconds
        """
        endpoint = MockEndpoint(
            path=path,
            method=method.upper(),
            response_body=response_body,
            status_code=status_code,
            headers=headers or {},
            delay=delay
        )
        self.endpoints.append(endpoint)

    def add_json_endpoint(
        self,
        path: str,
        method: str = "GET",
        json_data: Dict = None,
        status_code: int = 200,
        delay: float = 0.0
    ):
        """
        Add JSON endpoint (convenience method).

        Args:
            path: Endpoint path
            method: HTTP method
            json_data: JSON response data
            status_code: HTTP status code
            delay: Response delay in seconds
        """
        headers = {"Content-Type": "application/json"}
        self.add_endpoint(
            path=path,
            method=method,
            response_body=json_data,
            status_code=status_code,
            headers=headers,
            delay=delay
        )

    def add_error_endpoint(
        self,
        path: str,
        method: str = "GET",
        status_code: int = 500,
        error_message: str = "Internal Server Error"
    ):
        """
        Add error endpoint.

        Args:
            path: Endpoint path
            method: HTTP method
            status_code: HTTP error status code
            error_message: Error message
        """
        self.add_json_endpoint(
            path=path,
            method=method,
            json_data={"error": error_message},
            status_code=status_code
        )

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming requests."""
        # Log request
        request_data = {
            "timestamp": time.time(),
            "method": request.method,
            "path": request.path,
            "headers": dict(request.headers),
            "query": dict(request.query),
            "remote": request.remote
        }

        # Try to get body
        try:
            body = await request.text()
            if body:
                request_data["body"] = body
        except Exception:
            pass

        self.request_log.append(request_data)

        # Find matching endpoint
        for endpoint in self.endpoints:
            if endpoint.path == request.path and endpoint.method == request.method:
                # Apply delay if configured
                if endpoint.delay > 0:
                    await asyncio.sleep(endpoint.delay)

                # Prepare response
                headers = endpoint.headers.copy() if endpoint.headers else {}

                # Handle different response body types
                if isinstance(endpoint.response_body, (dict, list)):
                    headers["Content-Type"] = "application/json"
                    body = json.dumps(endpoint.response_body)
                elif isinstance(endpoint.response_body, str):
                    body = endpoint.response_body
                elif isinstance(endpoint.response_body, bytes):
                    body = endpoint.response_body
                else:
                    body = str(endpoint.response_body) if endpoint.response_body else ""

                return web.Response(
                    text=body if isinstance(body, str) else body.decode('utf-8', errors='ignore'),
                    status=endpoint.status_code,
                    headers=headers
                )

        # No matching endpoint found
        return web.Response(
            text=json.dumps({"error": "Endpoint not found"}),
            status=404,
            headers={"Content-Type": "application/json"}
        )

    async def start(self):
        """Start the mock server."""
        # Setup route handler for all methods
        for method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']:
            self.app.router.add_route(method, '/{path:.*}', self._handle_request)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()

    async def stop(self):
        """Stop the mock server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    def get_url(self, path: str = "") -> str:
        """
        Get full URL for a path.

        Args:
            path: Endpoint path

        Returns:
            Full URL
        """
        return f"http://{self.host}:{self.port}{path}"

    def get_request_log(self) -> List[Dict]:
        """
        Get logged requests.

        Returns:
            List of request logs
        """
        return self.request_log.copy()

    def clear_request_log(self):
        """Clear request log."""
        self.request_log.clear()

    def clear_endpoints(self):
        """Clear all endpoints."""
        self.endpoints.clear()

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
