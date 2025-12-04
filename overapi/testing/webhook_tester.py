"""Webhook testing utilities inspired by HTTP Workbench webhook support."""

import asyncio
import json
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from aiohttp import web


@dataclass
class WebhookCall:
    """Represents a received webhook call."""

    timestamp: str
    method: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, str]
    body: Optional[str] = None
    remote_addr: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "query_params": self.query_params,
            "body": self.body,
            "remote_addr": self.remote_addr
        }


class WebhookTester:
    """
    Webhook testing utility for capturing and verifying webhook calls.

    Inspired by HTTP Workbench's webhook support:
    - Capture incoming webhook requests
    - Verify webhook payloads
    - Test webhook retries and failures
    - Simulate various webhook scenarios
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        """
        Initialize webhook tester.

        Args:
            host: Server host
            port: Server port
        """
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner = None
        self.site = None
        self.webhook_calls: List[WebhookCall] = []
        self.custom_handlers: Dict[str, Callable] = {}
        self.default_response = {"status": "ok"}
        self.default_status_code = 200

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        """Handle incoming webhook request."""
        # Capture webhook call
        body = None
        try:
            body = await request.text()
        except Exception:
            pass

        webhook_call = WebhookCall(
            timestamp=datetime.utcnow().isoformat(),
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            query_params=dict(request.query),
            body=body,
            remote_addr=request.remote
        )

        self.webhook_calls.append(webhook_call)

        # Check for custom handler
        if request.path in self.custom_handlers:
            handler = self.custom_handlers[request.path]
            try:
                response_data = await handler(webhook_call)
                if isinstance(response_data, tuple):
                    body, status_code = response_data
                else:
                    body, status_code = response_data, 200

                return web.Response(
                    text=json.dumps(body) if isinstance(body, dict) else str(body),
                    status=status_code,
                    headers={"Content-Type": "application/json"}
                )
            except Exception as e:
                return web.Response(
                    text=json.dumps({"error": str(e)}),
                    status=500,
                    headers={"Content-Type": "application/json"}
                )

        # Default response
        return web.Response(
            text=json.dumps(self.default_response),
            status=self.default_status_code,
            headers={"Content-Type": "application/json"}
        )

    def set_default_response(self, response_body: Dict, status_code: int = 200):
        """
        Set default webhook response.

        Args:
            response_body: Default response body
            status_code: Default status code
        """
        self.default_response = response_body
        self.default_status_code = status_code

    def register_handler(self, path: str, handler: Callable):
        """
        Register custom handler for specific webhook path.

        Args:
            path: Webhook path
            handler: Async handler function
        """
        self.custom_handlers[path] = handler

    async def start(self):
        """Start the webhook server."""
        # Setup route handler for all methods
        for method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            self.app.router.add_route(method, '/{path:.*}', self._handle_webhook)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()

    async def stop(self):
        """Stop the webhook server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    def get_url(self, path: str = "/webhook") -> str:
        """
        Get webhook URL.

        Args:
            path: Webhook path

        Returns:
            Full webhook URL
        """
        return f"http://{self.host}:{self.port}{path}"

    def get_calls(self, path: Optional[str] = None, method: Optional[str] = None) -> List[WebhookCall]:
        """
        Get received webhook calls with optional filtering.

        Args:
            path: Filter by path
            method: Filter by HTTP method

        Returns:
            List of webhook calls
        """
        calls = self.webhook_calls

        if path:
            calls = [c for c in calls if c.path == path]

        if method:
            calls = [c for c in calls if c.method == method.upper()]

        return calls

    def get_last_call(self) -> Optional[WebhookCall]:
        """
        Get the most recent webhook call.

        Returns:
            Last webhook call or None
        """
        return self.webhook_calls[-1] if self.webhook_calls else None

    def wait_for_webhook(
        self,
        timeout: float = 5.0,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> Optional[WebhookCall]:
        """
        Wait for a webhook call (blocking).

        Args:
            timeout: Maximum wait time in seconds
            path: Expected webhook path
            method: Expected HTTP method

        Returns:
            Matching webhook call or None
        """
        start_time = time.time()
        initial_count = len(self.webhook_calls)

        while time.time() - start_time < timeout:
            calls = self.get_calls(path=path, method=method)
            if len(calls) > initial_count:
                return calls[-1]
            time.sleep(0.1)

        return None

    async def wait_for_webhook_async(
        self,
        timeout: float = 5.0,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> Optional[WebhookCall]:
        """
        Wait for a webhook call (async).

        Args:
            timeout: Maximum wait time in seconds
            path: Expected webhook path
            method: Expected HTTP method

        Returns:
            Matching webhook call or None
        """
        start_time = time.time()
        initial_count = len(self.webhook_calls)

        while time.time() - start_time < timeout:
            calls = self.get_calls(path=path, method=method)
            if len(calls) > initial_count:
                return calls[-1]
            await asyncio.sleep(0.1)

        return None

    def clear_calls(self):
        """Clear all webhook calls."""
        self.webhook_calls.clear()

    def assert_webhook_called(
        self,
        path: Optional[str] = None,
        method: Optional[str] = None,
        times: Optional[int] = None
    ) -> bool:
        """
        Assert webhook was called.

        Args:
            path: Expected path
            method: Expected method
            times: Expected number of calls

        Returns:
            True if assertion passes

        Raises:
            AssertionError: If assertion fails
        """
        calls = self.get_calls(path=path, method=method)

        if times is not None:
            assert len(calls) == times, f"Expected {times} webhook calls, got {len(calls)}"
        else:
            assert len(calls) > 0, "Expected at least one webhook call, got none"

        return True

    def assert_webhook_body_contains(self, expected: Dict, path: Optional[str] = None):
        """
        Assert webhook body contains expected data.

        Args:
            expected: Expected data in body
            path: Webhook path

        Raises:
            AssertionError: If assertion fails
        """
        calls = self.get_calls(path=path)
        assert len(calls) > 0, f"No webhook calls found for path {path}"

        last_call = calls[-1]
        if last_call.body:
            try:
                body_data = json.loads(last_call.body)
                for key, value in expected.items():
                    assert key in body_data, f"Key '{key}' not found in webhook body"
                    assert body_data[key] == value, f"Expected {key}={value}, got {body_data[key]}"
            except json.JSONDecodeError:
                raise AssertionError("Webhook body is not valid JSON")
        else:
            raise AssertionError("Webhook body is empty")

    def get_call_count(self, path: Optional[str] = None, method: Optional[str] = None) -> int:
        """
        Get number of webhook calls.

        Args:
            path: Filter by path
            method: Filter by method

        Returns:
            Number of calls
        """
        return len(self.get_calls(path=path, method=method))

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()

    def __len__(self) -> int:
        """Return number of webhook calls."""
        return len(self.webhook_calls)
