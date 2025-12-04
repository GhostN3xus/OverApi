"""PyTest configuration and fixtures for OverApi tests."""

import pytest
import pytest_asyncio
from unittest.mock import MagicMock

@pytest.fixture
def mock_config():
    """Create mock configuration object."""
    from overapi.core.config import Config, ScanMode
    return Config(
        url="https://api.example.com",
        threads=10,
        timeout=30,
        verify_ssl=False
    )

@pytest.fixture
def mock_logger():
    """Create mock logger."""
    return MagicMock()

@pytest.fixture
def sample_endpoints():
    """Sample endpoints for testing."""
    return [
        {"path": "/api/users", "method": "GET"},
        {"path": "/api/users/{id}", "method": "GET"},
    ]

# New fixtures inspired by HTTP Workbench

@pytest.fixture
def request_logger():
    """Create RequestLogger instance for detailed request/response logging."""
    from overapi.testing import RequestLogger
    return RequestLogger(enabled=True, max_body_size=10000)

@pytest_asyncio.fixture
async def mock_server():
    """
    Create and start MockHTTPServer for testing.

    Usage:
        async def test_api(mock_server):
            mock_server.add_json_endpoint("/api/test", json_data={"status": "ok"})
            url = mock_server.get_url("/api/test")
            # Make request to url
    """
    from overapi.testing import MockHTTPServer
    server = MockHTTPServer(host="127.0.0.1", port=8888)
    await server.start()
    yield server
    await server.stop()

@pytest_asyncio.fixture
async def webhook_tester():
    """
    Create and start WebhookTester for webhook testing.

    Usage:
        async def test_webhook(webhook_tester):
            webhook_url = webhook_tester.get_url("/webhook")
            # Send request to webhook_url
            call = await webhook_tester.wait_for_webhook_async(timeout=5.0)
            assert call is not None
    """
    from overapi.testing import WebhookTester
    tester = WebhookTester(host="127.0.0.1", port=9999)
    await tester.start()
    yield tester
    await tester.stop()
