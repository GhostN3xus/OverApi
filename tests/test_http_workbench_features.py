"""Test HTTP Workbench-inspired features."""

import pytest
import httpx
import json
import asyncio
from overapi.testing import (
    RequestLogger,
    MockHTTPServer,
    WebhookTester,
    RequestLog,
    WebhookCall
)


class TestRequestLogger:
    """Test RequestLogger functionality."""

    def test_logger_initialization(self):
        """Test logger can be initialized."""
        logger = RequestLogger(enabled=True, max_body_size=5000)
        assert logger.enabled is True
        assert logger.max_body_size == 5000
        assert len(logger) == 0

    def test_log_request_basic(self):
        """Test basic request logging."""
        logger = RequestLogger()

        log = logger.log_request(
            method="GET",
            url="https://api.example.com/users",
            headers={"User-Agent": "TestClient/1.0"},
            params={"page": 1}
        )

        assert log is not None
        assert log.method == "GET"
        assert log.url == "https://api.example.com/users"
        assert log.headers["User-Agent"] == "TestClient/1.0"
        assert log.query_params == {"page": 1}
        assert len(logger) == 1

    def test_log_request_with_json_body(self):
        """Test logging request with JSON body."""
        logger = RequestLogger()

        body = {"username": "test", "email": "test@example.com"}
        log = logger.log_request(
            method="POST",
            url="https://api.example.com/users",
            headers={"Content-Type": "application/json"},
            body=body
        )

        assert log.body_size > 0
        assert "username" in log.body
        assert log.content_type == "application/json"

    def test_log_response(self):
        """Test response logging."""
        logger = RequestLogger()

        # Create mock response
        response = httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b'{"status": "ok"}'
        )

        log = logger.log_request("GET", "https://api.example.com/test")
        logger.log_response(log, response, response_time=0.123)

        assert log.status_code == 200
        assert log.response_time == 0.123
        assert log.response_size > 0
        assert "status" in log.response_body

    def test_filter_logs_by_method(self):
        """Test filtering logs by HTTP method."""
        logger = RequestLogger()

        logger.log_request("GET", "https://api.example.com/users")
        logger.log_request("POST", "https://api.example.com/users")
        logger.log_request("GET", "https://api.example.com/posts")

        get_logs = logger.get_logs(method="GET")
        assert len(get_logs) == 2

        post_logs = logger.get_logs(method="POST")
        assert len(post_logs) == 1

    def test_filter_logs_by_url(self):
        """Test filtering logs by URL substring."""
        logger = RequestLogger()

        logger.log_request("GET", "https://api.example.com/users")
        logger.log_request("GET", "https://api.example.com/posts")
        logger.log_request("GET", "https://other.com/users")

        filtered = logger.get_logs(url_contains="example.com")
        assert len(filtered) == 2

    def test_get_summary(self):
        """Test getting log summary statistics."""
        logger = RequestLogger()

        # Add some requests
        response_ok = httpx.Response(200, content=b'{"status": "ok"}')
        response_error = httpx.Response(404, content=b'{"error": "not found"}')

        log1 = logger.log_request("GET", "https://api.example.com/users")
        logger.log_response(log1, response_ok, 0.1)

        log2 = logger.log_request("POST", "https://api.example.com/posts")
        logger.log_response(log2, response_ok, 0.2)

        log3 = logger.log_request("GET", "https://api.example.com/error")
        logger.log_response(log3, response_error, 0.15)

        summary = logger.get_summary()
        assert summary["total_requests"] == 3
        assert summary["methods"]["GET"] == 2
        assert summary["methods"]["POST"] == 1
        assert summary["status_codes"][200] == 2
        assert summary["status_codes"][404] == 1
        assert summary["avg_response_time"] > 0

    def test_clear_logs(self):
        """Test clearing logs."""
        logger = RequestLogger()

        logger.log_request("GET", "https://api.example.com/test")
        assert len(logger) == 1

        logger.clear()
        assert len(logger) == 0


class TestMockHTTPServer:
    """Test MockHTTPServer functionality."""

    @pytest.mark.asyncio
    async def test_mock_server_basic(self, mock_server):
        """Test basic mock server functionality."""
        # Add endpoint
        mock_server.add_json_endpoint(
            path="/api/test",
            method="GET",
            json_data={"message": "Hello World"}
        )

        # Make request
        url = mock_server.get_url("/api/test")
        async with httpx.AsyncClient() as client:
            response = await client.get(url)

        assert response.status_code == 200
        assert response.json()["message"] == "Hello World"

    @pytest.mark.asyncio
    async def test_mock_server_post_endpoint(self, mock_server):
        """Test POST endpoint."""
        mock_server.add_json_endpoint(
            path="/api/users",
            method="POST",
            json_data={"id": 123, "created": True},
            status_code=201
        )

        url = mock_server.get_url("/api/users")
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json={"username": "test"})

        assert response.status_code == 201
        assert response.json()["created"] is True

    @pytest.mark.asyncio
    async def test_mock_server_error_endpoint(self, mock_server):
        """Test error endpoint."""
        mock_server.add_error_endpoint(
            path="/api/error",
            status_code=500,
            error_message="Internal Server Error"
        )

        url = mock_server.get_url("/api/error")
        async with httpx.AsyncClient() as client:
            response = await client.get(url)

        assert response.status_code == 500
        assert "error" in response.json()

    @pytest.mark.asyncio
    async def test_mock_server_delay(self, mock_server):
        """Test delayed response."""
        mock_server.add_json_endpoint(
            path="/api/slow",
            json_data={"status": "ok"},
            delay=0.2
        )

        url = mock_server.get_url("/api/slow")
        start_time = asyncio.get_event_loop().time()

        async with httpx.AsyncClient() as client:
            response = await client.get(url)

        elapsed = asyncio.get_event_loop().time() - start_time
        assert elapsed >= 0.2
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_mock_server_request_logging(self, mock_server):
        """Test request logging."""
        mock_server.add_json_endpoint("/api/test", json_data={"status": "ok"})

        url = mock_server.get_url("/api/test")
        async with httpx.AsyncClient() as client:
            await client.get(url, headers={"X-Test-Header": "test-value"})

        logs = mock_server.get_request_log()
        assert len(logs) == 1
        assert logs[0]["method"] == "GET"
        assert logs[0]["path"] == "/api/test"
        assert "X-Test-Header" in logs[0]["headers"]


class TestWebhookTester:
    """Test WebhookTester functionality."""

    @pytest.mark.asyncio
    async def test_webhook_tester_basic(self, webhook_tester):
        """Test basic webhook functionality."""
        webhook_url = webhook_tester.get_url("/webhook")

        # Send webhook
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url,
                json={"event": "test", "data": {"value": 123}}
            )

        assert response.status_code == 200
        assert len(webhook_tester) == 1

    @pytest.mark.asyncio
    async def test_webhook_tester_get_calls(self, webhook_tester):
        """Test getting webhook calls."""
        webhook_url = webhook_tester.get_url("/webhook")

        # Send multiple webhooks
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json={"event": "test1"})
            await client.post(webhook_url, json={"event": "test2"})

        calls = webhook_tester.get_calls()
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_webhook_tester_filter_by_path(self, webhook_tester):
        """Test filtering webhook calls by path."""
        async with httpx.AsyncClient() as client:
            await client.post(webhook_tester.get_url("/webhook1"), json={"event": "a"})
            await client.post(webhook_tester.get_url("/webhook2"), json={"event": "b"})
            await client.post(webhook_tester.get_url("/webhook1"), json={"event": "c"})

        calls_webhook1 = webhook_tester.get_calls(path="/webhook1")
        assert len(calls_webhook1) == 2

        calls_webhook2 = webhook_tester.get_calls(path="/webhook2")
        assert len(calls_webhook2) == 1

    @pytest.mark.asyncio
    async def test_webhook_tester_wait_for_webhook(self, webhook_tester):
        """Test waiting for webhook."""
        webhook_url = webhook_tester.get_url("/webhook")

        # Send webhook after delay
        async def send_delayed():
            await asyncio.sleep(0.5)
            async with httpx.AsyncClient() as client:
                await client.post(webhook_url, json={"event": "delayed"})

        # Start sending in background
        asyncio.create_task(send_delayed())

        # Wait for webhook
        call = await webhook_tester.wait_for_webhook_async(timeout=2.0)
        assert call is not None
        assert "delayed" in call.body

    @pytest.mark.asyncio
    async def test_webhook_tester_assert_called(self, webhook_tester):
        """Test webhook assertion."""
        webhook_url = webhook_tester.get_url("/test")

        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json={"data": "test"})

        # Should pass
        webhook_tester.assert_webhook_called(path="/test", times=1)

        # Should fail
        with pytest.raises(AssertionError):
            webhook_tester.assert_webhook_called(path="/test", times=2)

    @pytest.mark.asyncio
    async def test_webhook_tester_assert_body_contains(self, webhook_tester):
        """Test webhook body assertion."""
        webhook_url = webhook_tester.get_url("/webhook")

        async with httpx.AsyncClient() as client:
            await client.post(
                webhook_url,
                json={"event": "user.created", "user_id": 123}
            )

        # Should pass
        webhook_tester.assert_webhook_body_contains(
            {"event": "user.created", "user_id": 123}
        )

        # Should fail
        with pytest.raises(AssertionError):
            webhook_tester.assert_webhook_body_contains({"event": "user.deleted"})

    @pytest.mark.asyncio
    async def test_webhook_tester_custom_handler(self, webhook_tester):
        """Test custom webhook handler."""
        # Register custom handler
        async def custom_handler(call: WebhookCall):
            return {"custom": "response", "received": True}, 201

        webhook_tester.register_handler("/custom", custom_handler)

        # Send request
        url = webhook_tester.get_url("/custom")
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json={"data": "test"})

        assert response.status_code == 201
        data = response.json()
        assert data["custom"] == "response"
        assert data["received"] is True


class TestIntegrationWithHTTPClient:
    """Test integration with existing HTTPClient."""

    @pytest.mark.asyncio
    async def test_request_logger_with_http_client(self, mock_server, request_logger):
        """Test RequestLogger with HTTPClient."""
        from overapi.utils.http_client import HTTPClient

        # Setup mock server
        mock_server.add_json_endpoint(
            "/api/test",
            json_data={"status": "success", "data": [1, 2, 3]}
        )

        # Create HTTP client
        client = HTTPClient(timeout=10, verify_ssl=False)

        # Make request and log it
        url = mock_server.get_url("/api/test")

        log = request_logger.log_request("GET", url, headers={"X-Test": "value"})

        import time
        start = time.time()
        response = await client.get(url, headers={"X-Test": "value"})
        elapsed = time.time() - start

        request_logger.log_response(log, response, elapsed)

        # Verify logging
        assert len(request_logger) == 1
        assert log.status_code == 200
        assert log.response_time > 0
        assert "status" in log.response_body

        await client.close()

    @pytest.mark.asyncio
    async def test_mock_server_simulates_api_endpoints(self, mock_server):
        """Test using MockHTTPServer to simulate API endpoints for testing."""
        from overapi.utils.http_client import HTTPClient

        # Setup various API endpoints
        mock_server.add_json_endpoint("/api/users", json_data=[
            {"id": 1, "name": "User 1"},
            {"id": 2, "name": "User 2"}
        ])

        mock_server.add_json_endpoint(
            "/api/users",
            method="POST",
            json_data={"id": 3, "name": "New User"},
            status_code=201
        )

        mock_server.add_error_endpoint(
            "/api/protected",
            status_code=401,
            error_message="Unauthorized"
        )

        # Test with HTTP client
        client = HTTPClient(timeout=10, verify_ssl=False)

        # Test GET
        response = await client.get(mock_server.get_url("/api/users"))
        assert response.status_code == 200
        assert len(response.json()) == 2

        # Test POST
        response = await client.post(
            mock_server.get_url("/api/users"),
            json_data={"name": "New User"}
        )
        assert response.status_code == 201

        # Test error endpoint
        response = await client.get(mock_server.get_url("/api/protected"))
        assert response.status_code == 401

        await client.close()
