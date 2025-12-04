"""PyTest configuration and fixtures for OverApi tests."""

import pytest
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
