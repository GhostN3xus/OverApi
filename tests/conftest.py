"""Pytest configuration and fixtures."""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def test_data_dir():
    """Get test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def reset_modules():
    """Reset modules before each test."""
    # Ensures clean state between tests
    yield


@pytest.fixture(scope="session")
def mock_api_url():
    """Mock API URL for testing."""
    return "http://localhost:8080/api"


@pytest.fixture(scope="session")
def test_timeout():
    """Default timeout for tests."""
    return 5


class TestConfig:
    """Test configuration settings."""

    # Verbose logging
    VERBOSE = True

    # Test timeouts (seconds)
    TIMEOUT = 5
    REQUEST_TIMEOUT = 10

    # Fuzzing parameters
    FUZZ_LIMIT = 10
    PAYLOAD_LIMIT = 20

    # Test API endpoints
    TEST_ENDPOINTS = [
        "/api",
        "/api/users",
        "/api/admin",
        "/graphql",
    ]

    # Test payloads
    TEST_SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1 --",
    ]

    TEST_XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ]


@pytest.fixture
def test_config():
    """Provide test configuration."""
    return TestConfig()


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security-focused"
    )
    config.addinivalue_line(
        "markers", "fuzzing: mark test as fuzzing test"
    )
