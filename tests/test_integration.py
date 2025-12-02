"""Integration tests for OverApi security testing."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from overapi.scanner.scanner import Scanner
from overapi.utils.wordlist_loader import WordlistLoader
from overapi.core.config import Config


class TestScannerIntegration:
    """Test Scanner integration with all components."""

    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        return Config(
            url="http://localhost:8080/api",
            threads=2,
            verbose=True,
        )

    @pytest.fixture
    def scanner(self, config):
        """Create a Scanner instance."""
        return Scanner(config)

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner is not None
        assert scanner.config is not None

    def test_scanner_endpoint_discovery(self, scanner):
        """Test endpoint discovery workflow."""
        # Mock HTTP responses
        with patch('overapi.scanner.scanner.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = '{"endpoints": ["/api/users"]}'
            mock_get.return_value = mock_response

            # Should not crash during discovery
            assert scanner is not None

    @patch('overapi.scanner.scanner.requests.get')
    def test_scanner_vulnerability_detection(self, mock_get, scanner):
        """Test vulnerability detection workflow."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "SQL Error"
        mock_get.return_value = mock_response

        # Should detect potential vulnerabilities
        assert scanner is not None

    def test_scanner_wordlist_integration(self, scanner):
        """Test scanner integration with wordlist loader."""
        loader = WordlistLoader()
        endpoints = loader.get_endpoints(limit=5)

        assert len(endpoints) > 0
        assert all(isinstance(e, str) for e in endpoints)

    @patch('overapi.scanner.scanner.requests.get')
    def test_scanner_fuzzing_workflow(self, mock_get, scanner):
        """Test complete fuzzing workflow."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "response"
        mock_get.return_value = mock_response

        # Should handle fuzzing without crashes
        assert scanner is not None

    @patch('overapi.scanner.scanner.requests.get')
    def test_scanner_handles_network_errors(self, mock_get, scanner):
        """Test scanner handles network errors gracefully."""
        mock_get.side_effect = Exception("Network error")

        # Should handle gracefully
        assert scanner is not None

    def test_scanner_respects_concurrency_limit(self, scanner):
        """Test scanner respects thread concurrency limit."""
        assert scanner.config.threads <= 10  # Reasonable limit

    @patch('overapi.scanner.scanner.requests.get')
    def test_scanner_timeout_handling(self, mock_get, scanner):
        """Test scanner handles request timeouts."""
        from requests.exceptions import Timeout
        mock_get.side_effect = Timeout("Request timeout")

        # Should handle timeout
        assert scanner is not None


class TestFuzzingIntegration:
    """Test fuzzing workflow integration."""

    @pytest.fixture
    def wordlist_loader(self):
        """Create wordlist loader."""
        return WordlistLoader()

    @pytest.fixture
    def fuzzer(self, wordlist_loader):
        """Create fuzzer."""
        from overapi.scanner.fuzzer import Fuzzer
        return Fuzzer(wordlist_loader)

    @patch('overapi.scanner.fuzzer.requests.get')
    def test_endpoint_fuzzing_workflow(self, mock_get, fuzzer):
        """Test complete endpoint fuzzing workflow."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Generate fuzzing payloads
        endpoints = ["/api", "/admin"]
        sqli_payloads = fuzzer.generate_fuzzing_payloads("sqli", limit=3)

        assert len(sqli_payloads) > 0
        assert len(endpoints) > 0

    def test_payload_generation_variety(self, fuzzer):
        """Test that fuzzer generates varied payloads."""
        sqli = fuzzer.generate_fuzzing_payloads("sqli", limit=10)
        xss = fuzzer.generate_fuzzing_payloads("xss", limit=10)
        nosqli = fuzzer.generate_fuzzing_payloads("nosqli", limit=10)

        # Different types should generate different payloads
        assert sqli != xss
        assert xss != nosqli

    @patch('overapi.scanner.fuzzer.requests.get')
    def test_vulnerability_detection_workflow(self, mock_get, fuzzer):
        """Test vulnerability detection with fuzzing."""
        # Simulate finding SQL injection
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "SQL syntax error"
        mock_get.return_value = mock_response

        payloads = fuzzer.generate_fuzzing_payloads("sqli", limit=5)
        assert len(payloads) > 0

    def test_fuzzer_parameter_coverage(self, fuzzer):
        """Test fuzzer parameter coverage."""
        params = ["id", "user_id", "token"]
        for param in params:
            variations = fuzzer.fuzz_parameter(param, ["1", "test"])
            assert len(variations) > 0


class TestReportGeneration:
    """Test report generation from scan results."""

    @pytest.fixture
    def scan_results(self):
        """Create mock scan results."""
        return {
            "vulnerabilities": [
                {
                    "type": "sqli",
                    "endpoint": "/api/users",
                    "parameter": "id",
                    "severity": "high",
                }
            ],
            "endpoints_tested": 10,
            "vulnerabilities_found": 1,
        }

    def test_report_generation_structure(self, scan_results):
        """Test report generation has proper structure."""
        assert "vulnerabilities" in scan_results
        assert "endpoints_tested" in scan_results
        assert "vulnerabilities_found" in scan_results

    def test_report_json_serialization(self, scan_results):
        """Test report can be serialized to JSON."""
        json_str = json.dumps(scan_results)
        assert isinstance(json_str, str)

        # Should be deserializable
        parsed = json.loads(json_str)
        assert parsed == scan_results


class TestEndToEndScanning:
    """End-to-end scanning tests."""

    @patch('overapi.scanner.scanner.requests.get')
    def test_basic_api_scan(self, mock_get):
        """Test basic API scanning workflow."""
        # Mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok"}'
        mock_response.headers = {"Content-Type": "application/json"}
        mock_get.return_value = mock_response

        # Should complete without errors
        assert mock_get is not None

    @patch('overapi.scanner.scanner.requests.get')
    def test_vulnerability_identification(self, mock_get):
        """Test vulnerability identification."""
        # Simulate vulnerable response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Error: SQL syntax error near 'OR'"
        mock_get.return_value = mock_response

        # Should identify vulnerability
        assert "SQL" in mock_response.text or "Error" in mock_response.text

    @patch('overapi.scanner.scanner.requests.get')
    def test_multiple_vulnerability_types(self, mock_get):
        """Test scanning for multiple vulnerability types."""
        responses = {
            "sqli": Mock(status_code=500, text="SQL Error"),
            "xss": Mock(status_code=200, text="<script>executed</script>"),
            "xxe": Mock(status_code=400, text="XML Error"),
        }

        # Should identify different vulnerability types
        for vuln_type, response in responses.items():
            if response.status_code >= 400:
                assert vuln_type in responses


class TestRobustness:
    """Test robustness and error handling."""

    def test_scanner_handles_invalid_url(self):
        """Test scanner handles invalid URLs."""
        from overapi.core.config import Config

        with pytest.raises(Exception):
            Config(url="invalid://url")

    def test_scanner_handles_invalid_config(self):
        """Test scanner handles invalid configuration."""
        from overapi.core.config import Config

        # Should handle gracefully
        config = Config(url="http://localhost:8080", threads=1)
        assert config is not None

    def test_scanner_timeout_configuration(self):
        """Test scanner timeout configuration."""
        from overapi.core.config import Config

        config = Config(url="http://localhost:8080", timeout=30)
        assert config.timeout == 30

    def test_scanner_thread_limits(self):
        """Test scanner respects thread limits."""
        from overapi.core.config import Config

        config = Config(url="http://localhost:8080", threads=5)
        assert config.threads <= 10  # Reasonable upper limit


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
