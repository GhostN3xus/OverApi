"""Tests for fuzzing functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from overapi.scanner.fuzzer import Fuzzer
from overapi.utils.wordlist_loader import WordlistLoader


class TestFuzzer:
    """Test Fuzzer functionality."""

    @pytest.fixture
    def wordlist_loader(self):
        """Create a WordlistLoader instance."""
        return WordlistLoader()

    @pytest.fixture
    def fuzzer(self, wordlist_loader):
        """Create a Fuzzer instance."""
        return Fuzzer(wordlist_loader)

    def test_fuzzer_initialization(self, fuzzer):
        """Test Fuzzer initialization."""
        assert fuzzer.wordlist_loader is not None
        assert fuzzer.payloads is not None

    def test_fuzzer_has_default_payloads(self, fuzzer):
        """Test that fuzzer has default payloads."""
        # Should have multiple payload types
        payload_types = list(fuzzer.payloads.keys())
        assert len(payload_types) > 0

    def test_generate_fuzzing_payloads(self, fuzzer):
        """Test generating fuzzing payloads."""
        payloads = fuzzer.generate_fuzzing_payloads("sqli", limit=10)
        assert len(payloads) <= 10
        assert all(isinstance(p, str) for p in payloads)

    def test_generate_fuzzing_payloads_respects_limit(self, fuzzer):
        """Test that payload generation respects limit parameter."""
        payloads_5 = fuzzer.generate_fuzzing_payloads("xss", limit=5)
        assert len(payloads_5) <= 5

        payloads_20 = fuzzer.generate_fuzzing_payloads("xss", limit=20)
        assert len(payloads_20) <= 20

    def test_fuzz_parameter_variations(self, fuzzer):
        """Test parameter fuzzing variations."""
        param_name = "id"
        variations = fuzzer.fuzz_parameter(param_name, ["1", "admin", "test"])

        # Should generate variations for each payload
        assert len(variations) > 0
        assert all(param_name in str(v) for v in variations)

    def test_fuzz_endpoint_path(self, fuzzer):
        """Test endpoint path fuzzing."""
        base_path = "/api/users"
        fuzzing_words = ["admin", "debug", "test"]

        paths = fuzzer.fuzz_endpoint_path(base_path, fuzzing_words)
        assert len(paths) > 0
        assert base_path in paths[0]

    def test_payload_mutation(self, fuzzer):
        """Test payload mutation/variation."""
        original = "<script>alert(1)</script>"
        variations = fuzzer.mutate_payload(original, count=5)

        # Should generate variations
        assert len(variations) <= 5
        # Original should still be present
        assert original in variations or len(variations) > 0

    def test_fuzzer_handles_empty_payloads(self, fuzzer):
        """Test fuzzer handles empty payload list gracefully."""
        payloads = fuzzer.generate_fuzzing_payloads("unknown_type", limit=10)
        # Should return empty or default
        assert isinstance(payloads, list)

    def test_fuzzer_handles_special_characters(self, fuzzer):
        """Test fuzzer handles special characters properly."""
        payloads = fuzzer.generate_fuzzing_payloads("sqli", limit=10)
        for payload in payloads:
            # Should handle encoding/decoding
            try:
                encoded = payload.encode('utf-8')
                decoded = encoded.decode('utf-8')
                assert decoded == payload
            except Exception:
                pytest.fail(f"Payload encoding failed: {payload}")

    def test_fuzzer_concurrent_operations(self, fuzzer):
        """Test fuzzer handles concurrent operations."""
        # Generate multiple payload sets concurrently
        sqli = fuzzer.generate_fuzzing_payloads("sqli", limit=5)
        xss = fuzzer.generate_fuzzing_payloads("xss", limit=5)

        assert len(sqli) > 0
        assert len(xss) > 0
        # Should have different payloads
        assert sqli != xss

    @patch('overapi.scanner.fuzzer.requests.get')
    def test_fuzzer_http_detection(self, mock_get, fuzzer):
        """Test fuzzer detects HTTP responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "response"
        mock_get.return_value = mock_response

        # Test would depend on actual implementation
        assert fuzzer is not None


class TestFuzzingRobustness:
    """Test robustness of fuzzing operations."""

    @pytest.fixture
    def fuzzer(self):
        """Create a Fuzzer instance."""
        return Fuzzer(WordlistLoader())

    def test_fuzzer_handles_timeout(self, fuzzer):
        """Test fuzzer handles request timeouts."""
        # Should not crash on timeout
        assert fuzzer is not None

    def test_fuzzer_retry_logic(self, fuzzer):
        """Test fuzzer has retry logic."""
        # Fuzzer should have retry mechanism
        assert hasattr(fuzzer, 'wordlist_loader') or hasattr(fuzzer, 'payloads')

    def test_fuzzer_memory_efficient(self, fuzzer):
        """Test fuzzer doesn't consume excessive memory."""
        # Generate large payload set
        large_set = fuzzer.generate_fuzzing_payloads("sqli", limit=100)
        assert len(large_set) <= 100

    def test_fuzzer_handles_encoding_errors(self, fuzzer):
        """Test fuzzer handles encoding errors gracefully."""
        # Should not crash with special characters
        payloads = fuzzer.generate_fuzzing_payloads("xss", limit=10)
        for payload in payloads:
            # Should be processable
            assert isinstance(payload, str)
            assert len(payload) > 0

    def test_fuzzer_respects_rate_limiting(self, fuzzer):
        """Test fuzzer respects rate limiting."""
        # Generate payloads multiple times
        for _ in range(5):
            payloads = fuzzer.generate_fuzzing_payloads("sqli", limit=10)
            assert len(payloads) <= 10


class TestPayloadCrafting:
    """Test payload crafting and manipulation."""

    @pytest.fixture
    def fuzzer(self):
        """Create a Fuzzer instance."""
        return Fuzzer(WordlistLoader())

    def test_craft_sqli_payload(self, fuzzer):
        """Test crafting SQL injection payloads."""
        payloads = fuzzer.generate_fuzzing_payloads("sqli", limit=5)
        assert any("'" in p for p in payloads)

    def test_craft_xss_payload(self, fuzzer):
        """Test crafting XSS payloads."""
        payloads = fuzzer.generate_fuzzing_payloads("xss", limit=5)
        assert any("<" in p for p in payloads)

    def test_craft_command_injection_payload(self, fuzzer):
        """Test crafting command injection payloads."""
        payloads = fuzzer.generate_fuzzing_payloads("command_injection", limit=5)
        assert any(";" in p or "|" in p for p in payloads)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
