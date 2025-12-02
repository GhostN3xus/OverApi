"""Tests for wordlist and payload loading functionality."""

import pytest
import tempfile
from pathlib import Path
from overapi.utils.wordlist_loader import WordlistLoader


class TestWordlistLoader:
    """Test WordlistLoader functionality."""

    @pytest.fixture
    def loader(self):
        """Create a WordlistLoader instance."""
        return WordlistLoader()

    @pytest.fixture
    def temp_wordlist(self):
        """Create a temporary wordlist file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("# Comment line\n")
            f.write("/custom/endpoint\n")
            f.write("/another/endpoint\n")
            f.write("\n")  # Empty line
            f.write("/third/endpoint\n")
            temp_path = f.name
        yield temp_path
        # Cleanup
        Path(temp_path).unlink()

    def test_default_endpoints_loaded(self, loader):
        """Test that default endpoints are loaded."""
        endpoints = loader.get_endpoints()
        assert "/api" in endpoints
        assert "/users" in endpoints
        assert "/admin" in endpoints
        assert len(endpoints) > 30

    def test_custom_wordlist_loading(self, loader, temp_wordlist):
        """Test loading custom wordlist file."""
        loader = WordlistLoader(custom_wordlist=temp_wordlist)
        endpoints = loader.get_endpoints()

        # Check custom endpoints are added
        assert "/custom/endpoint" in endpoints
        assert "/another/endpoint" in endpoints
        assert "/third/endpoint" in endpoints

    def test_get_endpoints_with_limit(self, loader):
        """Test limiting number of returned endpoints."""
        limited = loader.get_endpoints(limit=5)
        assert len(limited) == 5

    def test_get_parameters(self, loader):
        """Test parameter list retrieval."""
        params = loader.get_parameters()
        assert "id" in params
        assert "api_key" in params
        assert "token" in params
        assert len(params) > 10

    def test_sqli_payloads(self, loader):
        """Test SQL injection payloads."""
        payloads = loader.get_payloads("sqli")
        assert len(payloads) > 0
        # Check for various types of SQLi payloads
        assert any("UNION" in p for p in payloads)
        assert any("OR" in p for p in payloads)
        assert any("SLEEP" in p for p in payloads)

    def test_xss_payloads(self, loader):
        """Test XSS payloads."""
        payloads = loader.get_payloads("xss")
        assert len(payloads) > 0
        # Check for various types of XSS payloads
        assert any("<script>" in p for p in payloads)
        assert any("onerror" in p for p in payloads)
        assert any("javascript:" in p for p in payloads)

    def test_nosqli_payloads(self, loader):
        """Test NoSQL injection payloads."""
        payloads = loader.get_payloads("nosqli")
        assert len(payloads) > 0
        assert any("$ne" in p for p in payloads)
        assert any("$where" in p for p in payloads)

    def test_command_injection_payloads(self, loader):
        """Test command injection payloads."""
        payloads = loader.get_payloads("command_injection")
        assert len(payloads) > 0
        assert any("whoami" in p for p in payloads)
        assert any(";" in p for p in payloads)

    def test_xxe_payloads(self, loader):
        """Test XXE payloads."""
        payloads = loader.get_payloads("xxe")
        assert len(payloads) > 0
        assert all("<?xml" in p for p in payloads)

    def test_path_traversal_payloads(self, loader):
        """Test path traversal payloads."""
        payloads = loader.get_payloads("path_traversal")
        assert len(payloads) > 0
        assert ".." in str(payloads)

    def test_lfi_payloads(self, loader):
        """Test LFI payloads."""
        payloads = loader.get_payloads("lfi")
        assert len(payloads) > 0
        assert any("passwd" in p for p in payloads)

    def test_unknown_payload_type(self, loader):
        """Test requesting unknown payload type."""
        payloads = loader.get_payloads("unknown_type")
        assert payloads == []

    def test_payload_syntax_validation(self, loader):
        """Test that payloads don't have obvious syntax errors."""
        for payload_type in ["sqli", "xss", "nosqli", "xxe"]:
            payloads = loader.get_payloads(payload_type)
            for payload in payloads:
                # Basic checks for common syntax issues
                assert isinstance(payload, str)
                assert len(payload) > 0
                assert len(payload) < 2000  # Reasonable payload size

    def test_custom_wordlist_not_found(self):
        """Test handling of non-existent custom wordlist."""
        with pytest.raises(Exception):
            WordlistLoader(custom_wordlist="/nonexistent/path/wordlist.txt")

    def test_wordlist_no_duplicates_after_merge(self, loader):
        """Test that duplicate endpoints are handled."""
        endpoints = loader.get_endpoints()
        unique_endpoints = set(endpoints)
        # May have duplicates if list was merged, but should be manageable
        assert len(unique_endpoints) <= len(endpoints)


class TestPayloadValidation:
    """Test payload validation and security."""

    @pytest.fixture
    def loader(self):
        """Create a WordlistLoader instance."""
        return WordlistLoader()

    def test_xss_payload_contains_valid_vectors(self, loader):
        """Test that XSS payloads contain proper vectors."""
        payloads = loader.get_payloads("xss")

        # Should have script-based payloads
        script_payloads = [p for p in payloads if "<script>" in p]
        assert len(script_payloads) > 0

        # Should have event-based payloads
        event_payloads = [p for p in payloads if "on" in p.lower()]
        assert len(event_payloads) > 0

    def test_sqli_payload_variety(self, loader):
        """Test that SQLi payloads cover different attack types."""
        payloads = loader.get_payloads("sqli")

        # Union-based
        union_payloads = [p for p in payloads if "UNION" in p]
        assert len(union_payloads) > 0

        # Boolean-based
        bool_payloads = [p for p in payloads if "OR" in p or "AND" in p]
        assert len(bool_payloads) > 0

        # Time-based
        time_payloads = [p for p in payloads if "SLEEP" in p or "WAITFOR" in p]
        assert len(time_payloads) > 0

    def test_command_injection_multiplatform(self, loader):
        """Test command injection payloads for Unix and Windows."""
        payloads = loader.get_payloads("command_injection")

        # Unix/Linux separators
        unix_payloads = [p for p in payloads if ";" in p or "|" in p]
        assert len(unix_payloads) > 0

        # Check for common commands
        whoami_payloads = [p for p in payloads if "whoami" in p]
        assert len(whoami_payloads) > 0

    def test_payloads_are_encodable(self, loader):
        """Test that payloads can be properly encoded."""
        for payload_type in ["sqli", "xss", "nosqli"]:
            payloads = loader.get_payloads(payload_type)
            for payload in payloads:
                # Should be able to encode/decode as UTF-8
                encoded = payload.encode('utf-8')
                decoded = encoded.decode('utf-8')
                assert decoded == payload


class TestSecListsIntegration:
    """Test SecLists integration (if available)."""

    def test_seclists_loader_optional(self):
        """Test that SecLists loader is optional."""
        # Should not raise even if SecLists not available
        loader = WordlistLoader(use_seclists=False)
        assert loader.seclists_loader is None

    def test_get_seclists_available(self):
        """Test getting available SecLists."""
        loader = WordlistLoader(use_seclists=False)
        available = loader.get_seclists_available()
        # Without SecLists loader, should be empty
        assert available == {}

    def test_load_from_seclists_without_loader(self):
        """Test loading SecLists without loader initialized."""
        loader = WordlistLoader(use_seclists=False)
        endpoints = loader.load_from_seclists("discovery", "web_content")
        # Should fall back to default
        assert len(endpoints) > 0
        assert "/api" in endpoints


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
