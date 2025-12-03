
import pytest
from overapi.bypass.engine import BypassEngine

class TestBypass:
    @pytest.fixture
    def bypass(self):
        return BypassEngine()

    def test_header_poisoning(self, bypass):
        req = {"method": "GET", "path": "/"}
        results = bypass.header_poisoning(req)
        assert len(results) > 0
        assert results[0]['headers']['X-Forwarded-For'] == "127.0.0.1"

    def test_verb_tampering(self, bypass):
        req = {"method": "GET", "path": "/"}
        results = bypass.verb_tampering(req)
        assert len(results) > 0
        assert any(r['method'] == "POST" for r in results)

    def test_auth_bypass(self, bypass):
        req = {"method": "GET", "path": "/", "headers": {"Authorization": "Bearer token"}}
        results = bypass.auth_bypass(req)
        assert len(results) >= 2
        # Check for removal
        assert any('Authorization' not in r['headers'] for r in results)
        # Check for empty
        assert any(r['headers'].get('Authorization') == "Bearer " for r in results)
