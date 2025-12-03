
import pytest
from overapi.fuzzers.engine import FuzzingEngine
from overapi.core.context import ScanContext, Endpoint
from overapi.core.logger import Logger

class TestFuzzer:
    @pytest.fixture
    def context(self):
        return ScanContext(target="http://test.com", api_type="rest")

    @pytest.fixture
    def fuzzer(self, context):
        return FuzzingEngine(context, Logger())

    def test_mutations(self, fuzzer):
        mutations = list(fuzzer.generate_mutations("test"))
        assert len(mutations) > 0
        assert "t\x00st" not in mutations # Should have xor-ed

    def test_contextual_payloads_rest(self, fuzzer):
        endpoint = Endpoint("/api/test", "GET")
        payloads = fuzzer.get_contextual_payloads(endpoint)
        assert len(payloads) > 0
        assert any("Content-Type" in p for p in payloads)

    def test_contextual_payloads_graphql(self, fuzzer):
        fuzzer.context.api_type = "graphql"
        endpoint = Endpoint("/graphql", "POST")
        payloads = fuzzer.get_contextual_payloads(endpoint)
        assert any("query" in p for p in payloads)
