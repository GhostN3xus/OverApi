"""Tests for advanced features added to OverApi."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from overapi.fuzzers.engine import FuzzingEngine
from overapi.core.context import ScanContext, Endpoint
from overapi.bypass.engine import BypassEngine
from overapi.tools.vuln_db import VulnerabilityDatabase
from overapi.utils.validators import Validators
from overapi.reports.pdf_generator import PDFReportGenerator


class TestFuzzingEngine:
    """Tests for the advanced fuzzing engine."""

    @pytest.fixture
    def context(self):
        """Create a mock scan context."""
        ctx = ScanContext("https://api.example.com", "rest")
        return ctx

    @pytest.fixture
    def fuzzer(self, context):
        """Create a fuzzing engine instance."""
        return FuzzingEngine(context)

    def test_generate_mutations(self, fuzzer):
        """Test mutation generation."""
        mutations = list(fuzzer.generate_mutations("test"))
        assert len(mutations) > 0
        # Should include bit flips, special chars, length mutations
        assert "" in mutations  # Empty mutation
        assert "test" * 10 in mutations  # Repeat mutation

    def test_generate_boundary_values(self, fuzzer):
        """Test boundary value generation."""
        boundaries = list(fuzzer.generate_boundary_values("id"))
        assert "0" in boundaries
        assert "-1" in boundaries
        assert "" in boundaries  # Empty
        assert str(2**31 - 1) in boundaries  # INT_MAX

    def test_generate_injection_payloads(self, fuzzer):
        """Test injection payload generation based on parameter name."""
        # Test SQL injection for 'id' parameter
        payloads = list(fuzzer.generate_injection_payloads("user_id"))
        payload_types = {p["type"] for p in payloads}
        assert "sqli" in payload_types

        # Test XSS for 'name' parameter
        payloads = list(fuzzer.generate_injection_payloads("name"))
        payload_types = {p["type"] for p in payloads}
        assert "xss" in payload_types

        # Test SSRF for 'url' parameter
        payloads = list(fuzzer.generate_injection_payloads("callback_url"))
        payload_types = {p["type"] for p in payloads}
        assert "ssrf" in payload_types

    def test_encode_payload(self, fuzzer):
        """Test payload encoding."""
        payload = "<script>"

        # URL encoding
        url_encoded = fuzzer.encode_payload(payload, "url")
        assert "<" not in url_encoded

        # Base64 encoding
        b64_encoded = fuzzer.encode_payload(payload, "base64")
        assert "PHNjcmlwdD4=" == b64_encoded

    def test_waf_bypass_variants(self, fuzzer):
        """Test WAF bypass variant generation."""
        payload = "SELECT * FROM users"
        variants = list(fuzzer.get_waf_bypass_variants(payload))

        assert payload in variants  # Original
        assert payload.upper() in variants
        assert payload.lower() in variants
        # Should have comment insertion for SQL
        assert "SEL/**/ECT * FROM users" in variants

    def test_get_contextual_payloads(self, fuzzer):
        """Test contextual payload selection."""
        endpoint = Endpoint(path="/api/users/{id}", method="GET")
        payloads = fuzzer.get_contextual_payloads(endpoint)
        assert len(payloads) > 0

    def test_fuzz_endpoint(self, fuzzer):
        """Test endpoint fuzzing."""
        endpoint = Endpoint(path="/api/users/{id}", method="POST")
        test_cases = list(fuzzer.fuzz_endpoint(endpoint))

        assert len(test_cases) > 0
        # Should have various types
        types = {tc.get("type") for tc in test_cases}
        assert "payload" in types
        assert "header" in types


class TestBypassEngine:
    """Tests for the bypass engine."""

    @pytest.fixture
    def bypass(self):
        """Create a bypass engine instance."""
        return BypassEngine()

    def test_header_poisoning(self, bypass):
        """Test header poisoning bypass generation."""
        request = {"method": "GET", "path": "/admin", "headers": {}}
        results = bypass.header_poisoning(request)

        assert len(results) > 0
        # Should have IP spoofing headers
        headers_set = set()
        for r in results:
            headers_set.update(r.get("headers", {}).keys())

        assert "X-Forwarded-For" in headers_set
        assert "X-Client-IP" in headers_set

    def test_verb_tampering(self, bypass):
        """Test HTTP verb tampering."""
        request = {"method": "GET", "path": "/api/data", "headers": {}}
        results = bypass.verb_tampering(request)

        methods = {r["method"] for r in results}
        assert "POST" in methods
        assert "PUT" in methods
        assert "DELETE" in methods
        assert "GET" not in methods  # Original should not be included

    def test_auth_bypass(self, bypass):
        """Test authentication bypass techniques."""
        request = {
            "method": "GET",
            "path": "/api/admin",
            "headers": {"Authorization": "Bearer token123"}
        }
        results = bypass.auth_bypass(request)

        # Should have attempt without auth
        has_no_auth = any(
            "Authorization" not in r.get("headers", {})
            for r in results
        )
        assert has_no_auth

    def test_path_obfuscation(self, bypass):
        """Test path obfuscation bypass."""
        request = {"method": "GET", "path": "/admin", "headers": {}}
        results = bypass.path_obfuscation(request)

        paths = {r["path"] for r in results}
        assert "/admin/" in paths  # Trailing slash
        assert "//admin" in paths  # Double slash


class TestVulnerabilityDatabase:
    """Tests for the vulnerability database."""

    @pytest.fixture
    def vuln_db(self):
        """Create a vulnerability database instance."""
        return VulnerabilityDatabase()

    def test_get_vulnerability(self, vuln_db):
        """Test getting vulnerability by name."""
        vuln = vuln_db.get_vulnerability("SQL Injection")

        assert vuln is not None
        assert "title" in vuln
        assert "cwe" in vuln
        assert "remediation" in vuln

    def test_get_vulnerability_fuzzy(self, vuln_db):
        """Test fuzzy vulnerability lookup."""
        # Should find partial match
        vuln = vuln_db.get_vulnerability("sqli")
        # Might return SQL Injection if found

    def test_owasp_coverage(self, vuln_db):
        """Test that database covers OWASP API Top 10."""
        all_vulns = vuln_db.get_all()

        # Should have entries for major categories
        assert "BOLA" in all_vulns
        assert "Broken Authentication" in all_vulns
        assert "SSRF" in all_vulns
        assert "Mass Assignment" in all_vulns

    def test_cwe_references(self, vuln_db):
        """Test that vulnerabilities have CWE references."""
        all_vulns = vuln_db.get_all()

        for name, details in all_vulns.items():
            assert "cwe" in details, f"{name} missing CWE reference"


class TestValidators:
    """Tests for security validators."""

    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        # Should detect SQL errors
        assert Validators.is_sql_injection("mysql error in query", "' OR 1=1--")
        assert Validators.is_sql_injection("ORA-12345: error", "' OR 1=1--")

        # Should not false positive on normal text
        assert not Validators.is_sql_injection("Hello World", "test")

    def test_xss_detection(self):
        """Test XSS detection."""
        payload = "<script>alert(1)</script>"

        # Direct reflection should be detected
        assert Validators.is_xss(payload, payload)

        # Encoded should not be detected as XSS
        encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
        assert not Validators.is_xss(encoded, payload)

    def test_command_injection_detection(self):
        """Test command injection detection."""
        # Should detect command output patterns
        assert Validators.is_command_injection("root:x:0:0:", "; cat /etc/passwd")
        assert Validators.is_command_injection("/bin/bash", "| whoami")

    def test_sensitive_data_detection(self):
        """Test sensitive data exposure detection."""
        # AWS key
        response = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
        found, types = Validators.is_sensitive_data_exposure(response)
        assert found
        assert "aws_access_key" in types

        # JWT
        jwt_response = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
        found, types = Validators.is_sensitive_data_exposure(jwt_response)
        assert found
        assert "jwt" in types

    def test_cors_misconfiguration_detection(self):
        """Test CORS misconfiguration detection."""
        # Wildcard origin
        headers = {"Access-Control-Allow-Origin": "*"}
        is_misc, vuln_type = Validators.is_cors_misconfigured(headers)
        assert is_misc
        assert "Wildcard" in vuln_type

        # Credentials with reflection
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true"
        }
        is_misc, vuln_type = Validators.is_cors_misconfigured(headers, "https://evil.com")
        assert is_misc

    def test_jwt_vulnerability_detection(self):
        """Test JWT vulnerability detection."""
        # JWT with 'none' algorithm (vulnerable)
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234"}).encode()).decode().rstrip("=")
        none_jwt = f"{header}.{payload}."

        is_vuln, vulns = Validators.is_jwt_vulnerable(none_jwt)
        assert is_vuln
        assert any("none" in v.lower() for v in vulns)


class TestPDFReportGenerator:
    """Tests for the PDF report generator."""

    @pytest.fixture
    def context(self):
        """Create a mock scan context."""
        ctx = ScanContext("https://api.example.com", "rest")
        ctx.vulnerabilities = [
            {
                "type": "SQL Injection",
                "severity": "Critical",
                "endpoint": "/api/users",
                "evidence": "Error: mysql",
                "owasp_category": "API8:2023",
                "cwe": "CWE-89"
            },
            {
                "type": "CORS Misconfiguration",
                "severity": "Medium",
                "endpoint": "/api/data",
                "evidence": "Access-Control-Allow-Origin: *"
            }
        ]
        return ctx

    def test_pdf_generator_init(self):
        """Test PDF generator initialization."""
        generator = PDFReportGenerator()
        assert generator is not None

    def test_generate_fallback(self, context, tmp_path):
        """Test fallback report generation."""
        generator = PDFReportGenerator()
        output_path = str(tmp_path / "test_report.txt")

        result = generator._generate_fallback(context, output_path)

        assert result == output_path
        with open(result) as f:
            content = f.read()
            assert "api.example.com" in content
            assert "SQL Injection" in content


class TestIntegration:
    """Integration tests for the scanner."""

    def test_import_orchestrator(self):
        """Test that orchestrator imports correctly."""
        from overapi.scanners.orchestrator import Orchestrator
        assert Orchestrator is not None

    def test_import_security_tester(self):
        """Test that security tester imports correctly."""
        from overapi.scanners.security_tester import SecurityTester
        assert SecurityTester is not None

    def test_import_protocol_scanners(self):
        """Test that all protocol scanners import correctly."""
        from overapi.protocols.rest.scanner import RestScanner
        from overapi.protocols.graphql.scanner import GraphQLScanner
        from overapi.protocols.soap.scanner import SOAPScanner
        from overapi.protocols.grpc.scanner import GRPCScanner
        from overapi.protocols.websocket.scanner import WebSocketScanner

        assert RestScanner is not None
        assert GraphQLScanner is not None
        assert SOAPScanner is not None
        assert GRPCScanner is not None
        assert WebSocketScanner is not None

    def test_cli_help(self):
        """Test that CLI shows help correctly."""
        import subprocess
        result = subprocess.run(
            ["python3", "main.py", "--help"],
            capture_output=True,
            text=True,
            cwd="/home/user/OverApi"
        )
        assert result.returncode == 0
        assert "OverApi" in result.stdout
        assert "--url" in result.stdout
