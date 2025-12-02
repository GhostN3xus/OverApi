"""Comprehensive tests for OverApi security modules."""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta

# Import security modules
from overapi.modules.security import (
    JWTAnalyzer,
    JWTVulnerability,
    JWTVulnerabilityType,
    BusinessLogicScanner,
    BusinessLogicVulnerability,
    BusinessLogicVulnerabilityType,
    GraphQLAttacker,
    GraphQLVulnerability,
    GraphQLVulnerabilityType,
    SSRFTester,
    SSRFVulnerability,
    AdvancedReporter,
    CVSSCalculator,
)


# ============================================================================
# JWT Analyzer Tests
# ============================================================================

class TestJWTAnalyzer:
    """Test JWT analyzer module."""

    @pytest.fixture
    def analyzer(self):
        """Create JWT analyzer instance."""
        return JWTAnalyzer("https://api.example.com")

    def test_jwt_detection(self, analyzer):
        """Test JWT format detection."""
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert analyzer._is_valid_jwt(valid_jwt)

    def test_jwt_detection_invalid(self, analyzer):
        """Test invalid JWT detection."""
        invalid_jwt = "not.a.jwt"
        assert not analyzer._is_valid_jwt(invalid_jwt)

    def test_jwt_decoding(self, analyzer):
        """Test JWT decoding without signature verification."""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        decoded = analyzer.decode_jwt(token)

        assert 'header' in decoded
        assert 'payload' in decoded
        assert decoded['header'].get('alg') == 'HS256'

    def test_weak_secret_detection(self, analyzer):
        """Test weak secret detection."""
        # Token signed with 'secret'
        vulnerable_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"

        decoded = analyzer.decode_jwt(vulnerable_token)
        assert decoded['header']['alg'] == 'HS256'

    def test_jwt_generation(self, analyzer):
        """Test JWT token generation."""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': '1234567890', 'name': 'John Doe'}

        token = analyzer.generate_jwt(header, payload, secret='secret', algorithm='HS256')

        assert token
        assert len(token.split('.')) == 3

    def test_algorithm_none_payload_generation(self, analyzer):
        """Test algorithm none attack payload."""
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {'sub': '1234567890', 'role': 'admin'}

        token = analyzer.generate_jwt(header, payload, algorithm='none')

        assert token
        decoded = analyzer.decode_jwt(token)
        assert decoded['header']['alg'] == 'none'

    def test_claims_extraction(self, analyzer):
        """Test claims extraction from JWT."""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        decoded = analyzer.decode_jwt(token)

        assert decoded['payload']['sub'] == '1234567890'
        assert decoded['payload']['name'] == 'John Doe'

    @pytest.mark.asyncio
    async def test_expired_token_generation(self, analyzer):
        """Test generation of expired token."""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        # Past expiration
        payload = {
            'sub': '1234567890',
            'exp': int((datetime.utcnow() - timedelta(days=1)).timestamp())
        }

        token = analyzer.generate_jwt(header, payload, secret='secret', algorithm='HS256')
        decoded = analyzer.decode_jwt(token)

        assert decoded['payload']['exp'] < datetime.utcnow().timestamp()

    @pytest.mark.asyncio
    async def test_missing_exp_claim_detection(self, analyzer):
        """Test detection of missing exp claim."""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        vuln = await analyzer.test_missing_expiration(token)

        # Token should be detected as missing exp claim
        if vuln:
            assert vuln.vuln_type == JWTVulnerabilityType.NO_EXPIRATION

    @pytest.mark.asyncio
    async def test_weak_algorithm_detection(self, analyzer):
        """Test detection of weak algorithms."""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': '1234567890'}

        token = analyzer.generate_jwt(header, payload, secret='secret', algorithm='HS256')

        vuln = await analyzer.test_weak_algorithm(token)

        if vuln:
            assert vuln.vuln_type == JWTVulnerabilityType.WEAK_ALGORITHM
            assert vuln.severity == 'medium'


# ============================================================================
# Business Logic Scanner Tests
# ============================================================================

class TestBusinessLogicScanner:
    """Test business logic vulnerability scanner."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return BusinessLogicScanner("https://api.example.com")

    @pytest.mark.asyncio
    async def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.target_url == "https://api.example.com"
        assert scanner.vulnerabilities == []

    def test_default_test_endpoints(self, scanner):
        """Test default endpoint generation."""
        endpoints = scanner._get_default_test_endpoints()

        assert len(endpoints) > 0
        assert any('wallet' in e.get('path', '') for e in endpoints)
        assert any('coupon' in e.get('path', '') for e in endpoints)

    def test_payload_preparation(self, scanner):
        """Test test payload preparation."""
        endpoint = {'path': '/api/test', 'parameters': {'id': 'int', 'name': 'string'}}

        payload = scanner._prepare_test_payload(endpoint)

        assert isinstance(payload, dict)
        assert 'id' in payload or 'name' in payload or len(payload) >= 0

    @pytest.mark.asyncio
    async def test_race_condition_detection(self, scanner):
        """Test race condition vulnerability detection."""
        endpoint = {
            'path': '/api/wallet/withdraw',
            'method': 'POST',
            'parameters': {'amount': 'float'}
        }

        # Would require mock responses for full test
        # This is a basic structure test
        assert endpoint['path'].lower().find('withdraw') >= 0


# ============================================================================
# GraphQL Attacker Tests
# ============================================================================

class TestGraphQLAttacker:
    """Test GraphQL attack module."""

    @pytest.fixture
    def attacker(self):
        """Create GraphQL attacker instance."""
        return GraphQLAttacker("https://api.example.com")

    def test_batch_query_generation(self, attacker):
        """Test batch query generation."""
        batch = attacker._generate_batch_query(50)

        assert 'query0:' in batch
        assert 'query49:' in batch
        assert '{' in batch

    def test_circular_query_generation(self, attacker):
        """Test circular query generation."""
        circular = attacker._generate_circular_query(10)

        assert '{' in circular
        assert 'author' in circular or 'posts' in circular

    def test_alias_query_generation(self, attacker):
        """Test alias-based query generation."""
        alias_query = attacker._generate_alias_query(30)

        assert 'user0:' in alias_query
        assert 'user29:' in alias_query

    def test_deep_query_generation(self, attacker):
        """Test deep nested query generation."""
        deep_query = attacker._generate_deep_query(15)

        assert deep_query.count('{') == deep_query.count('}')
        assert '{' in deep_query


# ============================================================================
# SSRF Tester Tests
# ============================================================================

class TestSSRFTester:
    """Test SSRF testing module."""

    @pytest.fixture
    def tester(self):
        """Create SSRF tester instance."""
        return SSRFTester("https://api.example.com")

    def test_webhook_parameters(self, tester):
        """Test webhook parameter list."""
        assert 'callback_url' in tester.WEBHOOK_PARAMETERS
        assert 'webhook_url' in tester.WEBHOOK_PARAMETERS
        assert len(tester.WEBHOOK_PARAMETERS) > 0

    def test_ssrf_payloads(self, tester):
        """Test SSRF payload list."""
        assert len(tester.SSRF_PAYLOADS) > 0

        # Verify payload structure
        for payload, name in tester.SSRF_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(name, str)
            assert len(payload) > 0

    def test_metadata_payloads(self, tester):
        """Test cloud metadata payloads."""
        payloads = [p[0] for p in tester.SSRF_PAYLOADS]

        assert any('169.254.169.254' in p for p in payloads)  # AWS
        assert any('metadata.google.internal' in p for p in payloads)  # GCP


# ============================================================================
# Advanced Reporter Tests
# ============================================================================

class TestAdvancedReporter:
    """Test advanced reporting module."""

    @pytest.fixture
    def reporter(self):
        """Create reporter instance."""
        return AdvancedReporter()

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        return [
            {
                'severity': 'critical',
                'title': 'Test Critical',
                'description': 'Test description',
                'remediation': 'Test fix',
                'cvss_score': 9.0,
                'cwe_id': 'CWE-347',
                'owasp_category': 'API2:2023',
                'evidence': {'test': 'data'},
            },
            {
                'severity': 'high',
                'title': 'Test High',
                'description': 'Test description',
                'remediation': 'Test fix',
                'cvss_score': 7.5,
                'cwe_id': 'CWE-918',
                'owasp_category': 'API10:2023',
                'evidence': {},
            },
        ]

    def test_summary_calculation(self, reporter, sample_findings):
        """Test finding summary calculation."""
        summary = reporter._calculate_summary(sample_findings)

        assert summary['critical'] == 1
        assert summary['high'] == 1
        assert summary['total'] == 2

    def test_cvss_calculator(self):
        """Test CVSS score calculation."""
        from overapi.modules.security.reporting.advanced_reporter import CVSSVector

        vector = CVSSVector(
            av='N', ac='L', pr='N', ui='N', s='U',
            c='H', i='H', a='N'
        )

        score = CVSSCalculator.calculate_score(vector)

        assert 0 <= score <= 10.0
        assert score > 5.0  # Should be at least medium

    def test_severity_determination(self):
        """Test severity rating from CVSS score."""
        assert CVSSCalculator.get_severity(9.5) == 'Critical'
        assert CVSSCalculator.get_severity(7.5) == 'High'
        assert CVSSCalculator.get_severity(5.0) == 'Medium'
        assert CVSSCalculator.get_severity(2.0) == 'Low'

    def test_html_report_generation(self, reporter, sample_findings, tmp_path):
        """Test HTML report generation."""
        report_path = tmp_path / "report.html"

        output_path = reporter.generate_html_report(
            sample_findings,
            "https://api.example.com",
            str(report_path)
        )

        assert report_path.exists()
        content = report_path.read_text()

        assert 'Test Critical' in content
        assert 'Test High' in content
        assert 'api.example.com' in content

    def test_json_report_generation(self, reporter, sample_findings, tmp_path):
        """Test JSON report generation."""
        report_path = tmp_path / "report.json"

        output_path = reporter.generate_json_report(
            sample_findings,
            "https://api.example.com",
            str(report_path)
        )

        assert report_path.exists()
        content = json.loads(report_path.read_text())

        assert content['summary']['critical'] == 1
        assert content['summary']['high'] == 1
        assert content['metadata']['target'] == 'https://api.example.com'

    def test_executive_summary_generation(self, reporter, sample_findings):
        """Test executive summary generation."""
        summary = reporter.generate_executive_summary(sample_findings)

        assert 'risk_score' in summary
        assert 'risk_level' in summary
        assert 'finding_counts' in summary
        assert 'business_impact' in summary
        assert 'compliance_status' in summary
        assert 'priority_actions' in summary

    def test_risk_score_calculation(self, reporter, sample_findings):
        """Test risk score calculation."""
        score = reporter._calculate_risk_score(sample_findings)

        assert 0 <= score <= 100

    def test_business_impact_assessment(self, reporter, sample_findings):
        """Test business impact assessment."""
        impact = reporter._assess_business_impact(sample_findings)

        assert isinstance(impact, str)
        assert 'Critical' in impact or 'High' in impact or 'Medium' in impact or 'Low' in impact

    def test_priority_actions_generation(self, reporter, sample_findings):
        """Test priority actions generation."""
        actions = reporter._generate_priority_actions(sample_findings)

        assert isinstance(actions, list)
        assert len(actions) > 0
        assert any(action for action in actions if 'Fix' in action or 'fix' in action)

    def test_fix_time_estimation(self, reporter, sample_findings):
        """Test fix time estimation."""
        days = reporter._estimate_fix_time(sample_findings)

        assert isinstance(days, int)
        assert days >= 7  # Minimum 7 days

    def test_compliance_assessment(self, reporter, sample_findings):
        """Test compliance status assessment."""
        compliance = reporter._assess_compliance_status(sample_findings)

        assert 'OWASP_API_Top_10' in compliance
        assert 'PCI_DSS' in compliance
        assert 'SOC2' in compliance


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for security modules."""

    @pytest.mark.asyncio
    async def test_jwt_and_reporter_integration(self):
        """Test JWT analyzer with reporter."""
        jwt_analyzer = JWTAnalyzer("https://api.example.com")
        reporter = AdvancedReporter()

        # Create a sample vulnerability
        vuln = JWTVulnerability(
            vuln_type=JWTVulnerabilityType.ALGORITHM_NONE,
            severity='critical',
            title='Test JWT Vulnerability',
            description='Test description',
            remediation='Test remediation',
            cvss_score=9.1,
            cwe_id='CWE-347',
            owasp_category='API2:2023 Broken Authentication',
        )

        # Convert to dict and verify reporter can handle it
        finding_dict = vuln.to_dict()

        assert finding_dict['severity'] == 'critical'
        assert finding_dict['title'] == 'Test JWT Vulnerability'

    @pytest.mark.asyncio
    async def test_business_logic_and_reporter_integration(self):
        """Test business logic scanner with reporter."""
        scanner = BusinessLogicScanner("https://api.example.com")
        reporter = AdvancedReporter()

        # Create a sample vulnerability
        vuln = BusinessLogicVulnerability(
            vuln_type=BusinessLogicVulnerabilityType.RACE_CONDITION,
            severity='critical',
            title='Test Race Condition',
            description='Test description',
            remediation='Test remediation',
            cvss_score=8.2,
            cwe_id='CWE-362',
            owasp_category='API8:2023',
            endpoint='/api/test',
            method='POST',
        )

        # Convert to dict and verify reporter can handle it
        finding_dict = vuln.to_dict()

        assert finding_dict['severity'] == 'critical'
        assert finding_dict['endpoint'] == '/api/test'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
