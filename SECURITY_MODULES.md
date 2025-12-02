# OverApi Security Modules Documentation

## Overview

This document describes the advanced security testing modules integrated into OverApi. These professional-grade modules enable comprehensive offensive security testing of modern APIs across multiple attack vectors.

## Table of Contents

1. [JWT Advanced Testing Engine](#jwt-advanced-testing-engine)
2. [Business Logic Vulnerability Scanner](#business-logic-vulnerability-scanner)
3. [GraphQL Advanced Attack Module](#graphql-advanced-attack-module)
4. [SSRF & Callback Testing](#ssrf--callback-testing)
5. [Comprehensive Reporting Engine](#comprehensive-reporting-engine)
6. [Usage Examples](#usage-examples)
7. [Configuration](#configuration)

---

## JWT Advanced Testing Engine

### Overview

The JWT Analyzer module detects and exploits all known JWT vulnerabilities, from basic signature bypass to sophisticated algorithm confusion attacks.

### Module Location

```
overapi/modules/security/auth/jwt_analyzer.py
```

### Capabilities

#### 1. JWT Detection & Extraction
- Extracts JWT tokens from multiple locations:
  - HTTP Authorization headers (`Bearer` scheme)
  - HTTP Cookies
  - JSON response body (common field names)
  - Custom headers

#### 2. Algorithm Confusion Attacks (CVE-2015-9235)
- Detects `alg: none` vulnerability
- Tests RS256 → HS256 confusion
- Validates improper algorithm handling

#### 3. Weak Secret Bruteforce
- Dictionary attack against weak secrets
- Pre-configured list of 20+ common weak secrets
- Automated detection of vulnerable tokens

#### 4. Header Manipulation
- **kid (Key ID) injection**: SQL injection, path traversal, command injection
- **jku/x5u injection**: SSRF via JSON Web Key Set URL manipulation
- Tests arbitrary header injection points

#### 5. Claims Manipulation
- Modifies token claims without signature validation
- Tests for missing claim validation
- Attempts privilege escalation via claims

#### 6. Token Analysis
- Detects missing expiration claims
- Identifies weak algorithms (HS256 vs RS256)
- Analyzes token structure and content

### Example Usage

```python
from overapi.modules.security import JWTAnalyzer

analyzer = JWTAnalyzer(
    target_url="https://api.vulnerable.com",
    headers={"Authorization": "Bearer initial_token"}
)

# Run comprehensive analysis
results = asyncio.run(analyzer.analyze([
    {'path': '/api/user/profile', 'method': 'GET'},
    {'path': '/api/auth/login', 'method': 'POST'},
]))

# Results contain detailed vulnerability information
for vuln in analyzer.vulnerabilities:
    print(f"{vuln.title}: {vuln.severity}")
    print(f"CVSS: {vuln.cvss_score}")
    print(f"Evidence: {vuln.evidence}")
```

### Vulnerability Types Detected

| Type | Severity | CVSS | CWE |
|------|----------|------|-----|
| Algorithm None Attack | Critical | 9.1 | CWE-347 |
| Algorithm Confusion | Critical | 9.1 | CWE-347 |
| Weak Secret | Critical | 9.0 | CWE-521 |
| Header Injection | High | 7.5 | CWE-89/22/78 |
| Missing Expiration | Medium | 6.5 | CWE-613 |
| Weak Algorithm | Medium | 5.3 | CWE-327 |

---

## Business Logic Vulnerability Scanner

### Overview

Detects vulnerabilities in business logic that traditional testing misses, including race conditions, price manipulation, and workflow bypass attacks.

### Module Location

```
overapi/modules/security/business_logic/bl_scanner.py
```

### Capabilities

#### 1. Race Condition Testing
- Parallel request execution (configurable count)
- Detects concurrent access issues:
  - Duplicate voucher redemption
  - Balance over-withdrawal
  - Inventory over-selling
  - Duplicate transactions

#### 2. Mass Assignment Detection
- Tests authorization of sensitive fields
- Detects ability to set restricted parameters:
  - User roles and permissions
  - Account balances and credits
  - Verification status

#### 3. Price/Amount Manipulation
- Tests various numeric edge cases:
  - Negative prices
  - Zero amounts
  - Decimal precision issues
  - Integer overflow/underflow

#### 4. Workflow Bypass
- Tests multi-step process enforcement
- Attempts to skip required steps
- Validates state machine enforcement

#### 5. Rate Limit Evasion
- Tests bypass techniques:
  - X-Forwarded-For header spoofing
  - X-Real-IP manipulation
  - Null byte injection
  - URL encoding variations

#### 6. Integer Overflow Testing
- Tests extreme numeric values
- Detects overflow/underflow handling
- Validates numeric field validation

### Example Usage

```python
from overapi.modules.security import BusinessLogicScanner

scanner = BusinessLogicScanner(
    target_url="https://api.vulnerable.com",
    config={
        'race_conditions': {
            'parallel_requests': 100,
            'timeout_ms': 5000
        }
    }
)

# Run scan
vulnerabilities = asyncio.run(scanner.scan([
    {'path': '/api/wallet/withdraw', 'method': 'POST'},
    {'path': '/api/coupon/redeem', 'method': 'POST'},
]))

for vuln in vulnerabilities:
    print(f"Type: {vuln.vuln_type.value}")
    print(f"Impact: {vuln.impact}")
```

### Vulnerability Types Detected

| Type | Severity | CVSS | Impact |
|------|----------|------|--------|
| Race Condition | Critical | 8.2 | Business logic bypass, financial loss |
| Mass Assignment | High | 7.5 | Privilege escalation, data manipulation |
| Price Manipulation | Critical | 9.0 | Financial fraud, free services |
| Workflow Bypass | Critical | 8.5 | Unauthorized transactions |
| Rate Limit Evasion | High | 6.5 | Brute force, DoS |

---

## GraphQL Advanced Attack Module

### Overview

Comprehensive testing of GraphQL endpoints for common vulnerabilities and attack patterns.

### Module Location

```
overapi/modules/security/injection/graphql_attacker.py
```

### Capabilities

#### 1. Introspection Analysis
- Extracts full GraphQL schema if introspection enabled
- Maps all queries, mutations, subscriptions
- Identifies exposed directives and types

#### 2. Batch Query DoS
- Generates queries with 100+ aliases
- Tests resource exhaustion
- Measures response times

#### 3. Circular Query Testing
- Creates deeply nested queries (up to 20 levels)
- Tests depth limiting enforcement
- Detects exponential complexity growth

#### 4. Field Suggestion Analysis
- Exploits error messages for schema discovery
- Tests "did you mean" functionality
- Infers available fields from error responses

#### 5. Directive Abuse
- Tests @skip and @include misuse
- Attempts field-level authorization bypass
- Validates directive parameter validation

#### 6. Alias-based DoS
- Multiple aliases on single query
- Tests query duplication for resource exhaustion
- Measures complexity scoring

### Example Usage

```python
from overapi.modules.security import GraphQLAttacker

attacker = GraphQLAttacker(
    target_url="https://api.vulnerable.com",
    graphql_endpoint="/graphql"
)

# Run analysis
results = asyncio.run(attacker.analyze())

print(f"Introspection enabled: {results['schema'] is not None}")
print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")

for vuln in results['vulnerabilities']:
    print(f"- {vuln['title']}: {vuln['severity']}")
```

### Vulnerability Types Detected

| Type | Severity | CVSS | Impact |
|------|----------|------|--------|
| Introspection Enabled | High | 7.5 | Schema disclosure |
| Batch Query DoS | High | 7.5 | Resource exhaustion, DoS |
| Circular Query DoS | High | 7.5 | Resource exhaustion |
| Alias DoS | High | 7.5 | Resource exhaustion |
| No Depth Limit | Medium | 6.5 | Query complexity issues |

---

## SSRF & Callback Testing

### Overview

Detects Server-Side Request Forgery vulnerabilities that allow accessing internal resources.

### Module Location

```
overapi/modules/security/injection/ssrf_tester.py
```

### Capabilities

#### 1. Webhook URL Injection
- Tests webhook parameters for SSRF
- Common parameters tested:
  - `callback_url`, `webhook_url`
  - `redirect_uri`, `import_url`
  - `image_url`, `avatar_url`

#### 2. Cloud Metadata Access
- AWS EC2 metadata endpoint (169.254.169.254)
- GCP metadata endpoint
- Azure metadata endpoint
- Credential exposure detection

#### 3. Internal Service Probing
- Database servers (MySQL, PostgreSQL, MongoDB)
- Cache servers (Redis, Memcached)
- Search engines (Elasticsearch)
- Admin interfaces (Tomcat, Spring Actuator)

#### 4. Blind SSRF Detection
- Out-of-band callback detection
- Collaborator integration support
- DNS/HTTP request monitoring

#### 5. Internal Port Scanning
- Timing-based port detection
- Open port identification
- Service fingerprinting

#### 6. Protocol Smuggling
- Dict protocol for Memcached
- Gopher protocol for Redis
- File protocol for local file access

### Example Usage

```python
from overapi.modules.security import SSRFTester

tester = SSRFTester(
    target_url="https://api.vulnerable.com",
    collaborator_url="attacker-collaborator.burp.sh"
)

# Run SSRF tests
vulnerabilities = asyncio.run(tester.test([
    {'path': '/api/webhook/create', 'method': 'POST'},
    {'path': '/api/import', 'method': 'POST'},
]))

for vuln in vulnerabilities:
    print(f"{vuln.title}")
    print(f"Parameter: {vuln.parameter}")
    print(f"Evidence: {vuln.evidence}")
```

### Vulnerability Types Detected

| Type | Severity | CVSS | Impact |
|------|----------|------|--------|
| Webhook Injection | Critical | 8.6 | Metadata access, internal service compromise |
| Blind SSRF | High | 7.5 | Internal network probing |
| Internal Port Scan | High | 7.5 | Service discovery, port enumeration |

---

## Comprehensive Reporting Engine

### Overview

Professional-grade reporting with HTML, JSON, and executive summaries.

### Module Location

```
overapi/modules/security/reporting/advanced_reporter.py
```

### Capabilities

#### 1. HTML Interactive Reports
- Professional styling and layout
- Collapsible vulnerability sections
- CVSS score visualization
- Compliance framework mapping
- Mobile-responsive design

#### 2. JSON Reports
- Machine-readable findings
- Full evidence details
- Metadata and timestamps
- Easy integration with other tools

#### 3. Executive Summaries
- Risk score calculation (0-100)
- Business impact assessment
- Compliance status (OWASP, PCI-DSS, SOC2)
- Priority action recommendations
- Estimated remediation time

#### 4. CVSS 3.1 Calculation
- Automated score calculation
- Severity rating assignment
- Vector string generation

#### 5. Compliance Mapping
- OWASP API Top 10 2023
- PCI DSS requirements
- NIST SP 800-53 controls
- ISO 27001 mappings
- SOC2 trust service criteria

### Example Usage

```python
from overapi.modules.security.reporting import AdvancedReporter

reporter = AdvancedReporter()

# Generate HTML report
reporter.generate_html_report(
    findings=vulnerabilities,
    target_url="https://api.vulnerable.com",
    output_path="./reports/security_report.html"
)

# Generate JSON report
reporter.generate_json_report(
    findings=vulnerabilities,
    target_url="https://api.vulnerable.com",
    output_path="./reports/security_report.json"
)

# Generate executive summary
summary = reporter.generate_executive_summary(vulnerabilities)
print(f"Risk Score: {summary['risk_score']}")
print(f"Business Impact: {summary['business_impact']}")
print(f"Priority Actions: {summary['priority_actions']}")
```

### Report Components

1. **Summary Cards**: Critical/High/Medium/Low counts
2. **Executive Summary**: Risk assessment and recommendations
3. **Detailed Findings**:
   - Description and evidence
   - Remediation steps
   - CVSS scoring
   - Compliance mappings
4. **Compliance Analysis**: Framework-specific recommendations

---

## Usage Examples

### Example 1: Complete API Security Scan

```python
import asyncio
from overapi.modules.security import (
    JWTAnalyzer,
    BusinessLogicScanner,
    GraphQLAttacker,
    SSRFTester,
    AdvancedReporter,
)

async def comprehensive_scan(target_url: str):
    """Run complete security assessment."""

    all_findings = []

    # 1. JWT Analysis
    jwt_analyzer = JWTAnalyzer(target_url)
    jwt_results = await jwt_analyzer.analyze()
    all_findings.extend([v.to_dict() for v in jwt_analyzer.vulnerabilities])

    # 2. Business Logic Testing
    bl_scanner = BusinessLogicScanner(target_url)
    bl_vulns = await bl_scanner.scan()
    all_findings.extend([v.to_dict() for v in bl_vulns])

    # 3. GraphQL Testing
    graphql_attacker = GraphQLAttacker(target_url)
    graphql_results = await graphql_attacker.analyze()
    all_findings.extend(graphql_results['vulnerabilities'])

    # 4. SSRF Testing
    ssrf_tester = SSRFTester(target_url)
    ssrf_vulns = await ssrf_tester.test()
    all_findings.extend([v.to_dict() for v in ssrf_vulns])

    # 5. Generate Reports
    reporter = AdvancedReporter()

    reporter.generate_html_report(
        all_findings,
        target_url,
        "./reports/complete_report.html"
    )

    reporter.generate_json_report(
        all_findings,
        target_url,
        "./reports/complete_report.json"
    )

    summary = reporter.generate_executive_summary(all_findings)

    return all_findings, summary

# Run scan
findings, summary = asyncio.run(comprehensive_scan("https://api.example.com"))
print(f"Found {summary['finding_counts']['total']} vulnerabilities")
print(f"Risk Score: {summary['risk_score']}")
```

### Example 2: JWT-Only Testing with Custom Wordlist

```python
from overapi.modules.security import JWTAnalyzer

analyzer = JWTAnalyzer(
    target_url="https://api.example.com",
    headers={"Authorization": "Bearer eyJ..."}
)

# Extend weak secrets list
analyzer.WEAK_SECRETS.extend([
    "company_secret",
    "app_password_123",
    "my_jwt_secret",
])

results = asyncio.run(analyzer.analyze([
    {'path': '/api/protected', 'method': 'GET'},
]))

# Print findings
for vuln in analyzer.vulnerabilities:
    print(f"\n[{vuln.severity.upper()}] {vuln.title}")
    print(f"CVSS: {vuln.cvss_score}")
    print(f"PoC: {vuln.poc_script}")
```

### Example 3: Business Logic Testing with Custom Config

```python
from overapi.modules.security import BusinessLogicScanner

config = {
    'race_conditions': {
        'parallel_requests': 200,
        'timeout_ms': 10000,
    },
    'price_manipulation': {
        'enabled': True,
    },
}

scanner = BusinessLogicScanner(
    target_url="https://api.example.com",
    config=config,
)

results = asyncio.run(scanner.scan([
    {'path': '/api/purchase', 'method': 'POST'},
    {'path': '/api/checkout', 'method': 'POST'},
]))

# Analyze results
for vuln in results:
    print(f"{vuln.title}: {vuln.impact}")
```

---

## Configuration

### Config File Location

```
overapi/modules/security/config.yaml
```

### Key Configuration Options

```yaml
jwt_analyzer:
  enabled: true
  timeout: 30
  tests:
    algorithm_none: true
    algorithm_confusion: true
    weak_secret_bruteforce: true
    kid_injection: true
    jku_x5u_injection: true

business_logic_scanner:
  enabled: true
  race_conditions:
    parallel_requests: 50
  mass_assignment:
    test_fields:
      - role
      - is_admin
      - balance

graphql_attacker:
  enabled: true
  graphql_endpoint: /graphql
  limits:
    max_batch_size: 100
    max_nesting_depth: 15

ssrf_tester:
  enabled: true
  collaborator_url: null
  test_endpoints:
    - /api/webhook/create
    - /api/import

reporting:
  formats:
    html: true
    json: true
  output_dir: ./reports
```

### Environment Variables

```bash
# Collaborator URL for blind SSRF testing
export COLLABORATOR_URL=attacker-collaborator.burp.sh

# Custom webhook for callbacks
export WEBHOOK_URL=https://your-server.com/webhook

# Proxy configuration
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
```

---

## Testing

### Run Tests

```bash
# All security module tests
pytest tests/test_security_modules.py -v

# Specific module tests
pytest tests/test_security_modules.py::TestJWTAnalyzer -v
pytest tests/test_security_modules.py::TestBusinessLogicScanner -v

# With coverage
pytest tests/test_security_modules.py --cov=overapi.modules.security
```

### Test Coverage

- JWT Analyzer: 95%+ coverage
- Business Logic Scanner: 90%+ coverage
- GraphQL Attacker: 85%+ coverage
- SSRF Tester: 85%+ coverage
- Reporter: 90%+ coverage

---

## Security Considerations

### Authorization

These tools perform offensive testing. Ensure you have explicit written authorization before testing any API.

### Rate Limiting

- Modules respect target server rate limits
- Configurable timeouts and delays
- Graceful handling of 429 responses

### False Positives

- All findings require manual verification
- False positive filtering rules available
- Evidence collection for validation

### Data Handling

- No sensitive data storage
- Reports can be encrypted
- Configurable logging levels

---

## Performance

### Benchmarks

- JWT analysis: <2 seconds per token
- Business logic test: 30-60 seconds per endpoint
- GraphQL introspection: <5 seconds
- SSRF testing: 10-30 seconds per parameter

### Optimization Tips

- Use `parallel_requests` setting cautiously
- Increase `timeout` for slow targets
- Limit test endpoints list
- Disable unnecessary tests in config

---

## Troubleshooting

### JWT Token Not Detected

```python
# Manual token specification
token = "eyJ..."
results = await analyzer.test_algorithm_none_attack(token)
```

### GraphQL Endpoint Not Found

```python
# Specify custom endpoint
attacker = GraphQLAttacker(
    target_url="https://api.example.com",
    graphql_endpoint="/api/graphql"  # Custom path
)
```

### SSRF Blind Detection Failing

```python
# Ensure collaborator URL is configured
tester = SSRFTester(
    target_url="https://api.example.com",
    collaborator_url="your-collaborator.burp.sh"
)
```

---

## References

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [GraphQL Security](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## License

These security modules are part of the OverApi project and follow the same licensing terms.

## Support

For issues, questions, or feature requests, please refer to the main OverApi documentation or GitHub repository.

---

**Version**: 1.0.0
**Last Updated**: December 2024
**Maintained by**: OverApi Security Team
