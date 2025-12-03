# OverApi Enterprise Edition - Features Guide

## 🌟 Overview

OverApi Enterprise Edition v2.0 is a professional-grade API security testing platform with advanced features for enterprises, security teams, and professional penetration testers.

---

## 🎯 New Features in Enterprise Edition

### 1. Professional Tkinter GUI

**Location:** `overapi/gui/tkinter_app.py`

A modern, professional graphical user interface built with Tkinter featuring:

- **Professional Design:** Clean, modern interface with custom styled buttons and hover effects
- **Multi-Tab Interface:** Organized tabs for Scan Configuration, Dashboard, Vulnerabilities, Logs, and Configuration
- **Real-Time Monitoring:** Live progress tracking and log streaming
- **Advanced Configuration:** Easy-to-use controls for all scan parameters
- **Module Selection:** Enable/disable specific security tests
- **Export Options:** Quick export to multiple formats

**Launch GUI:**
```bash
python overapi-gui.py
# or
python -m overapi.gui.tkinter_app
```

---

### 2. Enterprise Payload Library (150+ Rules)

**Location:** `overapi/payloads/enterprise_payloads.py`

Comprehensive payload library covering:

- **SQL Injection (30+ payloads):** Classic, Union-based, Time-based blind, Boolean-based blind
- **NoSQL Injection (15+ payloads):** MongoDB, CouchDB operators
- **XSS (25+ payloads):** Basic XSS, Filter bypass, Event handlers, SVG-based, WAF bypass
- **Command Injection (20+ payloads):** Linux/Unix, Windows, Time-based detection
- **XXE (10+ payloads):** Basic XXE, Blind XXE, Billion Laughs attack
- **LDAP Injection (10+ payloads)**
- **XPath Injection (10+ payloads)**
- **Template Injection (15+ payloads):** Jinja2, Twig, Freemarker, Velocity, Smarty, ERB
- **SSRF (15+ payloads):** Internal network, Protocol wrappers, AWS/GCP metadata
- **Path Traversal (15+ payloads):** URL encoded, Double encoding, Unicode
- **JWT Attacks:** Algorithm confusion, Weak algorithms, Null signature
- **Authentication Bypass (20+ payloads):** Header manipulation, Method override, Role manipulation
- **CSRF, Mass Assignment, Parameter Pollution, Race Conditions**
- **Business Logic Tests**

**Total Payloads:** 150+ detection rules

---

### 3. Multi-Format Report Generation

**Location:** `overapi/reports/`

Professional report generation in multiple formats:

#### PDF Reports (`pdf_generator.py`)
- Executive summary with risk assessment
- Professional layout with tables and charts
- Detailed vulnerability findings
- Security recommendations
- CVSS scoring

#### HTML Reports (`html_generator.py`)
- Interactive dashboard
- Severity-based color coding
- Collapsible sections
- Search and filter capabilities
- Responsive design

#### CSV Export (`exporters.py`)
- Excel-compatible format
- All vulnerability details
- Easy data analysis
- Bulk processing

#### XML Export (`exporters.py`)
- Corporate audit format
- Hierarchical structure
- OWASP categorization
- Integration with enterprise tools

#### SARIF Export (`exporters.py`)
- CI/CD integration format
- GitHub Security Alerts compatible
- Azure DevOps integration
- Static analysis standard

#### Markdown Export (`exporters.py`)
- GitHub/GitLab compatible
- Technical documentation
- Version control friendly
- Easy to read and share

#### JIRA Export (`exporters.py`)
- Direct JIRA ticket creation
- Priority mapping
- Automated issue tracking
- Sprint planning support

---

### 4. Plugin System

**Location:** `overapi/plugins/`

Extensible plugin architecture for custom functionality:

#### Base Plugin Types:

1. **VulnerabilityPlugin:** Add custom vulnerability detection rules
2. **ReporterPlugin:** Create custom report formats
3. **IntegrationPlugin:** Integrate with external tools

#### Features:

- Dynamic plugin loading
- Hot-reload support
- Plugin lifecycle management
- Dependency handling
- Plugin marketplace ready

#### Creating a Plugin:

```python
from overapi.plugins.base import VulnerabilityPlugin

class MyCustomPlugin(VulnerabilityPlugin):
    def __init__(self):
        super().__init__()
        self.name = "CustomPlugin"
        self.version = "1.0.0"

    def initialize(self) -> bool:
        return True

    def detect_vulnerabilities(self, endpoint, config):
        vulnerabilities = []
        # Your detection logic here
        return vulnerabilities
```

---

### 5. Enterprise Logging System

**Location:** `overapi/core/enterprise_logger.py`

Professional logging with:

- **Automatic Log Rotation:** 10MB default with 10 backups
- **Multiple Formats:** Standard logs, JSON logs, Security events
- **Color-Coded Console:** Easy to read terminal output
- **Performance Metrics:** Track requests, vulnerabilities, errors
- **Security Events:** Dedicated security audit log
- **SIEM Integration:** JSON format for enterprise SIEM systems

**Usage:**
```python
from overapi.core.enterprise_logger import get_logger

logger = get_logger()
logger.info("Scan started")
logger.security_event("vulnerability_found", details)
```

---

### 6. Advanced Configuration System

The enterprise edition includes advanced configuration options:

- **Scan Profiles:** Safe, Normal, Aggressive modes
- **Module Selection:** Enable/disable specific tests
- **Performance Tuning:** Thread count, timeouts, delays
- **Authentication:** Multiple auth methods support
- **Proxy Support:** HTTP/SOCKS5 proxy configuration
- **SSL/TLS Options:** Certificate validation, custom CA bundles
- **Rate Limiting:** Configurable request delays
- **Wordlist Management:** Custom wordlist support

---

### 7. CI/CD Integration

#### GitHub Actions

```yaml
name: API Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run OverApi
        run: |
          pip install -e .
          overapi scan --url ${{ secrets.API_URL }} --out report.sarif --format sarif
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: report.sarif
```

#### GitLab CI

```yaml
security-scan:
  script:
    - pip install -e .
    - overapi scan --url $API_URL --out report.json
  artifacts:
    reports:
      sast: report.sarif
```

#### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh 'overapi scan --url ${API_URL} --out report.html'
        publishHTML([reportName: 'Security Report', reportFiles: 'report.html'])
    }
}
```

---

### 8. Dashboard and Metrics

Real-time monitoring features:

- **Progress Tracking:** Visual progress bars
- **Vulnerability Counter:** Real-time vulnerability count
- **Request Metrics:** Requests per second
- **Endpoint Discovery:** Live endpoint counter
- **Scan Duration:** Elapsed time tracking
- **Error Monitoring:** Failed requests tracking

---

### 9. OWASP API Security Top 10 Coverage

Complete coverage of OWASP API Security Top 10 (2023):

- ✅ **API1:2023** - Broken Object Level Authorization (BOLA/IDOR)
- ✅ **API2:2023** - Broken Authentication
- ✅ **API3:2023** - Broken Object Property Level Authorization
- ✅ **API4:2023** - Unrestricted Resource Consumption
- ✅ **API5:2023** - Broken Function Level Authorization (BFLA)
- ✅ **API6:2023** - Unrestricted Access to Sensitive Business Flows
- ✅ **API7:2023** - Server Side Request Forgery (SSRF)
- ✅ **API8:2023** - Security Misconfiguration
- ✅ **API9:2023** - Improper Inventory Management
- ✅ **API10:2023** - Unsafe Consumption of APIs

---

## 📊 Usage Examples

### Quick Start

```bash
# Launch GUI
python overapi-gui.py

# CLI scan with full features
overapi scan \
  --url https://api.example.com \
  --mode aggressive \
  --threads 20 \
  --out report.pdf \
  --format pdf
```

### Export to Multiple Formats

```bash
# Export to all formats
overapi scan --url https://api.example.com \
  --out-html report.html \
  --out-pdf report.pdf \
  --out-json report.json \
  --out-csv report.csv \
  --out-xml report.xml \
  --out-sarif report.sarif
```

### Using Plugins

```bash
# List available plugins
overapi plugins list

# Enable specific plugin
overapi plugins enable custom_scanner

# Reload plugin
overapi plugins reload custom_scanner
```

### Advanced Configuration

```bash
# Full enterprise scan
overapi scan \
  --url https://api.example.com \
  --mode aggressive \
  --threads 30 \
  --timeout 60 \
  --auth-token "Bearer eyJhbGc..." \
  --header "X-API-Key: secret" \
  --proxy http://127.0.0.1:8080 \
  --wordlist /path/to/wordlist.txt \
  --max-endpoints 5000 \
  --enable-all-modules \
  --out-dir ./reports \
  --verbose
```

---

## 🔧 Configuration Files

### Main Configuration

```yaml
# config.yaml
scan:
  mode: aggressive
  threads: 20
  timeout: 30
  max_endpoints: 5000

authentication:
  type: bearer
  token: ${API_TOKEN}

modules:
  injection: true
  authentication: true
  authorization: true
  bola: true
  rate_limiting: true
  ssrf: true
  business_logic: true

reporting:
  formats:
    - html
    - pdf
    - json
    - sarif
  output_dir: ./reports

plugins:
  enabled: true
  auto_load: true
  directory: ./plugins

logging:
  level: INFO
  rotation: true
  max_size: 10MB
  backup_count: 10
```

---

## 🚀 Performance

Enterprise edition is optimized for:

- **Concurrent Scanning:** Up to 50 threads
- **Large APIs:** Handle 10,000+ endpoints
- **Memory Efficient:** Streaming results
- **Fast Detection:** Optimized payload testing
- **Scalable:** Kubernetes-ready

---

## 🔐 Security Best Practices

1. **Use Virtual Environments:** Isolate dependencies
2. **Secure Credentials:** Use environment variables
3. **Rotate Logs:** Enable automatic rotation
4. **Review Reports:** Regularly audit findings
5. **Update Regularly:** Keep payloads current
6. **Test Responsibly:** Only scan authorized targets
7. **Backup Results:** Archive scan reports
8. **Monitor Performance:** Track metrics

---

## 📚 Additional Resources

- **Documentation:** https://github.com/GhostN3xus/OverApi/wiki
- **Plugin Development:** See `overapi/plugins/base.py`
- **API Reference:** See source code docstrings
- **Examples:** Check `examples/` directory
- **Support:** Open an issue on GitHub

---

## 🎓 Training and Certification

Enterprise edition includes:

- **Video Tutorials:** Getting started guides
- **Best Practices:** Security testing methodologies
- **Case Studies:** Real-world examples
- **Certification:** OverApi Security Tester certification

---

## 📞 Enterprise Support

For enterprise support and licensing:

- **Email:** enterprise@overapi.dev
- **Website:** https://overapi.dev/enterprise
- **Slack:** Join our enterprise Slack channel
- **Phone:** Available for enterprise customers

---

**Version:** 2.0.0 Enterprise
**Last Updated:** 2024-12-03
**Author:** GhostN3xus & OverApi Team
