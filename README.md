# OverApi Enterprise v2.0.0

<div align="center">

🔒 **API Security Testing Platform (DAST)** 🔒

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Beta-yellow)](https://github.com/GhostN3xus/OverApi)

**Advanced API vulnerability scanner for REST, GraphQL, SOAP, gRPC, and WebSockets**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [API Docs](#-api-documentation) • [Architecture](#-architecture)

</div>

---

## 🚀 Features

### Multi-Protocol Support
- **REST APIs** - Full REST endpoint discovery and testing
- **GraphQL** - Introspection queries, mutation testing, and schema analysis
- **SOAP/WSDL** - WSDL parsing and SOAP method enumeration
- **gRPC** - Protocol buffer inspection and RPC testing
- **WebSockets** - Real-time communication testing
- **Custom APIs** - Extensible framework for custom protocols

### Vulnerability Detection
- ✅ **OWASP API Top 10** - Complete coverage of modern API threats
  - BOLA (Broken Object Level Authorization)
  - Broken User Authentication
  - Excessive Data Exposure
  - Lack of Resource & Rate Limiting
  - Broken Function Level Authorization
  - Mass Assignment
  - Security Misconfiguration
  - Injection Attacks
  - Improper Assets Management
  - Insufficient Logging & Monitoring

- ✅ **Advanced Scanners**
  - JWT Token Analysis & Cryptographic Attacks
  - SSRF (Server-Side Request Forgery) Detection
  - SQL Injection, XSS, Command Injection
  - XXE (XML External Entity) Attacks
  - Business Logic Flaws
  - Rate Limiting Bypass
  - Authentication Bypass Techniques

### Enterprise Features
- 🎨 **Professional GUI** - Tkinter-based dashboard with real-time results
- 🔄 **Fuzzing Engine** - Intelligent parameter fuzzing with custom payloads
- 📊 **Report Generation** - HTML, JSON, and CSV exports with detailed findings
- 🛠️ **Extensible Architecture** - Plugin system for custom tests
- 📚 **Vulnerability Database** - Integrated CWE/OWASP knowledge base
- 📝 **Wordlist Manager** - Manage fuzzing dictionaries and custom lists
- 🔒 **Security-First** - Support for proxy, custom headers, SSL/TLS validation

---

## 📦 Installation

### Requirements
- **Python 3.8+**
- **pip** (Python package manager)
- **Git**

### Step 1: Clone Repository
```bash
git clone https://github.com/GhostN3xus/OverApi.git
cd OverApi
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: (Optional) Install GUI Dependencies
For desktop GUI support:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS
brew install python-tk@3.x

# Windows
# Tkinter is included with Python installer
```

### Step 4: Verify Installation
```bash
python main.py --help
```

---

## 🛠️ Quick Start

### Basic Usage (CLI)

#### 1. Simple REST API Scan
```bash
python main.py \
  --url https://api.example.com \
  --mode normal \
  --threads 10 \
  --out report.html
```

#### 2. Aggressive GraphQL Testing
```bash
python main.py \
  --url https://api.example.com/graphql \
  --type graphql \
  --mode aggressive \
  --enable-fuzzing \
  --json report.json
```

#### 3. With Authentication
```bash
python main.py \
  --url https://api.example.com \
  --header "Authorization: Bearer YOUR_TOKEN" \
  --header "X-API-Key: YOUR_KEY" \
  --mode normal
```

#### 4. With Proxy (e.g., Burp Suite)
```bash
python main.py \
  --url https://api.example.com \
  --proxy http://localhost:8080 \
  --no-verify-ssl
```

### GUI Mode

#### Launch Desktop Interface
```bash
python overapi-gui.py
```

Features:
- Visual endpoint discovery
- Real-time vulnerability detection
- Interactive report builder
- Payload editor and customization
- Scan history and results management

### CLI Advanced Commands

#### Custom Wordlist
```bash
python main.py \
  --url https://api.example.com \
  --wordlist /path/to/custom/wordlist.txt \
  --mode aggressive
```

#### Selective Testing
```bash
python main.py \
  --url https://api.example.com \
  --no-fuzzing \           # Skip fuzzing
  --no-injection \         # Skip injection tests
  --no-ratelimit \         # Skip rate limit tests
  --enable-bola-tests      # Only test BOLA
```

#### Verbose Output
```bash
python main.py \
  --url https://api.example.com \
  --verbose \
  --log-file scan.log
```

---

## 📊 Scanning Modes

| Mode | Aggressiveness | Speed | False Positives | Use Case |
|------|----------------|-------|-----------------|----------|
| **safe** | Low | Fast | Very Low | Non-prod, rate-limited APIs |
| **normal** | Medium | Medium | Low | Production-grade testing |
| **aggressive** | High | Slow | Higher | Lab/test environments |

---

## 📋 Command-Line Options

```
Target Options:
  --url URL                    Target API URL (required)
  --type {rest,graphql,soap}   Force API type detection

Scanning Options:
  --mode {safe,normal,aggressive}  Scan mode (default: normal)
  --threads N                  Thread count for parallel requests (default: 10)
  --timeout N                  Request timeout in seconds (default: 30)
  --max-endpoints N            Maximum endpoints to test (default: 1000)

Security Options:
  --proxy URL                  HTTP/HTTPS proxy URL
  --verify-ssl                 Verify SSL certificates (default: enabled)
  --no-verify-ssl              Disable SSL verification (NOT recommended)
  --custom-ca PATH             Path to custom CA certificate
  --header "Key: Value"        Custom HTTP header (repeatable)

Output Options:
  --out FILE                   HTML report output path
  --json FILE                  JSON report output path
  --outdir DIR                 Output directory (default: ./reports)
  --verbose, -v                Verbose output
  --log-file FILE              Log file path

Feature Control:
  --no-fuzzing                 Disable fuzzing tests
  --no-injection               Disable injection tests
  --no-ratelimit               Disable rate limit tests
  --no-bola                    Disable BOLA tests
  --wordlist PATH              Custom wordlist for fuzzing
```

---

## 🏗️ Architecture

### Directory Structure
```
OverApi/
├── overapi/                      # Main package
│   ├── core/                     # Core functionality
│   │   ├── logger.py            # Logging system
│   │   ├── config.py            # Configuration management
│   │   ├── context.py           # Scan context & results
│   │   ├── api_detector.py      # API type detection
│   │   └── exceptions.py        # Custom exceptions
│   │
│   ├── scanners/                # Vulnerability scanners
│   │   ├── orchestrator.py      # Main scan pipeline
│   │   ├── security_tester.py   # Core detection engine
│   │   ├── jwt.py               # JWT analysis
│   │   └── ssrf.py              # SSRF detection
│   │
│   ├── protocols/               # Protocol implementations
│   │   ├── rest/                # REST API scanner
│   │   ├── graphql/             # GraphQL scanner
│   │   ├── soap/                # SOAP scanner
│   │   ├── grpc/                # gRPC scanner
│   │   └── websocket/           # WebSocket scanner
│   │
│   ├── gui/                     # User interface
│   │   └── tkinter_app.py       # Tkinter-based GUI
│   │
│   ├── reports/                 # Report generation
│   │   ├── html_generator.py    # HTML reports
│   │   └── json_generator.py    # JSON reports
│   │
│   ├── fuzzers/                 # Fuzzing engine
│   │   └── engine.py            # Fuzzing logic
│   │
│   ├── payloads/                # Attack payloads
│   │   └── advanced_payloads.py # Payload lists
│   │
│   ├── bypass/                  # Security bypass techniques
│   │   └── engine.py            # Bypass methods
│   │
│   ├── utils/                   # Utilities
│   │   ├── http_client.py       # HTTP client
│   │   ├── validators.py        # Input validation
│   │   └── cert_manager.py      # Certificate handling
│   │
│   ├── tools/                   # Tools & databases
│   │   ├── vuln_db.py           # Vulnerability database
│   │   └── wordlist_manager.py  # Wordlist management
│   │
│   └── plugins/                 # Plugin system
│       └── base.py              # Plugin base classes
│
├── tests/                        # Test suite
│   ├── test_fuzzer.py
│   ├── test_bypass.py
│   └── test_wordlist_loader.py
│
├── main.py                       # CLI entry point
├── overapi-gui.py               # GUI launcher
├── requirements.txt              # Python dependencies
├── pytest.ini                    # Test configuration
└── README.md                     # This file
```

### Scan Pipeline
```
1. Initialization
   └─ Load config, initialize logger

2. API Type Detection
   └─ Identify REST/GraphQL/SOAP/etc.

3. Endpoint Discovery
   └─ Enumerate API methods/routes

4. Fuzzing (Optional)
   └─ Fuzz parameters with wordlist

5. Vulnerability Detection
   ├─ JWT Analysis
   ├─ SSRF Testing
   ├─ Injection Tests
   ├─ BOLA Testing
   └─ Business Logic Checks

6. Report Generation
   └─ HTML/JSON output with findings
```

---

## 📚 API Documentation

### Core Classes

#### Orchestrator
Main scan orchestrator that coordinates all scanning activities.
```python
from overapi.scanners.orchestrator import Orchestrator
from overapi.core.config import Config

config = Config(url="https://api.example.com")
orchestrator = Orchestrator(config)
results = orchestrator.scan()
```

#### RestScanner
REST API endpoint discovery and testing.
```python
from overapi.protocols.rest.scanner import RestScanner
from overapi.core.context import ScanContext

context = ScanContext(target="https://api.example.com")
scanner = RestScanner(context, config, logger)
endpoints = scanner.discover_endpoints()
```

#### SecurityTester
Main vulnerability detection engine.
```python
from overapi.scanners.security_tester import SecurityTester

tester = SecurityTester(context, config, logger)
vulnerabilities = tester.test_endpoint(endpoint)
```

### Plugin Development

Create custom scanners by extending the base plugin:

```python
from overapi.plugins.base import VulnerabilityPlugin

class MyCustomPlugin(VulnerabilityPlugin):
    """Custom vulnerability scanner."""

    def __init__(self, config, logger):
        super().__init__()
        self.config = config
        self.logger = logger

    def detect(self, endpoint):
        """Detect vulnerabilities in endpoint."""
        findings = []
        # Your detection logic here
        return findings
```

Place in `overapi/plugins/installed/my_plugin.py`

---

## 🔧 Configuration

### Config File Example
```python
from overapi.core.config import Config, ScanMode, ProxyConfig

config = Config(
    url="https://api.example.com",
    api_type="rest",
    mode=ScanMode.NORMAL,
    threads=10,
    timeout=30,
    verify_ssl=True,
    proxy=ProxyConfig(http="http://localhost:8080"),
    enable_fuzzing=True,
    enable_injection_tests=True,
    enable_ratelimit_tests=True,
    enable_bola_tests=True,
)
```

### Environment Variables
```bash
export OVERAPI_THREADS=20
export OVERAPI_TIMEOUT=60
export OVERAPI_PROXY="http://localhost:8080"
export OVERAPI_WORDLIST="/path/to/wordlist.txt"
```

---

## 🧪 Testing

Run the test suite:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ --cov=overapi --cov-report=html
```

Run specific test:
```bash
pytest tests/test_fuzzer.py -v
```

---

## 🐛 Troubleshooting

### Issue: "No module named 'tkinter'"
**Solution:** Install Tkinter for your OS
- Ubuntu: `sudo apt-get install python3-tk`
- macOS: `brew install python-tk`
- Windows: Re-run Python installer with Tkinter enabled

### Issue: SSL Certificate Verification Failed
**Solution:** Use `--no-verify-ssl` flag (development only)
```bash
python main.py --url https://api.example.com --no-verify-ssl
```

Or provide custom CA:
```bash
python main.py --url https://api.example.com --custom-ca /path/to/ca.pem
```

### Issue: Timeout Errors
**Solution:** Increase timeout value
```bash
python main.py --url https://api.example.com --timeout 60
```

### Issue: High False Positive Rate
**Solution:** Use `safe` mode
```bash
python main.py --url https://api.example.com --mode safe
```

### Issue: Import Errors
**Solution:** Verify installation
```bash
python -c "from overapi.scanners.orchestrator import Orchestrator; print('OK')"
pip install --upgrade -r requirements.txt
```

---

## 📈 Performance Tips

1. **Use Correct Thread Count**
   - Single endpoint: 5-10 threads
   - Multiple endpoints: 20-50 threads
   - Large APIs: 50-100+ threads

2. **Choose Appropriate Mode**
   - Development/staging: `aggressive`
   - Production: `normal`
   - Rate-limited APIs: `safe`

3. **Disable Unnecessary Tests**
   ```bash
   python main.py --url https://api.example.com \
     --no-fuzzing \
     --enable-bola-tests
   ```

4. **Use Custom Wordlists**
   - Smaller wordlists = faster scans
   - Relevant keywords = better results

5. **Leverage Parallel Scanning**
   - Scan multiple APIs simultaneously
   - Use different output directories

---

## 📊 Report Format

### HTML Report Features
- Executive summary with risk score
- Detailed vulnerability findings with PoC
- Endpoint inventory and metadata
- Scan timeline and statistics
- Downloadable evidence/screenshots

### JSON Report Format
```json
{
  "scan_metadata": {
    "target": "https://api.example.com",
    "start_time": "2024-01-01T10:00:00Z",
    "duration_seconds": 120,
    "endpoints_tested": 45
  },
  "vulnerabilities": [
    {
      "type": "BOLA",
      "severity": "HIGH",
      "endpoint": "GET /api/users/{id}",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature/my-feature`
5. Submit Pull Request

### Development Setup
```bash
git clone https://github.com/yourusername/OverApi.git
cd OverApi
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock
```

---

## ⚖️ Legal & Security

**⚠️ DISCLAIMER:**

OverApi is provided for authorized security testing only. Unauthorized access to computer systems is illegal. Users are responsible for:

- Obtaining explicit written permission before testing any system
- Complying with all applicable laws and regulations
- Conducting responsible disclosure of findings
- Using this tool ethically and responsibly

Illegal usage may result in civil and criminal penalties.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 📞 Support & Feedback

- **Issues:** [GitHub Issues](https://github.com/GhostN3xus/OverApi/issues)
- **Discussions:** [GitHub Discussions](https://github.com/GhostN3xus/OverApi/discussions)
- **Documentation:** See `docs/` directory for detailed guides

---

## 🙏 Acknowledgments

- OWASP for API Top 10 framework
- Security research community for vulnerability research
- Contributors and testers

---

<div align="center">

**Made with ❤️ for API Security**

[⬆ Back to top](#overapi-enterprise-v200)

</div>
