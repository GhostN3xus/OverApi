# OverApi - Universal API Security Scanner

🔒 **OverApi** is a robust, modular, and professional CLI tool for comprehensive offensive and defensive security scanning of APIs. It supports multiple API types including REST, GraphQL, SOAP, gRPC, WebSockets, and Webhooks.

## Features

### API Type Detection
- ✅ Automatic detection of API types (REST, GraphQL, SOAP, gRPC, WebSocket, OpenAPI)
- ✅ Smart heuristic-based identification
- ✅ Support for undocumented APIs (blind scan)

### Endpoint Discovery
- ✅ Wordlist-based fuzzing
- ✅ Swagger/OpenAPI documentation parsing
- ✅ GraphQL introspection
- ✅ WSDL parsing for SOAP
- ✅ gRPC reflection

### Security Testing
- ✅ **OWASP API Top 10** vulnerability testing
- ✅ Injection testing (SQLi, XSS, NoSQL, Command Injection)
- ✅ BOLA (Broken Object Level Authorization)
- ✅ Authentication bypass detection
- ✅ Rate limit testing
- ✅ Data exposure detection

### Reporting
- ✅ Professional HTML reports with severity color-coding
- ✅ Structured JSON reports
- ✅ Executive summary with risk assessment
- ✅ Detailed vulnerability evidence

## Installation

```bash
pip install -r requirements.txt
chmod +x main.py
```

## Usage

### Basic Scan
```bash
python main.py --url https://api.example.com
```

### With Options
```bash
python main.py --url https://api.example.com \
    --threads 20 \
    --mode aggressive \
    --out report.html \
    --json results.json
```

### Available Options

- `--url URL` (required): Target API URL
- `--type TYPE`: Force API type (rest, graphql, soap)
- `--mode MODE`: Scan mode (safe, normal, aggressive)
- `--threads N`: Number of threads (default: 10)
- `--timeout N`: Request timeout (default: 30s)
- `--proxy PROXY`: Proxy URL
- `--no-verify-ssl`: Disable SSL verification
- `--header "Key: Value"`: Custom headers
- `--out PATH`: HTML report output
- `--json PATH`: JSON report output
- `--wordlist PATH`: Custom wordlist
- `--max-endpoints N`: Max endpoints to test
- `--no-fuzzing`: Disable fuzzing
- `--no-injection`: Disable injection tests
- `-v, --verbose`: Verbose output

## Examples

```bash
# Simple REST scan
python main.py --url https://api.example.com --out report.html

# Aggressive mode
python main.py --url https://api.example.com --mode aggressive --threads 20

# With proxy and custom headers
python main.py --url https://api.example.com \
    --proxy http://127.0.0.1:8080 \
    --header "Authorization: Bearer token" \
    --no-verify-ssl

# GraphQL API
python main.py --url https://api.example.com/graphql --type graphql --out report.html
```

## Project Structure

```
OverApi/
├── overapi/
│   ├── core/              # Core modules
│   ├── modules/           # API-specific modules
│   ├── scanner/           # Scanning engines
│   ├── utils/             # Utilities
│   └── report/            # Report generation
├── main.py               # Entry point
└── requirements.txt      # Dependencies
```

## Version
1.0.0

---
*For authorized security testing only.*
