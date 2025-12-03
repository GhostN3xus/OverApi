# OverApi Enterprise

![OverApi Logo](https://via.placeholder.com/150)

**OverApi Enterprise** is a comprehensive, modular, and professional API Security Testing Platform (DAST) designed for modern enterprises. It supports REST, GraphQL, SOAP, gRPC, and WebSockets, providing deep inspection and advanced vulnerability detection.

## 🚀 Features

*   **Multi-Protocol Support:** REST, GraphQL, SOAP, gRPC, WebSockets.
*   **Advanced Detection Engine:** Deep HTTP analysis, heuristic detection, and validation logic to reduce false positives.
*   **Enterprise GUI:** Modern Tkinter-based interface with Dashboard, Reporting, and Tool management.
*   **Tools Suite:**
    *   **Plugin Manager:** Extensible architecture for custom scanners.
    *   **Vulnerability Database:** Integrated knowledge base of CWE/OWASP vulnerabilities.
    *   **Wordlist Manager:** Manage and edit fuzzing lists.
    *   **Preferences:** Global configuration management.
*   **OWASP API Top 10 Coverage:** Automated tests for BOLA, Broken Auth, Data Exposure, etc.
*   **Advanced Payloads:** Extensive payload lists for SQLi, XSS, CMD Injection, XXE, SSRF.
*   **Reporting:** Export to HTML, JSON, CSV.

## 📦 Installation

```bash
git clone https://github.com/GhostN3xus/OverApi.git
cd OverApi
pip install -r requirements.txt
```

## 🛠 Usage

### GUI Mode (Recommended)

Run the enterprise GUI:

```bash
python overapi/gui/tkinter_app.py
```

### CLI Mode

Run the command-line interface:

```bash
python main.py scan https://api.example.com
```

## 📚 Documentation

### Key Modules

*   **`overapi.core.api_detector`**: Automatically identifies API types and technologies.
*   **`overapi.scanners.security_tester`**: Main vulnerability scanning engine with verification logic.
*   **`overapi.tools`**: Helper modules for DB, Wordlists, and Config.
*   **`overapi.payloads.advanced_payloads`**: Centralized repository of attack vectors.

### Creating Plugins

Plugins are Python files located in `overapi/plugins/installed/`. A basic plugin looks like this:

```python
from overapi.plugins.base import VulnerabilityPlugin

class MyPlugin(VulnerabilityPlugin):
    def detect_vulnerabilities(self, endpoint, config):
        # Your logic here
        return []
```

## 🛡 Security

OverApi is intended for legal security testing only. Usage against systems you do not own or have permission to test is illegal.

## 🤝 Contributing

Contributions are welcome! Please submit Pull Requests to the main repository.

## 📄 License

MIT License
