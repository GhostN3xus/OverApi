"""
Vulnerability Database Manager for OverApi
"""

import json
import os
from typing import Dict, List, Optional


class VulnerabilityDatabase:
    """
    Manages the local vulnerability database.
    Provides descriptions, remediations, CWE, and OWASP references.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), 'vuln_db.json')
        self.database = self._load_database()

    def _load_database(self) -> Dict:
        """Load database from file or create default if not exists."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            except Exception:
                return self._get_default_database()
        return self._get_default_database()

    def _get_default_database(self) -> Dict:
        """Return default vulnerability database."""
        return {
            "SQL Injection": {
                "title": "SQL Injection",
                "description": "SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query.",
                "impact": "Attackers can access, modify, or delete data in the database.",
                "cwe": "CWE-89",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Use parameterized queries or prepared statements. Validate all inputs."
            },
            "XSS": {
                "title": "Cross-Site Scripting (XSS)",
                "description": "XSS allows attackers to execute malicious scripts in the victim's browser.",
                "impact": "Session hijacking, deflection, and defacement.",
                "cwe": "CWE-79",
                "owasp": "API3:2023 - Broken Object Property Level Authorization", # Context dependent, generally injection
                "remediation": "Escape all untrusted data based on the output context (HTML, JavaScript, CSS, URL)."
            },
            "BOLA": {
                "title": "Broken Object Level Authorization (BOLA/IDOR)",
                "description": "API exposes endpoints that handle object identifiers without validating user access permissions.",
                "impact": "Unauthorized access to other users' data.",
                "cwe": "CWE-639",
                "owasp": "API1:2023 - Broken Object Level Authorization",
                "remediation": "Implement proper authorization checks for every object access."
            },
            "Broken Authentication": {
                "title": "Broken Authentication",
                "description": "Incorrect implementation of authentication mechanisms.",
                "impact": "Attackers can compromise passwords, keys, or session tokens.",
                "cwe": "CWE-287",
                "owasp": "API2:2023 - Broken Authentication",
                "remediation": "Use standard authentication protocols (OAuth2, OpenID Connect). Enforce strong passwords and MFA."
            },
            "Excessive Data Exposure": {
                "title": "Excessive Data Exposure",
                "description": "API returns more data than the client needs, relying on the client to filter it.",
                "impact": "Leakage of sensitive PII or internal data.",
                "cwe": "CWE-200",
                "owasp": "API3:2023 - Broken Object Property Level Authorization",
                "remediation": "Filter data on the server side. Use 'Schema' to define responses explicitly."
            }
        }

    def get_vulnerability(self, vuln_type: str) -> Optional[Dict]:
        """Get details for a specific vulnerability type."""
        # Fuzzy match or direct lookup
        if vuln_type in self.database:
            return self.database[vuln_type]

        # Try case-insensitive
        for key, value in self.database.items():
            if key.lower() == vuln_type.lower():
                return value
            if vuln_type.lower() in key.lower(): # Partial match
                return value

        return None

    def add_vulnerability(self, key: str, data: Dict):
        """Add or update a vulnerability in the database."""
        self.database[key] = data
        self.save()

    def save(self):
        """Save database to file."""
        try:
            with open(self.db_path, 'w') as f:
                json.dump(self.database, f, indent=4)
        except Exception as e:
            print(f"Error saving vulnerability database: {e}")

    def get_all(self) -> Dict:
        """Get all vulnerabilities."""
        return self.database
