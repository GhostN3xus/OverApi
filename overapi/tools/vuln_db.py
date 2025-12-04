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
        """Return default vulnerability database with OWASP API Top 10 2023."""
        return {
            # OWASP API Top 10 2023
            "SQL Injection": {
                "title": "SQL Injection",
                "description": "SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query.",
                "impact": "Attackers can access, modify, or delete data in the database.",
                "cwe": "CWE-89",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Use parameterized queries or prepared statements. Validate all inputs."
            },
            "SQL Injection (Time-based Blind)": {
                "title": "Time-based Blind SQL Injection",
                "description": "A variant of SQL injection where the attacker infers information based on response delays.",
                "impact": "Data extraction through time-based inference attacks.",
                "cwe": "CWE-89",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Use parameterized queries. Implement query timeout limits."
            },
            "XSS": {
                "title": "Cross-Site Scripting (XSS)",
                "description": "XSS allows attackers to execute malicious scripts in the victim's browser.",
                "impact": "Session hijacking, defacement, and phishing attacks.",
                "cwe": "CWE-79",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Escape all untrusted data based on the output context (HTML, JavaScript, CSS, URL)."
            },
            "BOLA": {
                "title": "Broken Object Level Authorization (BOLA/IDOR)",
                "description": "API exposes endpoints that handle object identifiers without validating user access permissions.",
                "impact": "Unauthorized access to other users' data.",
                "cwe": "CWE-639",
                "owasp": "API1:2023 - Broken Object Level Authorization",
                "remediation": "Implement proper authorization checks for every object access. Use random, unpredictable IDs."
            },
            "BOLA (Broken Object Level Authorization)": {
                "title": "Broken Object Level Authorization (BOLA/IDOR)",
                "description": "API exposes endpoints that handle object identifiers without validating user access permissions.",
                "impact": "Unauthorized access to other users' data.",
                "cwe": "CWE-639",
                "owasp": "API1:2023 - Broken Object Level Authorization",
                "remediation": "Implement proper authorization checks for every object access. Use random, unpredictable IDs."
            },
            "Broken Authentication": {
                "title": "Broken Authentication",
                "description": "Incorrect implementation of authentication mechanisms.",
                "impact": "Attackers can compromise passwords, keys, or session tokens.",
                "cwe": "CWE-287",
                "owasp": "API2:2023 - Broken Authentication",
                "remediation": "Use standard authentication protocols (OAuth2, OpenID Connect). Enforce strong passwords and MFA."
            },
            "Weak Token Validation": {
                "title": "Weak Token Validation",
                "description": "API accepts invalid or improperly validated tokens.",
                "impact": "Authentication bypass allowing unauthorized access.",
                "cwe": "CWE-287",
                "owasp": "API2:2023 - Broken Authentication",
                "remediation": "Implement strict token validation. Use cryptographically secure tokens."
            },
            "JWT Vulnerability": {
                "title": "JWT Security Vulnerability",
                "description": "JSON Web Token implementation has security weaknesses.",
                "impact": "Token forgery, privilege escalation, or session hijacking.",
                "cwe": "CWE-347",
                "owasp": "API2:2023 - Broken Authentication",
                "remediation": "Use strong algorithms (RS256, ES256). Validate all claims. Set appropriate expiration times."
            },
            "Excessive Data Exposure": {
                "title": "Excessive Data Exposure",
                "description": "API returns more data than the client needs, relying on the client to filter it.",
                "impact": "Leakage of sensitive PII or internal data.",
                "cwe": "CWE-200",
                "owasp": "API3:2023 - Broken Object Property Level Authorization",
                "remediation": "Filter data on the server side. Use schema validation for responses."
            },
            "Lack of Rate Limiting": {
                "title": "Lack of Resource & Rate Limiting",
                "description": "API does not implement rate limiting, allowing unlimited requests.",
                "impact": "Denial of Service, brute force attacks, and resource exhaustion.",
                "cwe": "CWE-770",
                "owasp": "API4:2023 - Unrestricted Resource Consumption",
                "remediation": "Implement rate limiting per user/IP. Use throttling and request quotas."
            },
            "Privilege Escalation": {
                "title": "Broken Function Level Authorization",
                "description": "API exposes administrative functions to regular users.",
                "impact": "Unauthorized access to admin functions and data.",
                "cwe": "CWE-285",
                "owasp": "API5:2023 - Broken Function Level Authorization",
                "remediation": "Implement role-based access control. Validate permissions on every function call."
            },
            "Mass Assignment": {
                "title": "Mass Assignment",
                "description": "API blindly binds user input to internal objects without proper filtering.",
                "impact": "Attackers can modify object properties they shouldn't have access to.",
                "cwe": "CWE-915",
                "owasp": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
                "remediation": "Whitelist allowed parameters. Use DTOs for data transfer."
            },
            "SSRF": {
                "title": "Server-Side Request Forgery (SSRF)",
                "description": "API fetches remote resources without validating user-supplied URLs.",
                "impact": "Access to internal services, data exfiltration, and network scanning.",
                "cwe": "CWE-918",
                "owasp": "API7:2023 - Server Side Request Forgery",
                "remediation": "Validate and sanitize URLs. Use allowlists for permitted domains."
            },
            "Security Misconfiguration": {
                "title": "Security Misconfiguration",
                "description": "API or server is configured with insecure settings.",
                "impact": "Information disclosure, unauthorized access.",
                "cwe": "CWE-16",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Follow security hardening guidelines. Disable verbose error messages."
            },
            "CORS Misconfiguration": {
                "title": "CORS Misconfiguration",
                "description": "Cross-Origin Resource Sharing policy is misconfigured.",
                "impact": "Cross-site data theft and unauthorized API access.",
                "cwe": "CWE-942",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Configure strict CORS policies. Avoid wildcard origins with credentials."
            },
            "Missing Security Header": {
                "title": "Missing Security Headers",
                "description": "HTTP security headers are not configured.",
                "impact": "Increased attack surface for XSS, clickjacking, and other attacks.",
                "cwe": "CWE-693",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Implement HSTS, X-Frame-Options, CSP, and other security headers."
            },
            "Command Injection": {
                "title": "OS Command Injection",
                "description": "API executes system commands with user-controlled input.",
                "impact": "Remote code execution and system compromise.",
                "cwe": "CWE-78",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Avoid system calls with user input. Use parameterized commands."
            },
            "XXE": {
                "title": "XML External Entity (XXE) Injection",
                "description": "XML parser processes external entity references.",
                "impact": "File disclosure, SSRF, and denial of service.",
                "cwe": "CWE-611",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Disable external entity processing. Use less complex formats like JSON."
            },
            "NoSQL Injection": {
                "title": "NoSQL Injection",
                "description": "NoSQL database query can be manipulated through user input.",
                "impact": "Data access, modification, or deletion.",
                "cwe": "CWE-943",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Validate and sanitize input. Use parameterized queries."
            },
            "Unsafe Redirect": {
                "title": "Unsafe Redirect (Open Redirect)",
                "description": "API redirects to user-controlled destinations.",
                "impact": "Phishing attacks and credential theft.",
                "cwe": "CWE-601",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Validate redirect URLs. Use allowlists for permitted destinations."
            },
            "Authentication/Authorization Bypass": {
                "title": "Authentication/Authorization Bypass",
                "description": "Security controls can be bypassed through technique manipulation.",
                "impact": "Unauthorized access to protected resources.",
                "cwe": "CWE-287",
                "owasp": "API2:2023 - Broken Authentication",
                "remediation": "Implement robust authentication that cannot be bypassed with header or method manipulation."
            },
            "Access Control Bypass": {
                "title": "Access Control Bypass",
                "description": "Access controls can be circumvented through various techniques.",
                "impact": "Unauthorized access to restricted data or functionality.",
                "cwe": "CWE-639",
                "owasp": "API1:2023 - Broken Object Level Authorization",
                "remediation": "Implement consistent access controls across all endpoints and methods."
            },
            "Improper Asset Management": {
                "title": "Improper Inventory Management",
                "description": "Old or undocumented API versions are exposed.",
                "impact": "Access to deprecated endpoints with known vulnerabilities.",
                "cwe": "CWE-1059",
                "owasp": "API9:2023 - Improper Inventory Management",
                "remediation": "Maintain API inventory. Deprecate and remove old versions."
            },
            "Unsafe API Consumption": {
                "title": "Unsafe Consumption of APIs",
                "description": "API trusts third-party API responses without validation.",
                "impact": "Injection attacks and data corruption through third-party APIs.",
                "cwe": "CWE-20",
                "owasp": "API10:2023 - Unsafe Consumption of APIs",
                "remediation": "Validate all third-party API responses. Use HTTPS for external calls."
            },
            "Information Disclosure": {
                "title": "Information Disclosure",
                "description": "API exposes sensitive information in responses or errors.",
                "impact": "Disclosure of internal details, configuration, or user data.",
                "cwe": "CWE-200",
                "owasp": "API8:2023 - Security Misconfiguration",
                "remediation": "Implement generic error messages. Remove stack traces and debug info."
            },
            "GraphQL Introspection": {
                "title": "GraphQL Introspection Enabled",
                "description": "GraphQL introspection exposes the entire API schema.",
                "impact": "Schema disclosure enables targeted attacks.",
                "cwe": "CWE-200",
                "owasp": "API9:2023 - Improper Inventory Management",
                "remediation": "Disable introspection in production. Implement field-level authorization."
            },
            "GraphQL Query Depth": {
                "title": "GraphQL Query Depth Attack",
                "description": "GraphQL allows deeply nested queries causing resource exhaustion.",
                "impact": "Denial of service through expensive queries.",
                "cwe": "CWE-400",
                "owasp": "API4:2023 - Unrestricted Resource Consumption",
                "remediation": "Implement query depth limiting and complexity analysis."
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
