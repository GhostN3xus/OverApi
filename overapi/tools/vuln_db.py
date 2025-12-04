"""
Vulnerability Database for OverApi

Provides a comprehensive database of vulnerability information including
CWE mappings, OWASP categories, and remediation guidance.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import json
from pathlib import Path


@dataclass
class VulnerabilityInfo:
    """Information about a vulnerability type."""
    name: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    severity: str
    description: str
    impact: str
    remediation: List[str]
    references: List[str]
    cvss_base: float


class VulnerabilityDatabase:
    """
    Comprehensive vulnerability database.

    Provides detailed information about common API vulnerabilities,
    CWE mappings, OWASP categories, and remediation guidance.
    """

    def __init__(self):
        """Initialize the vulnerability database."""
        self.vulnerabilities: Dict[str, VulnerabilityInfo] = {}
        self._initialize_database()

    def _initialize_database(self):
        """Initialize the database with vulnerability information."""

        # OWASP API Security Top 10 2023
        self.vulnerabilities = {
            'BOLA': VulnerabilityInfo(
                name='Broken Object Level Authorization (BOLA)',
                cwe_id='CWE-639',
                cwe_name='Authorization Bypass Through User-Controlled Key',
                owasp_category='API1:2023 - Broken Object Level Authorization',
                severity='HIGH',
                description=(
                    'Object level authorization is an access control mechanism that is usually '
                    'implemented at the code level to validate that one user can only access '
                    'objects that they should have permissions to access.'
                ),
                impact=(
                    'Unauthorized viewing, modification, or deletion of data. '
                    'Attackers can access other users\' objects by manipulating object IDs.'
                ),
                remediation=[
                    'Implement proper authorization checks for every object access',
                    'Use random and unpredictable object identifiers',
                    'Validate user permissions before returning object data',
                    'Implement proper session management',
                    'Use automated testing to verify authorization logic'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
                    'https://cwe.mitre.org/data/definitions/639.html'
                ],
                cvss_base=8.2
            ),

            'Broken_Authentication': VulnerabilityInfo(
                name='Broken User Authentication',
                cwe_id='CWE-287',
                cwe_name='Improper Authentication',
                owasp_category='API2:2023 - Broken Authentication',
                severity='CRITICAL',
                description=(
                    'Authentication mechanisms are often implemented incorrectly, allowing '
                    'attackers to compromise authentication tokens or to exploit implementation '
                    'flaws to assume other users\' identities.'
                ),
                impact=(
                    'Complete account takeover, unauthorized access to sensitive data, '
                    'identity theft, and privilege escalation.'
                ),
                remediation=[
                    'Implement multi-factor authentication (MFA)',
                    'Use strong password policies',
                    'Implement rate limiting on authentication endpoints',
                    'Use secure session management',
                    'Invalidate tokens after logout',
                    'Implement proper credential storage (bcrypt, Argon2)',
                    'Use OAuth 2.0 or OpenID Connect for third-party auth'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/',
                    'https://cwe.mitre.org/data/definitions/287.html'
                ],
                cvss_base=9.1
            ),

            'Excessive_Data_Exposure': VulnerabilityInfo(
                name='Excessive Data Exposure',
                cwe_id='CWE-213',
                cwe_name='Exposure of Sensitive Information Due to Incompatible Policies',
                owasp_category='API3:2023 - Broken Object Property Level Authorization',
                severity='HIGH',
                description=(
                    'APIs tend to expose more data than necessary, relying on clients to '
                    'perform data filtering. Attackers can intercept traffic and access '
                    'sensitive data not intended for them.'
                ),
                impact=(
                    'Exposure of sensitive user data, PII, credentials, or business logic. '
                    'Can lead to identity theft, fraud, or competitive disadvantage.'
                ),
                remediation=[
                    'Never rely on client-side filtering',
                    'Implement response filtering at the API level',
                    'Use data transfer objects (DTOs)',
                    'Return only necessary data for each endpoint',
                    'Implement field-level authorization',
                    'Review and minimize data exposure regularly'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/',
                    'https://cwe.mitre.org/data/definitions/213.html'
                ],
                cvss_base=7.5
            ),

            'Rate_Limit': VulnerabilityInfo(
                name='Lack of Resources & Rate Limiting',
                cwe_id='CWE-770',
                cwe_name='Allocation of Resources Without Limits or Throttling',
                owasp_category='API4:2023 - Unrestricted Resource Consumption',
                severity='MEDIUM',
                description=(
                    'APIs often don\'t impose restrictions on the size or number of resources '
                    'that can be requested, leading to denial of service or excessive billing.'
                ),
                impact=(
                    'Denial of service, server downtime, excessive costs, degraded performance '
                    'for legitimate users, and potential data extraction through automated scraping.'
                ),
                remediation=[
                    'Implement rate limiting per user/IP',
                    'Set maximum request payload sizes',
                    'Implement timeout controls',
                    'Use API gateways with rate limiting',
                    'Monitor and alert on unusual usage patterns',
                    'Implement CAPTCHA for public endpoints',
                    'Use backoff strategies for retries'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/',
                    'https://cwe.mitre.org/data/definitions/770.html'
                ],
                cvss_base=6.5
            ),

            'BFLA': VulnerabilityInfo(
                name='Broken Function Level Authorization',
                cwe_id='CWE-285',
                cwe_name='Improper Authorization',
                owasp_category='API5:2023 - Broken Function Level Authorization',
                severity='HIGH',
                description=(
                    'Complex access control policies with different hierarchies and roles '
                    'make it easy to introduce authorization flaws. Attackers can exploit '
                    'these flaws to access unauthorized functionality.'
                ),
                impact=(
                    'Unauthorized access to administrative functions, privilege escalation, '
                    'ability to modify/delete critical data, and system compromise.'
                ),
                remediation=[
                    'Implement proper role-based access control (RBAC)',
                    'Deny all access by default',
                    'Validate user roles for every function',
                    'Use centralized authorization logic',
                    'Implement least privilege principle',
                    'Test authorization logic thoroughly',
                    'Review admin functions regularly'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
                    'https://cwe.mitre.org/data/definitions/285.html'
                ],
                cvss_base=8.3
            ),

            'Mass_Assignment': VulnerabilityInfo(
                name='Mass Assignment',
                cwe_id='CWE-915',
                cwe_name='Improperly Controlled Modification of Dynamically-Determined Object Attributes',
                owasp_category='API6:2023 - Unrestricted Access to Sensitive Business Flows',
                severity='MEDIUM',
                description=(
                    'APIs automatically bind client input to internal objects without proper '
                    'filtering, allowing attackers to modify object properties they shouldn\'t '
                    'have access to.'
                ),
                impact=(
                    'Privilege escalation, data tampering, bypass of security mechanisms, '
                    'and unauthorized modification of sensitive properties.'
                ),
                remediation=[
                    'Use allow-lists of properties that can be updated',
                    'Implement explicit property binding',
                    'Use data transfer objects (DTOs)',
                    'Disable automatic binding in frameworks',
                    'Validate and sanitize all input',
                    'Use schema validation',
                    'Implement property-level access controls'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/',
                    'https://cwe.mitre.org/data/definitions/915.html'
                ],
                cvss_base=6.5
            ),

            'Security_Misconfiguration': VulnerabilityInfo(
                name='Security Misconfiguration',
                cwe_id='CWE-16',
                cwe_name='Configuration',
                owasp_category='API7:2023 - Server Side Request Forgery',
                severity='MEDIUM',
                description=(
                    'APIs and systems supporting them are often complex and misconfigured, '
                    'leaving them vulnerable to attacks.'
                ),
                impact=(
                    'Exposure of sensitive data, unauthorized access, full server compromise, '
                    'and exploitation of known vulnerabilities.'
                ),
                remediation=[
                    'Implement security hardening procedures',
                    'Remove unnecessary features and frameworks',
                    'Keep all components updated',
                    'Use security headers (HSTS, CSP, etc.)',
                    'Disable directory listings',
                    'Use strong TLS configurations',
                    'Implement automated security scanning',
                    'Use infrastructure as code for consistency'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/',
                    'https://cwe.mitre.org/data/definitions/16.html'
                ],
                cvss_base=7.5
            ),

            'Injection': VulnerabilityInfo(
                name='Injection',
                cwe_id='CWE-77',
                cwe_name='Improper Neutralization of Special Elements',
                owasp_category='API8:2023 - Security Misconfiguration',
                severity='CRITICAL',
                description=(
                    'Injection flaws occur when untrusted data is sent to an interpreter '
                    'as part of a command or query. Common types include SQL, NoSQL, LDAP, '
                    'OS command, and XML injection.'
                ),
                impact=(
                    'Data loss, data corruption, disclosure of sensitive data, denial of access, '
                    'complete system compromise, and remote code execution.'
                ),
                remediation=[
                    'Use parameterized queries and prepared statements',
                    'Implement input validation with allow-lists',
                    'Use ORM frameworks properly',
                    'Escape special characters',
                    'Implement principle of least privilege for databases',
                    'Use static analysis tools (SAST)',
                    'Implement web application firewalls (WAF)',
                    'Never concatenate user input into queries'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/',
                    'https://cwe.mitre.org/data/definitions/77.html',
                    'https://cwe.mitre.org/data/definitions/89.html',
                    'https://cwe.mitre.org/data/definitions/78.html'
                ],
                cvss_base=9.3
            ),

            'Improper_Assets_Management': VulnerabilityInfo(
                name='Improper Assets Management',
                cwe_id='CWE-1059',
                cwe_name='Incomplete Documentation',
                owasp_category='API9:2023 - Improper Inventory Management',
                severity='MEDIUM',
                description=(
                    'APIs often expose more endpoints than intended due to modern concepts '
                    'like microservices. Old API versions may remain accessible and unpatched.'
                ),
                impact=(
                    'Exposure of sensitive data through deprecated endpoints, access to '
                    'unpatched vulnerabilities, and unauthorized access through forgotten endpoints.'
                ),
                remediation=[
                    'Maintain API inventory and documentation',
                    'Implement API versioning strategy',
                    'Deprecate and remove old API versions',
                    'Use API gateways to control access',
                    'Document all APIs and endpoints',
                    'Implement automated discovery of endpoints',
                    'Regular security audits of all API versions'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/',
                    'https://cwe.mitre.org/data/definitions/1059.html'
                ],
                cvss_base=6.5
            ),

            'Insufficient_Logging': VulnerabilityInfo(
                name='Insufficient Logging & Monitoring',
                cwe_id='CWE-778',
                cwe_name='Insufficient Logging',
                owasp_category='API10:2023 - Unsafe Consumption of APIs',
                severity='LOW',
                description=(
                    'Insufficient logging and monitoring, coupled with missing or ineffective '
                    'integration with incident response, allows attackers to persist and pivot '
                    'to other systems.'
                ),
                impact=(
                    'Delayed detection of breaches, inability to perform forensics, '
                    'compliance violations, and extended attacker presence.'
                ),
                remediation=[
                    'Log all authentication and authorization events',
                    'Log all input validation failures',
                    'Implement centralized logging',
                    'Use security information and event management (SIEM)',
                    'Implement real-time monitoring and alerting',
                    'Establish incident response procedures',
                    'Regular log review and analysis',
                    'Ensure logs are tamper-proof'
                ],
                references=[
                    'https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/',
                    'https://cwe.mitre.org/data/definitions/778.html'
                ],
                cvss_base=4.0
            ),

            # Additional Common Vulnerabilities

            'SSRF': VulnerabilityInfo(
                name='Server-Side Request Forgery (SSRF)',
                cwe_id='CWE-918',
                cwe_name='Server-Side Request Forgery',
                owasp_category='API7:2023 - Server Side Request Forgery',
                severity='HIGH',
                description=(
                    'SSRF flaws occur when an API fetches a remote resource without validating '
                    'the user-supplied URL. Attackers can force the application to send requests '
                    'to unintended locations.'
                ),
                impact=(
                    'Internal network scanning, access to internal services, reading local files, '
                    'cloud metadata exposure (AWS, Azure, GCP), and potential RCE.'
                ),
                remediation=[
                    'Validate and sanitize all URLs',
                    'Use allow-lists of permitted domains',
                    'Disable HTTP redirections',
                    'Implement network segmentation',
                    'Use firewall rules to restrict outbound traffic',
                    'Never expose URL parameters directly',
                    'Validate response content types'
                ],
                references=[
                    'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
                    'https://cwe.mitre.org/data/definitions/918.html'
                ],
                cvss_base=8.6
            ),

            'JWT_Vulnerability': VulnerabilityInfo(
                name='JWT Security Issues',
                cwe_id='CWE-347',
                cwe_name='Improper Verification of Cryptographic Signature',
                owasp_category='API2:2023 - Broken Authentication',
                severity='CRITICAL',
                description=(
                    'JSON Web Tokens can be vulnerable to various attacks including algorithm '
                    'confusion, weak secrets, and missing signature verification.'
                ),
                impact=(
                    'Authentication bypass, privilege escalation, account takeover, '
                    'and unauthorized access to protected resources.'
                ),
                remediation=[
                    'Always verify JWT signatures',
                    'Use strong secrets (256+ bits)',
                    'Explicitly specify allowed algorithms',
                    'Never use "none" algorithm in production',
                    'Implement token expiration',
                    'Use refresh tokens properly',
                    'Validate all JWT claims',
                    'Store secrets securely'
                ],
                references=[
                    'https://tools.ietf.org/html/rfc7519',
                    'https://cwe.mitre.org/data/definitions/347.html',
                    'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/'
                ],
                cvss_base=9.1
            ),

            'XXE': VulnerabilityInfo(
                name='XML External Entity (XXE)',
                cwe_id='CWE-611',
                cwe_name='Improper Restriction of XML External Entity Reference',
                owasp_category='API8:2023 - Security Misconfiguration',
                severity='HIGH',
                description=(
                    'Many older or poorly configured XML processors evaluate external entity '
                    'references within XML documents, leading to information disclosure, SSRF, '
                    'or denial of service.'
                ),
                impact=(
                    'Disclosure of internal files, internal port scanning, remote code execution, '
                    'and denial of service attacks.'
                ),
                remediation=[
                    'Disable XML external entities in all parsers',
                    'Use less complex data formats (JSON)',
                    'Patch or upgrade XML processors',
                    'Implement input validation',
                    'Use SOAP version 1.2 or higher',
                    'Enable WAF protections'
                ],
                references=[
                    'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                    'https://cwe.mitre.org/data/definitions/611.html'
                ],
                cvss_base=8.2
            ),

            'CORS_Misconfiguration': VulnerabilityInfo(
                name='CORS Misconfiguration',
                cwe_id='CWE-346',
                cwe_name='Origin Validation Error',
                owasp_category='API8:2023 - Security Misconfiguration',
                severity='MEDIUM',
                description=(
                    'Cross-Origin Resource Sharing (CORS) misconfigurations can allow '
                    'unauthorized domains to access sensitive data or functionality.'
                ),
                impact=(
                    'Data theft, unauthorized API access from malicious sites, '
                    'and bypass of same-origin policy protections.'
                ),
                remediation=[
                    'Never use "Access-Control-Allow-Origin: *" with credentials',
                    'Validate origin against allow-list',
                    'Avoid reflecting the Origin header',
                    'Implement proper preflight handling',
                    'Use credentials carefully',
                    'Avoid wildcard subdomains in origins'
                ],
                references=[
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
                    'https://cwe.mitre.org/data/definitions/346.html'
                ],
                cvss_base=6.5
            )
        }

    def get_vulnerability(self, vuln_type: str) -> Optional[VulnerabilityInfo]:
        """
        Get vulnerability information by type.

        Args:
            vuln_type: Vulnerability type identifier

        Returns:
            VulnerabilityInfo object or None if not found
        """
        return self.vulnerabilities.get(vuln_type)

    def search_by_cwe(self, cwe_id: str) -> List[VulnerabilityInfo]:
        """
        Search vulnerabilities by CWE ID.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")

        Returns:
            List of matching vulnerabilities
        """
        return [
            vuln for vuln in self.vulnerabilities.values()
            if vuln.cwe_id == cwe_id
        ]

    def search_by_owasp(self, owasp_category: str) -> List[VulnerabilityInfo]:
        """
        Search vulnerabilities by OWASP category.

        Args:
            owasp_category: OWASP category

        Returns:
            List of matching vulnerabilities
        """
        return [
            vuln for vuln in self.vulnerabilities.values()
            if owasp_category.lower() in vuln.owasp_category.lower()
        ]

    def get_by_severity(self, severity: str) -> List[VulnerabilityInfo]:
        """
        Get all vulnerabilities of a specific severity.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

        Returns:
            List of vulnerabilities
        """
        return [
            vuln for vuln in self.vulnerabilities.values()
            if vuln.severity.upper() == severity.upper()
        ]

    def get_all(self) -> List[VulnerabilityInfo]:
        """Get all vulnerabilities in the database."""
        return list(self.vulnerabilities.values())

    def export_json(self, output_path: str):
        """
        Export database to JSON file.

        Args:
            output_path: Path to output file
        """
        data = {
            vuln_type: {
                'name': vuln.name,
                'cwe_id': vuln.cwe_id,
                'cwe_name': vuln.cwe_name,
                'owasp_category': vuln.owasp_category,
                'severity': vuln.severity,
                'description': vuln.description,
                'impact': vuln.impact,
                'remediation': vuln.remediation,
                'references': vuln.references,
                'cvss_base': vuln.cvss_base
            }
            for vuln_type, vuln in self.vulnerabilities.items()
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    def get_statistics(self) -> Dict[str, int]:
        """
        Get statistics about the vulnerability database.

        Returns:
            Dictionary with statistics
        """
        stats = {
            'total': len(self.vulnerabilities),
            'by_severity': {},
            'by_owasp': {}
        }

        # Count by severity
        for vuln in self.vulnerabilities.values():
            severity = vuln.severity
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            # Count by OWASP category
            owasp = vuln.owasp_category.split(':')[0]  # Get API1, API2, etc.
            stats['by_owasp'][owasp] = stats['by_owasp'].get(owasp, 0) + 1

        return stats
