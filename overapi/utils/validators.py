"""Enhanced validators for security checks with multiple detection strategies."""

import re
import json
from typing import List, Tuple, Dict
from html.parser import HTMLParser
from urllib.parse import quote


class XSSPayloadDetector(HTMLParser):
    """HTML parser for detecting XSS payloads in different contexts."""

    def __init__(self):
        super().__init__()
        self.found_script = False
        self.found_event = False
        self.found_dangerous_tag = False


class Validators:
    """Enhanced validation utilities for security testing."""

    # ============ SQL INJECTION DETECTION ============

    @staticmethod
    def is_sql_injection(response: str, test_payload: str, response_time: float = None) -> bool:
        """
        Check if response indicates SQL injection vulnerability.
        Uses error-based and blind detection methods.

        Args:
            response: Response content
            test_payload: Payload used in test
            response_time: Response time in seconds (for time-based blind detection)

        Returns:
            True if SQL injection is likely
        """
        # Error-based SQL injection detection
        sql_error_patterns = [
            r"(?i)(sql|mysql|postgresql|oracle|sql server|mariadb).*error",
            r"(?i)syntax error",
            r"(?i)database error",
            r"(?i)unknown column",
            r"(?i)incorrect syntax",
            r"(?i)sql exception",
            r"(?i)constraint violation",
            r"(?i)integrity check failed",
            r"(?i)ORA-\d+",  # Oracle error codes
            r"(?i)SQL\d+",   # MSSQL error codes
            r"(?i)errno:\s*\d+",  # MySQL error codes
            r"(?i)Warning.*mysql",
            r"(?i)Warning.*mysqli",
            r"(?i)Warning.*PostgreSQL",
            r"(?i)FATAL.*PostgreSQL",
            r"(?i)Exception.*java\.sql",
            r"(?i)OleDbException",
            r"(?i)MySQLSyntaxErrorException",
            r"(?i)SQLServerException",
        ]

        for pattern in sql_error_patterns:
            if re.search(pattern, response):
                return True

        # Time-based blind SQLi detection (very long response time)
        if response_time and response_time > 5:
            return True

        # Boolean-based blind detection (check for payload reflection in logic)
        if "' OR '1'='1" in test_payload or "1' OR '1'='1" in test_payload:
            # Check if response suggests boolean difference
            if re.search(r"(?i)(true|false|yes|no|on|off|1|0)", response):
                return True

        return False

    # ============ NoSQL INJECTION DETECTION ============

    @staticmethod
    def is_nosql_injection(response: str, test_payload: str) -> bool:
        """
        Check if response indicates NoSQL injection vulnerability.

        Args:
            response: Response content
            test_payload: Payload used in test

        Returns:
            True if NoSQL injection is likely
        """
        nosql_patterns = [
            r"(?i)mongodb.*error",
            r"(?i)mongo.*exception",
            r"(?i)no results?",
            r"(?i)SyntaxError",
            r"(?i)E_PARSE",
            r'{\s*"\$ne"',
            r'{\s*"\$gt"',
            r'{\s*"\$regex"',
            r'{\s*"\$or"',
            r'{\s*"\$where"',
        ]

        for pattern in nosql_patterns:
            if re.search(pattern, response):
                return True

        # Try to parse as JSON and check for unusual structures
        try:
            data = json.loads(response)
            # Check for NoSQL injection indicators in JSON
            if isinstance(data, dict):
                for key in data:
                    if key.startswith('$'):
                        return True
        except:
            pass

        return False

    # ============ XSS DETECTION ============

    @staticmethod
    def is_xss(response: str, test_payload: str, context: str = "html") -> bool:
        """
        Check if response indicates XSS vulnerability.
        Uses context-aware detection for HTML, JavaScript, and URL contexts.

        Args:
            response: Response content
            test_payload: Payload used in test
            context: Context type (html, js, url, css)

        Returns:
            True if XSS is likely
        """
        # Direct payload reflection (unencoded)
        if test_payload in response and '<' in test_payload:
            # Check if it's actually in HTML context
            return True

        # HTML context detection
        if context in ("html", "all"):
            html_xss_patterns = [
                r"<script[^>]*>.*?</script>",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>",
                r"<img[^>]*onerror\s*=",
                r"<svg[^>]*onload\s*=",
                r'on\w+\s*=\s*["\']?[^"\'>]*["\']?',
                r"javascript:",
                r"data:text/html",
                r"vbscript:",
            ]

            for pattern in html_xss_patterns:
                if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                    return True

        # JavaScript context detection
        if context in ("js", "all"):
            js_patterns = [
                r'["\']\s*\+\s*["\']*alert',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\(',
                r'location\s*=',
                r'document\.write\s*\(',
                r'innerHTML\s*=',
            ]

            for pattern in js_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return True

        # URL context detection
        if context in ("url", "all"):
            url_patterns = [
                r"javascript:",
                r"data:text/html",
                r"vbscript:",
            ]

            for pattern in url_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return True

        # Check for encoded payload that matches original
        encoded_variations = [
            test_payload.replace('<', '%3C').replace('>', '%3E'),
            test_payload.replace('<', '&lt;').replace('>', '&gt;'),
            test_payload.replace('"', '&quot;'),
            test_payload.replace("'", '&#x27;'),
        ]

        for variant in encoded_variations:
            if variant in response:
                return False  # Properly encoded, not XSS

        return False

    # ============ XXE DETECTION ============

    @staticmethod
    def is_xxe(response: str, test_payload: str = None) -> bool:
        """
        Check if response indicates XXE vulnerability.

        Args:
            response: Response content
            test_payload: Optional payload used in test

        Returns:
            True if XXE is likely
        """
        xxe_patterns = [
            r"(?i)<!entity",
            r"(?i)<!doctype.*\[",
            r"(?i)systemid",
            r"(?i)publicid",
            r"(?i)<!element",
            r"(?i)system:",
            r"(?i)\/etc\/passwd",
            r"(?i)root:[x0-9]+:",  # /etc/passwd content
            r"(?i)c:\\windows\\",
            r"(?i)\\Users\\",
            r"(?i)WARNING.*simplexml",
            r"(?i)expected.*but found",
            r"(?i)XML.*error",
            r"(?i)entity.*not allowed",
        ]

        for pattern in xxe_patterns:
            if re.search(pattern, response):
                return True

        # Check for file disclosure in response
        if re.search(r"(?i)(root|admin|user):[x*]:", response):
            return True

        return False

    # ============ COMMAND INJECTION DETECTION ============

    @staticmethod
    def is_command_injection(response: str, test_payload: str = None) -> bool:
        """
        Check if response indicates command injection.

        Args:
            response: Response content
            test_payload: Optional payload used in test

        Returns:
            True if command injection is likely
        """
        patterns = [
            r"(?i)command not found",
            r"(?i)permission denied",
            r"(?i)no such file",
            r"(?i)sh: \d+:",
            r"(?i)/bin/(bash|sh|cmd)",
            r"(?i)cmd\.exe",
            r"(?i)unknown user",
            r"(?i)root:[x*]:",  # /etc/passwd content
            r"(?i)bin/bash",
            r"(?i)bin/sh",
            r"(?i)bash: line \d+:",
            r"(?i)Error: command",
            r"(?i)fatal: command",
        ]

        for pattern in patterns:
            if re.search(pattern, response):
                return True

        return False

    # ============ PATH TRAVERSAL DETECTION ============

    @staticmethod
    def is_path_traversal(response: str, test_payload: str = None) -> bool:
        """
        Check if response indicates path traversal.

        Args:
            response: Response content
            test_payload: Optional payload used in test

        Returns:
            True if path traversal is likely
        """
        file_patterns = [
            r"(?i)\/etc\/passwd",
            r"(?i)\/etc\/shadow",
            r"(?i)\/etc\/hosts",
            r"(?i)\/root\/",
            r"(?i)\/home\/",
            r"(?i)\/var\/www",
            r"(?i)c:\\windows",
            r"(?i)c:\\users",
            r"(?i)c:\\winnt",
            r"(?i)\\windows\\",
            r"(?i)\\system32",
            r"root:[x*]:",
            r"<?php",
            r"<?xml",
        ]

        for pattern in file_patterns:
            if re.search(pattern, response):
                return True

        return False

    # ============ AUTHENTICATION BYPASS DETECTION ============

    @staticmethod
    def is_authentication_bypass(status_code: int, expected_code: int = 401,
                                response_headers: Dict = None) -> bool:
        """
        Check if authentication might be bypassed.

        Args:
            status_code: Response status code
            expected_code: Expected unauthorized code
            response_headers: Response headers dict

        Returns:
            True if authentication might be bypassed
        """
        success_codes = [200, 201, 204]

        if status_code in success_codes:
            # Check for auth-related headers that shouldn't be there
            if response_headers:
                # Presence of these headers on success might indicate bypass
                auth_headers = ['authorization', 'x-api-key', 'x-auth-token']
                for header in auth_headers:
                    if header in [h.lower() for h in response_headers.keys()]:
                        return True
            return True

        return False

    # ============ JWT VULNERABILITIES DETECTION ============

    @staticmethod
    def is_jwt_vulnerable(token: str, response: str = None) -> Tuple[bool, List[str]]:
        """
        Check if JWT token has known vulnerabilities.

        Args:
            token: JWT token string
            response: Optional response content

        Returns:
            Tuple of (is_vulnerable, vulnerability_list)
        """
        vulnerabilities = []

        # Check JWT format
        parts = token.split('.')
        if len(parts) != 3:
            return False, []

        try:
            import base64
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            # Check for "none" algorithm
            if header.get('alg') == 'none':
                vulnerabilities.append('JWT uses "none" algorithm')

            # Check for weak algorithms
            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                vulnerabilities.append(f'Weak algorithm: {header.get("alg")}')

            # Check for missing expiration
            if 'exp' not in payload:
                vulnerabilities.append('JWT missing expiration')

            # Check for key disclosure in response
            if response and header.get('alg', '').startswith('HS'):
                if 'secret' in response.lower() or 'key' in response.lower():
                    vulnerabilities.append('Potential key disclosure')

        except Exception:
            return False, []

        return len(vulnerabilities) > 0, vulnerabilities

    # ============ PRIVILEGE ESCALATION DETECTION ============

    @staticmethod
    def is_privilege_escalation(response: str, admin_indicators: List[str] = None) -> bool:
        """
        Check if response indicates privilege escalation.

        Args:
            response: Response content
            admin_indicators: Indicators of admin/elevated access

        Returns:
            True if privilege escalation is likely
        """
        if admin_indicators is None:
            admin_indicators = [
                "admin", "administrator", "root", "superuser", "elevated",
                "sudo", "uid=0", "gid=0", "is_admin", "role.*admin"
            ]

        for indicator in admin_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                return True

        return False

    # ============ SENSITIVE DATA EXPOSURE DETECTION ============

    @staticmethod
    def is_sensitive_data_exposure(response: str) -> Tuple[bool, List[str]]:
        """
        Check if response contains sensitive data.

        Args:
            response: Response content

        Returns:
            Tuple of (found_sensitive_data, data_types_found)
        """
        found_types = []
        sensitive_patterns = {
            'password': r"(?i)password\s*[:=\s\"\']+[^\s\"\']{6,}",
            'api_key': r"(?i)api[_-]?key\s*[:=\s\"\']+[a-zA-Z0-9]{20,}",
            'private_key': r"(?i)private[_-]?key\s*[:=]|-----BEGIN.*PRIVATE",
            'secret': r"(?i)secret\s*[:=\s\"\']+[^\s\"\']{8,}",
            'token': r"(?i)(token|auth|bearer)\s*[:=\s\"\']+[a-zA-Z0-9\._\-]{20,}",
            'credit_card': r"\b\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}\b",
            'ssn': r"\b\d{3}[_\-]?\d{2}[_\-]?\d{4}\b",
            'phone': r"(?i)phone\s*[:=\s\"\']+\+?[\d\s\-\(\)]{10,}",
            'email': r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            'database_url': r"(?i)(mysql|postgres|mongodb|redis)://[^\s\"\']+",
            'aws_key': r"AKIA[0-9A-Z]{16}",
            'github_token': r"ghp_[a-zA-Z0-9]{36,255}",
        }

        for data_type, pattern in sensitive_patterns.items():
            if re.search(pattern, response):
                found_types.append(data_type)

        return len(found_types) > 0, found_types

    # ============ RATE LIMITING DETECTION ============

    @staticmethod
    def is_rate_limited(status_code: int, headers: Dict = None) -> bool:
        """
        Check if rate limiting is detected.

        Args:
            status_code: Response status code
            headers: Response headers dict

        Returns:
            True if rate limited
        """
        if status_code in [429, 503, 509]:
            return True

        # Check for rate limit headers
        if headers:
            rate_limit_headers = [
                'x-ratelimit-limit',
                'x-ratelimit-remaining',
                'x-ratelimit-reset',
                'retry-after',
                'x-rate-limit-limit',
                'x-rate-limit-remaining',
            ]

            for header in rate_limit_headers:
                if any(header.lower() == h.lower() for h in headers.keys()):
                    # Check if limit is reached
                    remaining = headers.get(header) or headers.get(header.upper())
                    if remaining and remaining == '0':
                        return True

        return False

    # ============ CORS MISCONFIGURATION DETECTION ============

    @staticmethod
    def is_cors_misconfigured(headers: Dict, origin: str = "*") -> Tuple[bool, str]:
        """
        Check if CORS is misconfigured.

        Args:
            headers: Response headers
            origin: Requested origin

        Returns:
            Tuple of (is_misconfigured, vulnerability_type)
        """
        cors_origin = headers.get('Access-Control-Allow-Origin')
        cors_methods = headers.get('Access-Control-Allow-Methods')
        cors_headers = headers.get('Access-Control-Allow-Headers')
        cors_creds = headers.get('Access-Control-Allow-Credentials')

        if cors_origin:
            # Wildcard origin
            if cors_origin == '*':
                return True, "Wildcard CORS origin"

            # Reflection of any origin
            if origin and cors_origin == origin:
                if cors_creds == 'true':
                    return True, "CORS allows credentials with reflection"

        # Allow all methods
        if cors_methods and '*' in cors_methods:
            return True, "CORS allows all methods"

        # Allow all headers
        if cors_headers and '*' in cors_headers:
            return True, "CORS allows all headers"

        return False, ""

    # ============ SECURITY HEADER DETECTION ============

    @staticmethod
    def is_missing_security_header(headers: Dict) -> Tuple[bool, List[str]]:
        """
        Check for missing security headers.

        Args:
            headers: Response headers

        Returns:
            Tuple of (has_missing, missing_headers)
        """
        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'Content-Type sniffing',
            'X-Frame-Options': 'Clickjacking',
            'X-XSS-Protection': 'XSS protection',
            'Content-Security-Policy': 'CSP',
            'Referrer-Policy': 'Referrer policy',
        }

        missing = []
        header_lower = {k.lower(): v for k, v in headers.items()}

        for header, description in required_headers.items():
            if header.lower() not in header_lower:
                missing.append(f"{header} (prevents {description})")

        return len(missing) > 0, missing

    # ============ INSECURE DESERIALIZATION DETECTION ============

    @staticmethod
    def is_insecure_deserialization(response: str) -> bool:
        """
        Check for insecure deserialization indicators.

        Args:
            response: Response content

        Returns:
            True if insecure deserialization likely
        """
        patterns = [
            r"(?i)pickle\.",
            r"(?i)java\.io\.(Object|Serializable)",
            r"(?i)unserialize",
            r"(?i)deserialize",
            r"(?i)O:(\d+):",  # PHP serialized object
            r"(?i)a:(\d+):{",  # PHP serialized array
            r"(?i)Exception.*Serializable",
            r"(?i)IllegalAccessException",
            r"(?i)ClassNotFoundException",
        ]

        for pattern in patterns:
            if re.search(pattern, response):
                return True

        return False

    # ============ MASS ASSIGNMENT DETECTION ============

    @staticmethod
    def is_mass_assignment_vulnerable(param: str, response: str = None) -> bool:
        """
        Check if endpoint is vulnerable to mass assignment.

        Args:
            param: Parameter name tested
            response: Response content

        Returns:
            True if mass assignment likely
        """
        sensitive_params = [
            'is_admin', 'admin', 'role', 'is_premium', 'price',
            'discount', 'subscription_level', 'is_verified',
            'permissions', 'access_level', 'is_moderator'
        ]

        return any(sensitive in param.lower() for sensitive in sensitive_params)

    # ============ UNSAFE REDIRECT DETECTION ============

    @staticmethod
    def is_unsafe_redirect(location: str, original_url: str) -> bool:
        """
        Check if redirect is unsafe.

        Args:
            location: Redirect location header
            original_url: Original request URL

        Returns:
            True if redirect is potentially unsafe
        """
        if not location:
            return False

        dangerous_patterns = [
            r"javascript:",
            r"data:",
            r"vbscript:",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, location, re.IGNORECASE):
                return True

        # Check if redirecting to external domain
        from urllib.parse import urlparse
        try:
            original_domain = urlparse(original_url).netloc
            redirect_domain = urlparse(location).netloc

            if redirect_domain and redirect_domain != original_domain:
                return True
        except:
            pass

        return False
