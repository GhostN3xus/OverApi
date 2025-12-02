"""Validators for various security checks."""

import re
from typing import List, Tuple


class Validators:
    """Validation utilities for security testing."""

    @staticmethod
    def is_sql_injection(response: str, test_payload: str) -> bool:
        """
        Check if response indicates SQL injection vulnerability.

        Args:
            response: Response content
            test_payload: Payload used in test

        Returns:
            True if SQL injection is likely
        """
        sql_error_patterns = [
            r"(?i)(sql|mysql|postgresql|oracle|sql server)",
            r"(?i)syntax error",
            r"(?i)database error",
            r"(?i)unknown column",
            r"(?i)incorrect syntax",
            r"(?i)sql exception",
            r"(?i)constraint violation",
            r"(?i)integrity check failed",
        ]

        for pattern in sql_error_patterns:
            if re.search(pattern, response):
                return True

        return False

    @staticmethod
    def is_xss(response: str, test_payload: str) -> bool:
        """
        Check if response indicates XSS vulnerability.

        Args:
            response: Response content
            test_payload: Payload used in test

        Returns:
            True if XSS is likely
        """
        # Check if payload is reflected without encoding
        if test_payload in response:
            return True

        # Check for common XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onload\s*=",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    @staticmethod
    def is_xxe(response: str) -> bool:
        """
        Check if response indicates XXE vulnerability.

        Args:
            response: Response content

        Returns:
            True if XXE is likely
        """
        xxe_patterns = [
            r"(?i)<!entity",
            r"(?i)<!doctype",
            r"(?i)xml.*declaration",
            r"(?i)file:\/\/",
            r"(?i)\/etc\/passwd",
        ]

        for pattern in xxe_patterns:
            if re.search(pattern, response):
                return True

        return False

    @staticmethod
    def is_command_injection(response: str) -> bool:
        """
        Check if response indicates command injection.

        Args:
            response: Response content

        Returns:
            True if command injection is likely
        """
        patterns = [
            r"(?i)command not found",
            r"(?i)permission denied",
            r"(?i)no such file",
            r"(?i)syntax error",
            r"(?i)unknown user",
            r"(?i)root:",  # /etc/passwd content
            r"(?i)bin/",   # /bin/bash, /bin/sh
        ]

        for pattern in patterns:
            if re.search(pattern, response):
                return True

        return False

    @staticmethod
    def is_path_traversal(response: str) -> bool:
        """
        Check if response indicates path traversal.

        Args:
            response: Response content

        Returns:
            True if path traversal is likely
        """
        patterns = [
            r"(?i)\/etc\/passwd",
            r"(?i)\/root\/",
            r"(?i)\/home\/",
            r"(?i)c:\\windows",
            r"(?i)c:\\users",
        ]

        for pattern in patterns:
            if re.search(pattern, response):
                return True

        return False

    @staticmethod
    def is_authentication_bypass(status_code: int, expected_code: int = 401) -> bool:
        """
        Check if authentication might be bypassed.

        Args:
            status_code: Response status code
            expected_code: Expected unauthorized code

        Returns:
            True if authentication might be bypassed
        """
        # If we get 200/201/204 instead of 401, might be bypass
        success_codes = [200, 201, 204]
        return status_code in success_codes

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
            admin_indicators = ["admin", "administrator", "root", "superuser", "elevated"]

        for indicator in admin_indicators:
            if indicator.lower() in response.lower():
                return True

        return False

    @staticmethod
    def is_sensitive_data_exposure(response: str) -> bool:
        """
        Check if response contains sensitive data.

        Args:
            response: Response content

        Returns:
            True if sensitive data is likely exposed
        """
        sensitive_patterns = [
            r"(?i)password\s*[:=]",
            r"(?i)api[_-]?key\s*[:=]",
            r"(?i)secret\s*[:=]",
            r"(?i)token\s*[:=]",
            r"(?i)credit[_-]?card",
            r"(?i)ssn",
            r"(?i)phone\s*[:=]",
            r"(?i)email\s*[:=]",
            r"(?i)private[_-]?key",
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, response):
                return True

        return False

    @staticmethod
    def is_rate_limited(status_code: int) -> bool:
        """
        Check if rate limiting is detected.

        Args:
            status_code: Response status code

        Returns:
            True if rate limited
        """
        return status_code in [429, 503, 509]
