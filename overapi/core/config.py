"""Configuration management for OverApi."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict
from enum import Enum


class ScanMode(Enum):
    """Scan mode enumeration."""
    SAFE = "safe"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    http: Optional[str] = None
    https: Optional[str] = None
    socks5: Optional[str] = None

    def get_proxies(self) -> Dict[str, str]:
        """Get proxy dictionary for requests."""
        proxies = {}
        if self.http:
            proxies['http'] = self.http
        if self.https:
            proxies['https'] = self.https
        return proxies if proxies else None


@dataclass
class Config:
    """Main configuration class for OverApi."""

    # Target configuration
    url: str
    api_type: Optional[str] = None

    # Scanning options
    mode: ScanMode = ScanMode.NORMAL
    threads: int = 10
    timeout: int = 30
    follow_redirects: bool = True

    # Security options
    verify_ssl: bool = True
    proxy: Optional[ProxyConfig] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_ca_path: Optional[str] = None
    certificate_pinning: Dict[str, List[str]] = field(default_factory=dict)

    # Output options
    output_html: Optional[str] = None
    output_json: Optional[str] = None
    output_dir: str = "./reports"
    log_file: Optional[str] = None

    # Scanning scope
    include_modules: List[str] = field(default_factory=lambda: [
        "rest", "graphql", "soap", "grpc", "websocket", "webhook"
    ])
    wordlist: Optional[str] = None
    max_endpoints: int = 1000

    # Features
    verbose: bool = False
    enable_fuzzing: bool = True
    enable_injection_tests: bool = True
    enable_ratelimit_tests: bool = True
    enable_bola_tests: bool = True

    def __post_init__(self):
        """Validate configuration after initialization with comprehensive checks."""
        # URL validation
        if not self.url:
            raise ValueError("URL is required")

        self.url = self.url.strip()

        # Validate URL format
        from urllib.parse import urlparse
        try:
            parsed = urlparse(self.url)
            if not parsed.scheme:
                raise ValueError(f"URL must include scheme (http:// or https://): {self.url}")
            if parsed.scheme not in ['http', 'https', 'ws', 'wss']:
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Must be http, https, ws, or wss")
            if not parsed.netloc:
                raise ValueError(f"Invalid URL format: {self.url}")
        except Exception as e:
            raise ValueError(f"Invalid URL format: {self.url}. Error: {str(e)}")

        # Threads validation
        if not isinstance(self.threads, int):
            raise TypeError("Threads must be an integer")
        if self.threads < 1:
            raise ValueError("Threads must be >= 1")
        if self.threads > 200:
            raise ValueError("Threads must be <= 200 (too many threads can cause issues)")

        # Timeout validation
        if not isinstance(self.timeout, int):
            raise TypeError("Timeout must be an integer")
        if self.timeout < 1:
            raise ValueError("Timeout must be >= 1 second")
        if self.timeout > 300:
            raise ValueError("Timeout must be <= 300 seconds")

        # Max endpoints validation
        if not isinstance(self.max_endpoints, int):
            raise TypeError("Max endpoints must be an integer")
        if self.max_endpoints < 1:
            raise ValueError("Max endpoints must be >= 1")
        if self.max_endpoints > 100000:
            raise ValueError("Max endpoints must be <= 100000")

        # Wordlist validation (if provided)
        if self.wordlist:
            from pathlib import Path
            wordlist_path = Path(self.wordlist)
            if not wordlist_path.exists():
                raise FileNotFoundError(f"Wordlist file not found: {self.wordlist}")
            if not wordlist_path.is_file():
                raise ValueError(f"Wordlist path is not a file: {self.wordlist}")
            # Check file size (warn if > 100MB)
            if wordlist_path.stat().st_size > 100 * 1024 * 1024:
                import warnings
                warnings.warn(f"Wordlist file is very large ({wordlist_path.stat().st_size / (1024*1024):.1f}MB). This may cause memory issues.")

        # Custom CA path validation (if provided)
        if self.custom_ca_path:
            from pathlib import Path
            ca_path = Path(self.custom_ca_path)
            if not ca_path.exists():
                raise FileNotFoundError(f"Custom CA certificate file not found: {self.custom_ca_path}")
            if not ca_path.is_file():
                raise ValueError(f"Custom CA path is not a file: {self.custom_ca_path}")

        # Output directory validation
        if self.output_dir:
            from pathlib import Path
            output_path = Path(self.output_dir)
            # Create directory if it doesn't exist
            try:
                output_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise ValueError(f"Cannot create output directory {self.output_dir}: {str(e)}")

        # Validate custom headers format
        if self.custom_headers:
            if not isinstance(self.custom_headers, dict):
                raise TypeError("Custom headers must be a dictionary")
            for key, value in self.custom_headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise TypeError(f"Header key and value must be strings: {key}={value}")

        # Validate include modules
        valid_modules = ["rest", "graphql", "soap", "grpc", "websocket", "webhook"]
        for module in self.include_modules:
            if module not in valid_modules:
                raise ValueError(f"Invalid module '{module}'. Valid modules: {valid_modules}")
