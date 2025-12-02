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
        """Validate configuration after initialization."""
        if not self.url:
            raise ValueError("URL is required")
        if self.threads < 1:
            raise ValueError("Threads must be >= 1")
        if self.timeout < 1:
            raise ValueError("Timeout must be >= 1")
