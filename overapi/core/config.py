"""Configuration management for OverApi using Pydantic."""

from typing import Optional, List, Dict
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ConfigDict
from pydantic_settings import BaseSettings
from pathlib import Path


class ScanMode(str, Enum):
    """Scan mode enumeration."""
    SAFE = "safe"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class ProxyConfig(BaseModel):
    """Proxy configuration with validation."""
    http: Optional[str] = None
    https: Optional[str] = None
    socks5: Optional[str] = None

    def get_proxies(self) -> Optional[Dict[str, str]]:
        """Get proxy dictionary for HTTP clients."""
        proxies = {}
        if self.http:
            proxies['http'] = self.http
        if self.https:
            proxies['https'] = self.https
        return proxies if proxies else None


class Config(BaseSettings):
    """
    Main configuration class for OverApi with Pydantic validation.

    Supports loading from environment variables and .env file.
    """
    model_config = ConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        env_prefix='OVERAPI_',
        extra='ignore'
    )

    # Target configuration
    url: str = Field(..., description="Target API URL (required)")
    api_type: Optional[str] = Field(None, description="Force API type detection")

    # Scanning options
    mode: ScanMode = Field(ScanMode.NORMAL, description="Scan mode")
    threads: int = Field(100, ge=1, le=1000, description="Concurrency level (1-1000)")
    timeout: int = Field(30, ge=1, le=300, description="Request timeout in seconds (1-300)")
    follow_redirects: bool = Field(True, description="Follow HTTP redirects")

    # Security options
    verify_ssl: bool = Field(True, description="Verify SSL certificates")
    proxy: Optional[ProxyConfig] = Field(None, description="Proxy configuration")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    custom_ca_path: Optional[str] = Field(None, description="Path to custom CA certificate bundle")
    certificate_pinning: Dict[str, List[str]] = Field(default_factory=dict, description="Certificate pinning config")

    # Output options
    output_html: Optional[str] = Field(None, description="Output HTML report path")
    output_json: Optional[str] = Field(None, description="Output JSON report path")
    output_dir: str = Field("./reports", description="Output directory for reports")
    log_file: Optional[str] = Field(None, description="Log file path")

    # Scanning scope
    include_modules: List[str] = Field(
        default_factory=lambda: ["rest", "graphql", "soap", "grpc", "websocket", "webhook"],
        description="API types to scan"
    )
    wordlist: Optional[str] = Field(None, description="Custom wordlist path")
    max_endpoints: int = Field(1000, ge=1, le=100000, description="Maximum endpoints to test (1-100000)")

    # Features
    verbose: bool = Field(False, description="Verbose output")
    enable_fuzzing: bool = Field(True, description="Enable fuzzing tests")
    enable_injection_tests: bool = Field(True, description="Enable injection tests")
    enable_ratelimit_tests: bool = Field(True, description="Enable rate limit tests")
    enable_bola_tests: bool = Field(True, description="Enable BOLA tests")

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format."""
        if not v or not v.strip():
            raise ValueError("URL is required and cannot be empty")

        v = v.strip()

        # Basic URL validation
        from urllib.parse import urlparse
        try:
            parsed = urlparse(v)
            if not parsed.scheme:
                raise ValueError(f"URL must include scheme (http:// or https://): {v}")
            if parsed.scheme not in ['http', 'https', 'ws', 'wss']:
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Must be http, https, ws, or wss")
            if not parsed.netloc:
                raise ValueError(f"Invalid URL format: {v}")
        except Exception as e:
            raise ValueError(f"Invalid URL format: {v}. Error: {str(e)}")

        return v

    @field_validator('wordlist')
    @classmethod
    def validate_wordlist(cls, v: Optional[str]) -> Optional[str]:
        """Validate wordlist file exists."""
        if v is None:
            return v

        wordlist_path = Path(v)
        if not wordlist_path.exists():
            raise FileNotFoundError(f"Wordlist file not found: {v}")
        if not wordlist_path.is_file():
            raise ValueError(f"Wordlist path is not a file: {v}")

        # Warn if file is very large (>100MB)
        if wordlist_path.stat().st_size > 100 * 1024 * 1024:
            import warnings
            size_mb = wordlist_path.stat().st_size / (1024 * 1024)
            warnings.warn(
                f"Wordlist file is very large ({size_mb:.1f}MB). This may cause memory issues.",
                UserWarning
            )

        return v

    @field_validator('custom_ca_path')
    @classmethod
    def validate_custom_ca(cls, v: Optional[str]) -> Optional[str]:
        """Validate custom CA certificate path."""
        if v is None:
            return v

        ca_path = Path(v)
        if not ca_path.exists():
            raise FileNotFoundError(f"Custom CA certificate file not found: {v}")
        if not ca_path.is_file():
            raise ValueError(f"Custom CA path is not a file: {v}")

        return v

    @field_validator('output_dir')
    @classmethod
    def validate_output_dir(cls, v: str) -> str:
        """Validate and create output directory."""
        output_path = Path(v)
        try:
            output_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise ValueError(f"Cannot create output directory {v}: {str(e)}")

        return v

    @field_validator('include_modules')
    @classmethod
    def validate_include_modules(cls, v: List[str]) -> List[str]:
        """Validate module names."""
        valid_modules = ["rest", "graphql", "soap", "grpc", "websocket", "webhook"]
        for module in v:
            if module not in valid_modules:
                raise ValueError(f"Invalid module '{module}'. Valid modules: {valid_modules}")
        return v

    @field_validator('custom_headers')
    @classmethod
    def validate_custom_headers(cls, v: Dict[str, str]) -> Dict[str, str]:
        """Validate custom headers format."""
        for key, value in v.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError(f"Header key and value must be strings: {key}={value}")
        return v

    def model_post_init(self, __context) -> None:
        """Post-initialization validation."""
        # Additional cross-field validation can go here
        pass
