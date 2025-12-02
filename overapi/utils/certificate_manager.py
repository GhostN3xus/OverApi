"""Advanced SSL/TLS certificate management with caching and pinning."""

import os
import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from datetime import datetime
import ssl
import certifi
from urllib.parse import urlparse

from ..core.logger import Logger
from ..core.exceptions import NetworkError


class CertificateManager:
    """Advanced certificate manager with pinning, caching, and validation."""

    def __init__(self, logger: Logger = None, cache_dir: Optional[str] = None):
        """
        Initialize certificate manager.

        Args:
            logger: Logger instance
            cache_dir: Directory for certificate caching (default: ~/.overapi/certs)
        """
        self.logger = logger or Logger(__name__)
        self.cache_dir = Path(cache_dir or os.path.expanduser("~/.overapi/certs"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.pinned_certs: Dict[str, List[str]] = {}
        self.certificate_cache: Dict[str, Dict] = {}
        self._load_pinned_certificates()

    def _load_pinned_certificates(self) -> None:
        """Load pinned certificates from configuration file."""
        pins_file = self.cache_dir / "pins.json"
        if pins_file.exists():
            try:
                with open(pins_file, 'r') as f:
                    self.pinned_certs = json.load(f)
                    self.logger.debug(f"Loaded {len(self.pinned_certs)} pinned certificate domains")
            except Exception as e:
                self.logger.warning(f"Failed to load pinned certificates: {str(e)}")

    def save_pinned_certificate(self, hostname: str, cert_hash: str) -> None:
        """
        Save a pinned certificate for a domain.

        Args:
            hostname: Domain name
            cert_hash: SHA-256 hash of the certificate
        """
        if hostname not in self.pinned_certs:
            self.pinned_certs[hostname] = []

        if cert_hash not in self.pinned_certs[hostname]:
            self.pinned_certs[hostname].append(cert_hash)
            self._persist_pins()
            self.logger.debug(f"Pinned certificate for {hostname}")

    def _persist_pins(self) -> None:
        """Persist pinned certificates to file."""
        pins_file = self.cache_dir / "pins.json"
        try:
            with open(pins_file, 'w') as f:
                json.dump(self.pinned_certs, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to persist certificate pins: {str(e)}")

    def get_ca_bundle(self) -> str:
        """Get path to CA bundle for SSL verification."""
        return certifi.where()

    def create_ssl_context(
        self,
        verify: bool = True,
        custom_ca_path: Optional[str] = None,
        check_hostname: bool = True
    ) -> ssl.SSLContext:
        """
        Create advanced SSL context with custom configuration.

        Args:
            verify: Whether to verify SSL certificates
            custom_ca_path: Path to custom CA certificate bundle
            check_hostname: Whether to check hostname

        Returns:
            Configured SSL context
        """
        context = ssl.create_default_context()

        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.check_hostname = check_hostname
            context.verify_mode = ssl.CERT_REQUIRED

            # Load custom CA if provided, otherwise use certifi
            ca_path = custom_ca_path or self.get_ca_bundle()
            if os.path.exists(ca_path):
                try:
                    context.load_verify_locations(ca_path)
                except Exception as e:
                    self.logger.warning(f"Failed to load CA bundle: {str(e)}")

        # Set strong security settings
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        return context

    def validate_certificate(
        self,
        hostname: str,
        port: int = 443,
        custom_ca_path: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validate certificate for a hostname.

        Args:
            hostname: Domain name
            port: Port number
            custom_ca_path: Path to custom CA certificate

        Returns:
            Tuple of (is_valid, message)
        """
        try:
            context = self.create_ssl_context(
                verify=True,
                custom_ca_path=custom_ca_path
            )

            with ssl.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert_bin()
                    if cert:
                        cert_hash = hashlib.sha256(cert).hexdigest()

                        # Check for pinned certificate mismatch
                        if hostname in self.pinned_certs:
                            if cert_hash not in self.pinned_certs[hostname]:
                                msg = f"Certificate pinning validation failed for {hostname}"
                                self.logger.error(msg)
                                return False, msg

                        return True, f"Certificate valid for {hostname}"

        except ssl.SSLError as e:
            msg = f"SSL validation failed for {hostname}: {str(e)}"
            self.logger.error(msg)
            return False, msg
        except Exception as e:
            msg = f"Certificate validation error for {hostname}: {str(e)}"
            self.logger.error(msg)
            return False, msg

    def get_certificate_info(
        self,
        hostname: str,
        port: int = 443
    ) -> Optional[Dict]:
        """
        Get detailed certificate information for a hostname.

        Args:
            hostname: Domain name
            port: Port number

        Returns:
            Certificate information dictionary or None
        """
        cache_key = f"{hostname}:{port}"
        if cache_key in self.certificate_cache:
            return self.certificate_cache[cache_key]

        try:
            context = self.create_ssl_context(verify=True)

            with ssl.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert_bin()
                    cert_dict = ssock.getpeercert()

                    if cert_dict:
                        info = {
                            "hostname": hostname,
                            "port": port,
                            "subject": dict(x[0] for x in cert_dict.get('subject', [])),
                            "issuer": dict(x[0] for x in cert_dict.get('issuer', [])),
                            "version": cert_dict.get('version'),
                            "serial_number": cert_dict.get('serialNumber'),
                            "not_before": cert_dict.get('notBefore'),
                            "not_after": cert_dict.get('notAfter'),
                            "cert_hash": hashlib.sha256(cert_bin).hexdigest(),
                            "retrieved_at": datetime.now().isoformat()
                        }

                        # Cache the result
                        self.certificate_cache[cache_key] = info

                        self.logger.debug(f"Retrieved certificate info for {hostname}")
                        return info

        except Exception as e:
            self.logger.debug(f"Failed to get certificate info: {str(e)}")
            return None

    def check_certificate_expiry(self, hostname: str, port: int = 443) -> Optional[int]:
        """
        Check days until certificate expiry.

        Args:
            hostname: Domain name
            port: Port number

        Returns:
            Days until expiry or None if error
        """
        try:
            cert_info = self.get_certificate_info(hostname, port)
            if cert_info and 'not_after' in cert_info:
                from datetime import datetime
                expiry = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days
                return days_left
        except Exception as e:
            self.logger.debug(f"Failed to check certificate expiry: {str(e)}")
        return None

    def suppress_insecure_warnings(self, suppress: bool = True) -> None:
        """
        Suppress urllib3 InsecureRequestWarning for development/testing.

        Note: This should only be used in development/testing with proper justification.
        Production code should always verify SSL certificates.

        Args:
            suppress: Whether to suppress warnings
        """
        if suppress:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.logger.warning("SSL verification warnings suppressed (development mode)")
        else:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            urllib3.util.ssl_.create_urllib3_context = self._original_ssl_context
            self.logger.info("SSL verification warnings enabled")

    def export_certificate(
        self,
        hostname: str,
        port: int = 443,
        output_path: Optional[str] = None
    ) -> Optional[str]:
        """
        Export certificate for a hostname to PEM format.

        Args:
            hostname: Domain name
            port: Port number
            output_path: Where to save the certificate (default: cache directory)

        Returns:
            Path to exported certificate or None
        """
        try:
            context = self.create_ssl_context(verify=True)

            with ssl.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert_bin()

                    if not output_path:
                        output_path = self.cache_dir / f"{hostname}.pem"
                    else:
                        output_path = Path(output_path)

                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    import base64
                    with open(output_path, 'w') as f:
                        f.write("-----BEGIN CERTIFICATE-----\n")
                        f.write(base64.b64encode(cert_bin).decode('ascii'))
                        f.write("\n-----END CERTIFICATE-----\n")

                    self.logger.info(f"Certificate exported to {output_path}")
                    return str(output_path)

        except Exception as e:
            self.logger.error(f"Failed to export certificate: {str(e)}")
            return None
