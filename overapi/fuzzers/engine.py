"""Advanced Fuzzing Engine for OverApi Enterprise."""

from typing import List, Dict, Any, Generator, Optional
import random
import string
import base64
import urllib.parse
import re
from overapi.core.logger import Logger
from overapi.core.context import ScanContext, Endpoint
from overapi.payloads import get_payloads
from overapi.payloads.advanced_payloads import PayloadManager


class FuzzingEngine:
    """Advanced fuzzing engine with multiple fuzzing strategies."""

    def __init__(self, context: ScanContext, logger: Logger = None):
        self.context = context
        self.logger = logger or Logger(__name__)
        self.payloads = get_payloads()
        self.payload_manager = PayloadManager()

    def generate_mutations(self, data: str) -> Generator[str, None, None]:
        """Generate mutational fuzzing payloads."""
        if not data:
            return

        # Bit flipping
        for i in range(min(len(data), 50)):  # Limit to prevent explosion
            yield data[:i] + chr(ord(data[i]) ^ 0xFF) + data[i+1:]

        # Injection of special chars
        special_chars = ["'", '"', "<", ">", ";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]", "\\", "/", "\x00", "\r\n"]
        for char in special_chars:
            yield data + char
            yield char + data
            yield data[:len(data)//2] + char + data[len(data)//2:]

        # Format string mutations
        format_strings = ["%s", "%x", "%n", "%p", "{{7*7}}", "${7*7}"]
        for fmt in format_strings:
            yield data + fmt
            yield fmt + data

        # Length mutations
        yield data * 10  # Repeat
        yield data[::-1]  # Reverse
        yield ""  # Empty
        yield " " * len(data)  # Spaces
        yield "\x00" * len(data)  # Nulls

    def generate_boundary_values(self, param_name: str) -> Generator[str, None, None]:
        """Generate boundary value test cases."""
        # Numeric boundaries
        yield "0"
        yield "-1"
        yield "1"
        yield str(2**31 - 1)  # INT_MAX
        yield str(2**31)  # Overflow
        yield str(-2**31)  # INT_MIN
        yield str(2**63 - 1)  # LONG_MAX
        yield "NaN"
        yield "Infinity"
        yield "-Infinity"
        yield "1e308"
        yield "1e-308"

        # String boundaries
        yield ""  # Empty
        yield " "  # Space
        yield "a" * 1000  # Long string
        yield "a" * 10000  # Very long string
        yield "\x00"  # Null byte
        yield "\r\n"  # CRLF
        yield "\t\t\t"  # Tabs

        # Unicode edge cases
        yield "\u0000"  # Null
        yield "\uffff"  # Max BMP
        yield "😀" * 100  # Emoji
        yield "中文" * 100  # CJK
        yield "\u202e"  # Right-to-left override

    def generate_injection_payloads(self, param_name: str) -> Generator[Dict[str, Any], None, None]:
        """Generate injection test payloads based on parameter context."""
        param_lower = param_name.lower()

        # SQL Injection
        if any(term in param_lower for term in ['id', 'user', 'query', 'search', 'filter', 'where', 'order', 'sort', 'limit', 'offset']):
            for payload in self.payload_manager.get_sqli_payloads():
                yield {"type": "sqli", "payload": payload, "param": param_name}

        # XSS
        if any(term in param_lower for term in ['name', 'title', 'message', 'comment', 'text', 'content', 'description', 'q', 'search']):
            for payload in self.payload_manager.get_xss_payloads():
                yield {"type": "xss", "payload": payload, "param": param_name}

        # Command Injection
        if any(term in param_lower for term in ['cmd', 'command', 'exec', 'ping', 'ip', 'host', 'file', 'path', 'dir', 'name']):
            for payload in self.payload_manager.get_cmd_injection_payloads():
                yield {"type": "cmdi", "payload": payload, "param": param_name}

        # SSRF
        if any(term in param_lower for term in ['url', 'uri', 'link', 'src', 'href', 'callback', 'redirect', 'next', 'return']):
            for payload in self.payload_manager.get_ssrf_payloads():
                yield {"type": "ssrf", "payload": payload, "param": param_name}

        # Path Traversal
        if any(term in param_lower for term in ['file', 'path', 'filename', 'filepath', 'document', 'template', 'include']):
            for payload in self.payload_manager.get_path_traversal_payloads():
                yield {"type": "path_traversal", "payload": payload, "param": param_name}

        # LDAP Injection
        if any(term in param_lower for term in ['user', 'username', 'uid', 'cn', 'dn', 'ou', 'dc']):
            for payload in self.payload_manager.get_ldap_injection_payloads():
                yield {"type": "ldapi", "payload": payload, "param": param_name}

        # NoSQL Injection
        if any(term in param_lower for term in ['id', 'user', 'query', 'filter', 'find', 'search']):
            for payload in self.payload_manager.get_nosql_injection_payloads()[:5]:
                yield {"type": "nosqli", "payload": payload, "param": param_name}

        # SSTI
        if any(term in param_lower for term in ['template', 'name', 'title', 'message', 'text', 'content']):
            for payload in self.payload_manager.get_ssti_payloads()[:5]:
                yield {"type": "ssti", "payload": payload, "param": param_name}

    def encode_payload(self, payload: str, encoding: str = "url") -> str:
        """Encode payload with various techniques."""
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == "html":
            return ''.join(f'&#{ord(c)};' for c in payload)
        else:
            return payload

    def get_waf_bypass_variants(self, payload: str) -> Generator[str, None, None]:
        """Generate WAF bypass variants of a payload."""
        yield payload

        # Case variations
        yield payload.upper()
        yield payload.lower()
        yield ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))

        # URL encoding
        yield self.encode_payload(payload, "url")
        yield self.encode_payload(payload, "double_url")

        # Unicode variations
        yield payload.replace("<", "＜").replace(">", "＞")
        yield payload.replace("'", "ʼ")

        # Comment insertion (SQL)
        if "'" in payload or "SELECT" in payload.upper():
            yield payload.replace(" ", "/**/")
            yield payload.replace("SELECT", "SEL/**/ECT")
            yield payload.replace("UNION", "UNI/**/ON")

        # Newline/Tab insertion
        yield payload.replace(" ", "\n")
        yield payload.replace(" ", "\t")
        yield payload.replace(" ", "\r\n")

        # Null byte insertion
        yield payload.replace("'", "'\x00")
        yield "\x00" + payload

    def get_contextual_payloads(self, endpoint: Endpoint) -> List[str]:
        """Get payloads based on endpoint context (e.g. REST, GraphQL)."""
        payloads = []

        # Add general payloads
        payloads.extend(self.payloads.get('generic', []))

        # Add specific payloads based on API type
        if self.context.api_type == 'rest':
            payloads.extend(self.payloads.get('rest', []))
            payloads.extend(self.payload_manager.get_sqli_payloads()[:5])
            payloads.extend(self.payload_manager.get_xss_payloads()[:5])
        elif self.context.api_type == 'graphql':
            payloads.extend(self.payloads.get('graphql', []))
            payloads.extend(self.payload_manager.get_graphql_payloads())
        elif self.context.api_type == 'soap':
            payloads.extend(self.payloads.get('xml', []))
            payloads.extend(self.payload_manager.get_xxe_payloads())
        elif self.context.api_type == 'grpc':
            # gRPC-specific payloads
            payloads.extend(self.payload_manager.get_deserialization_payloads()[:3])

        return payloads

    def extract_parameters(self, endpoint: Endpoint) -> List[str]:
        """Extract parameter names from endpoint."""
        params = []
        path = endpoint.path if hasattr(endpoint, 'path') else endpoint.get('path', '')

        # Extract path parameters like {id}, :id, <id>
        path_params = re.findall(r'{(\w+)}|:(\w+)|<(\w+)>', path)
        for match in path_params:
            param = next((p for p in match if p), None)
            if param:
                params.append(param)

        # Common parameter names
        common_params = ['id', 'user_id', 'name', 'email', 'search', 'q', 'filter', 'page', 'limit', 'offset']
        params.extend(common_params)

        return list(set(params))

    def fuzz_endpoint(self, endpoint: Endpoint) -> Generator[Dict[str, Any], None, None]:
        """
        Fuzz a specific endpoint with comprehensive strategies.
        Yields test cases (headers, body, query params).
        """
        payloads = self.get_contextual_payloads(endpoint)
        params = self.extract_parameters(endpoint)

        # 1. Basic payload injection
        for payload in payloads:
            yield {
                "type": "payload",
                "payload": payload,
                "location": "body"
            }

        # 2. Parameter-specific fuzzing
        for param in params:
            # Injection payloads
            for test_case in self.generate_injection_payloads(param):
                yield test_case

            # Boundary values
            for boundary in self.generate_boundary_values(param):
                yield {
                    "type": "boundary",
                    "payload": boundary,
                    "param": param,
                    "location": "query"
                }

        # 3. Header fuzzing
        sensitive_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "evil.com"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("Host", "evil.com"),
            ("Origin", "https://evil.com"),
        ]
        for header, value in sensitive_headers:
            yield {
                "type": "header",
                "header_name": header,
                "header_value": value,
                "location": "header"
            }

        # 4. Content-Type fuzzing
        content_types = [
            "application/json",
            "application/xml",
            "text/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "application/json;charset=UTF-7",
        ]
        for ct in content_types:
            yield {
                "type": "content_type",
                "content_type": ct,
                "location": "header"
            }

    def fuzz_json_body(self, json_template: Dict) -> Generator[Dict, None, None]:
        """Fuzz a JSON request body."""
        import copy

        # Original
        yield json_template

        # Type confusion
        for key in json_template:
            # String to array
            mutated = copy.deepcopy(json_template)
            mutated[key] = [json_template[key]]
            yield mutated

            # String to object
            mutated = copy.deepcopy(json_template)
            mutated[key] = {"value": json_template[key]}
            yield mutated

            # Add prototype pollution
            mutated = copy.deepcopy(json_template)
            mutated["__proto__"] = {"isAdmin": True}
            yield mutated

            # Add extra fields
            mutated = copy.deepcopy(json_template)
            mutated["isAdmin"] = True
            mutated["role"] = "admin"
            yield mutated

    def fuzz_graphql_query(self, base_query: str) -> Generator[str, None, None]:
        """Fuzz a GraphQL query."""
        yield base_query

        # Introspection
        yield "query { __schema { types { name fields { name } } } }"
        yield "query { __type(name: \"User\") { name fields { name } } }"

        # Field suggestion
        yield base_query.replace("}", " invalidField }")

        # Batching
        yield f"[{{'query': '{base_query}'}}, {{'query': '{base_query}'}}]"

        # Alias abuse
        yield re.sub(r'(\w+):', r'a\g<1> b\g<1> c\g<1>:', base_query)

        # Deeply nested query
        nested = "query { " + "user { friend { " * 50 + "id" + " } " * 50 + " } }"
        yield nested
