"""Fuzzing Engine."""

from typing import List, Dict, Any, Generator
import random
import string
from overapi.core.logger import Logger
from overapi.core.context import ScanContext, Endpoint
from overapi.payloads import get_payloads

class FuzzingEngine:
    def __init__(self, context: ScanContext, logger: Logger = None):
        self.context = context
        self.logger = logger or Logger(__name__)
        self.payloads = get_payloads()

    def generate_mutations(self, data: str) -> Generator[str, None, None]:
        """Generate mutational fuzzing payloads."""
        # Simple bit flipping and character replacement
        if not data:
            return

        # Bit flipping
        for i in range(len(data)):
            yield data[:i] + chr(ord(data[i]) ^ 0xFF) + data[i+1:]

        # Injection of special chars
        special_chars = ["'", '"', "<", ">", ";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]", "\\", "/"]
        for char in special_chars:
             yield data + char
             yield char + data

    def get_contextual_payloads(self, endpoint: Endpoint) -> List[str]:
        """Get payloads based on endpoint context (e.g. REST, GraphQL)."""
        payloads = []

        # Add general payloads
        payloads.extend(self.payloads.get('generic', []))

        # Add specific payloads
        if self.context.api_type == 'rest':
            payloads.extend(self.payloads.get('rest', []))
        elif self.context.api_type == 'graphql':
            payloads.extend(self.payloads.get('graphql', []))
        elif self.context.api_type == 'soap':
            payloads.extend(self.payloads.get('xml', []))

        return payloads

    def fuzz_endpoint(self, endpoint: Endpoint) -> Generator[Dict[str, Any], None, None]:
        """
        Fuzz a specific endpoint.
        Yields test cases (headers, body, query params).
        """
        payloads = self.get_contextual_payloads(endpoint)

        # Fuzz Path (Path Traversal, etc)
        # TODO: Implement path fuzzing logic if parameters exist in path

        # Fuzz Query Parameters (if any logic to extract them exists or we blindly append)
        # For now, let's assume we are generating payloads to be injected into parameters found or headers.

        for payload in payloads:
            yield {
                "type": "payload",
                "payload": payload,
                "location": "body" # Simplified for now
            }
