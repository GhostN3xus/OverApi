"""GraphQL Advanced Attack Module for OverApi."""

import json
import logging
import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import requests


class GraphQLVulnerabilityType(Enum):
    """GraphQL vulnerability types."""
    INTROSPECTION_ENABLED = "introspection_enabled"
    BATCH_QUERY_DOS = "batch_query_dos"
    CIRCULAR_QUERY = "circular_query"
    FIELD_SUGGESTION = "field_suggestion"
    MUTATION_INJECTION = "mutation_injection"
    DIRECTIVE_ABUSE = "directive_abuse"
    ALIAS_DOS = "alias_dos"
    SCHEMA_INVERSION = "schema_inversion"
    NO_RATE_LIMITING = "no_rate_limiting"
    NO_DEPTH_LIMIT = "no_depth_limit"


@dataclass
class GraphQLVulnerability:
    """GraphQL vulnerability finding."""
    vuln_type: GraphQLVulnerabilityType
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    poc_query: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
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
            'poc_query': self.poc_query,
        }


class GraphQLAttacker:
    """Advanced GraphQL attack engine."""

    INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        type { name kind ofType { name kind } }
      }
      interfaces { name }
      possibleTypes { name }
      enumValues { name }
      inputFields { name type { name } }
    }
    directives {
      name
      description
      locations
      args { name type { name } }
    }
  }
}"""

    def __init__(self, target_url: str, graphql_endpoint: str = "/graphql",
                 headers: Dict[str, str] = None, proxies: Dict[str, str] = None,
                 timeout: int = 30):
        """
        Initialize GraphQL Attacker.

        Args:
            target_url: Base target URL
            graphql_endpoint: GraphQL endpoint path
            headers: Custom HTTP headers
            proxies: Proxy configuration
            timeout: Request timeout
        """
        self.target_url = target_url
        self.graphql_endpoint = graphql_endpoint
        self.headers = headers or {}
        self.proxies = proxies
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[GraphQLVulnerability] = []
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)

        self.schema = None
        self.types = {}

    async def analyze(self) -> Dict[str, Any]:
        """
        Execute comprehensive GraphQL analysis.

        Returns:
            Analysis results with vulnerabilities and schema info
        """
        self.logger.info("Starting GraphQL analysis...")

        results = {
            'vulnerabilities': [],
            'schema': None,
            'queries_enabled': False,
            'mutations_enabled': False,
            'subscriptions_enabled': False,
            'directives': [],
        }

        # Test introspection
        vuln = await self.test_introspection()
        if vuln:
            self.vulnerabilities.append(vuln)
            results['vulnerabilities'].append(vuln.to_dict())
            # Extract schema if introspection successful
            self.schema = self._parse_introspection_response()

        if self.schema:
            results['schema'] = self.schema
            results['queries_enabled'] = 'queryType' in self.schema and self.schema['queryType']
            results['mutations_enabled'] = 'mutationType' in self.schema and self.schema['mutationType']
            results['subscriptions_enabled'] = 'subscriptionType' in self.schema

            # Run additional tests only if we have schema
            tests = [
                self.test_batch_query_dos(),
                self.test_circular_query(),
                self.test_field_suggestion(),
                self.test_directive_abuse(),
                self.test_alias_dos(),
                self.test_no_depth_limit(),
            ]

            for test in tests:
                result = await test
                if result:
                    self.vulnerabilities.append(result)
                    results['vulnerabilities'].append(result.to_dict())

        self.logger.info(f"Found {len(self.vulnerabilities)} GraphQL vulnerabilities")
        return results

    async def test_introspection(self) -> Optional[GraphQLVulnerability]:
        """
        Test if GraphQL introspection is enabled.

        Introspection should be disabled in production.
        """
        try:
            response = await self._execute_graphql_query(self.INTROSPECTION_QUERY)

            if response and response.status_code == 200:
                data = response.json()

                if 'data' in data and data['data'].get('__schema'):
                    return GraphQLVulnerability(
                        vuln_type=GraphQLVulnerabilityType.INTROSPECTION_ENABLED,
                        severity="high",
                        title="GraphQL Introspection Enabled",
                        description="GraphQL introspection is enabled, allowing attackers to extract full schema",
                        evidence={
                            'endpoint': self.graphql_endpoint,
                            'introspection_available': True,
                        },
                        remediation="Disable introspection in production. Only enable for authenticated users.",
                        cvss_score=7.5,
                        cwe_id="CWE-200",
                        owasp_category="API3:2023 Broken Object Level Authorization",
                        poc_query=self.INTROSPECTION_QUERY,
                    )

        except Exception as e:
            self.logger.debug(f"Introspection test error: {str(e)}")

        return None

    async def test_batch_query_dos(self) -> Optional[GraphQLVulnerability]:
        """
        Test for batch query DoS vulnerability.

        Multiple queries in one request can exhaust resources.
        """
        try:
            if not self.schema:
                return None

            # Generate batch query
            batch_query = self._generate_batch_query(100)

            response = await self._execute_graphql_query(batch_query)

            if response and response.status_code == 200:
                response_time = response.elapsed.total_seconds()

                if response_time > 2:  # Slow response indicates resource usage
                    return GraphQLVulnerability(
                        vuln_type=GraphQLVulnerabilityType.BATCH_QUERY_DOS,
                        severity="high",
                        title="GraphQL Batch Query DoS",
                        description="API allows batch queries without rate limiting, enabling DoS attacks",
                        evidence={
                            'batch_size': 100,
                            'response_time': response_time,
                            'status_code': response.status_code,
                        },
                        remediation="Implement query complexity analysis. Limit batch size. Add rate limiting.",
                        cvss_score=7.5,
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption",
                        poc_query=batch_query,
                    )

        except Exception as e:
            self.logger.debug(f"Batch query test error: {str(e)}")

        return None

    async def test_circular_query(self) -> Optional[GraphQLVulnerability]:
        """
        Test for circular/nested query vulnerability.

        Deeply nested queries can cause exponential resource consumption.
        """
        try:
            if not self.schema:
                return None

            # Generate circular query
            circular_query = self._generate_circular_query(15)

            response = await self._execute_graphql_query(circular_query)

            if response and response.status_code == 200:
                return GraphQLVulnerability(
                    vuln_type=GraphQLVulnerabilityType.CIRCULAR_QUERY,
                    severity="high",
                    title="GraphQL Circular Query DoS",
                    description="API allows deeply nested queries without depth limiting",
                    evidence={
                        'nesting_depth': 15,
                        'status_code': response.status_code,
                        'query_accepted': True,
                    },
                    remediation="Implement query depth limits. Use query complexity analysis. Set maximum depth to 5-10.",
                    cvss_score=7.5,
                    cwe_id="CWE-770",
                    owasp_category="API4:2023 Unrestricted Resource Consumption",
                    poc_query=circular_query,
                )

        except Exception as e:
            self.logger.debug(f"Circular query test error: {str(e)}")

        return None

    async def test_field_suggestion(self) -> Optional[GraphQLVulnerability]:
        """
        Test for field suggestion attack (typo-based discovery).

        GraphQL may reveal field names through typo suggestions.
        """
        try:
            # Try a query with typo
            typo_query = """{
  usser {
    id
    name
  }
}"""

            response = await self._execute_graphql_query(typo_query)

            if response and response.status_code == 200:
                data = response.json()
                response_text = json.dumps(data)

                # Check for suggestions in error messages
                if 'did you mean' in response_text.lower() or 'suggestions' in response_text.lower():
                    return GraphQLVulnerability(
                        vuln_type=GraphQLVulnerabilityType.FIELD_SUGGESTION,
                        severity="medium",
                        title="GraphQL Field Suggestion Attack",
                        description="GraphQL provides field suggestions, allowing schema inference through typos",
                        evidence={
                            'suggestions_enabled': True,
                            'error_messages_detailed': True,
                        },
                        remediation="Disable detailed error messages in production. Use generic errors for invalid queries.",
                        cvss_score=5.3,
                        cwe_id="CWE-209",
                        owasp_category="API9:2023 Improper Inventory Management",
                    )

        except Exception as e:
            self.logger.debug(f"Field suggestion test error: {str(e)}")

        return None

    async def test_directive_abuse(self) -> Optional[GraphQLVulnerability]:
        """
        Test for directive abuse (@skip, @include).

        Directives can be abused to bypass validation or access restricted data.
        """
        try:
            # Query with directive abuse
            directive_query = """{
  user(id: 1) @include(if: true) {
    id
    name
    secretField @skip(if: false)
    adminData @include(if: true)
  }
}"""

            response = await self._execute_graphql_query(directive_query)

            if response and response.status_code == 200:
                data = response.json()

                # Check if sensitive fields are exposed
                if 'data' in data and ('secretField' in str(data) or 'adminData' in str(data)):
                    return GraphQLVulnerability(
                        vuln_type=GraphQLVulnerabilityType.DIRECTIVE_ABUSE,
                        severity="high",
                        title="GraphQL Directive Abuse",
                        description="Directives can be abused to access restricted fields",
                        evidence={
                            'directive_abuse_possible': True,
                            'sensitive_fields_accessible': True,
                        },
                        remediation="Validate directives server-side. Don't rely on client-side directive filtering.",
                        cvss_score=7.5,
                        cwe_id="CWE-639",
                        owasp_category="API1:2023 Broken Object Level Authorization",
                    )

        except Exception as e:
            self.logger.debug(f"Directive abuse test error: {str(e)}")

        return None

    async def test_alias_dos(self) -> Optional[GraphQLVulnerability]:
        """
        Test for alias-based DoS attack.

        GraphQL aliases can be used to multiply query requests.
        """
        try:
            # Generate query with many aliases
            alias_query = self._generate_alias_query(50)

            response = await self._execute_graphql_query(alias_query)

            if response and response.status_code == 200:
                response_time = response.elapsed.total_seconds()

                if response_time > 1:
                    return GraphQLVulnerability(
                        vuln_type=GraphQLVulnerabilityType.ALIAS_DOS,
                        severity="high",
                        title="GraphQL Alias-based DoS",
                        description="GraphQL aliases allow multiplying queries for resource exhaustion",
                        evidence={
                            'alias_count': 50,
                            'response_time': response_time,
                        },
                        remediation="Implement query complexity scoring. Limit number of aliases. Add rate limiting.",
                        cvss_score=7.5,
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption",
                        poc_query=alias_query,
                    )

        except Exception as e:
            self.logger.debug(f"Alias DoS test error: {str(e)}")

        return None

    async def test_no_depth_limit(self) -> Optional[GraphQLVulnerability]:
        """
        Test if query depth limits are enforced.
        """
        try:
            # Try a very deep query
            deep_query = self._generate_deep_query(20)

            response = await self._execute_graphql_query(deep_query)

            if response and response.status_code == 200:
                return GraphQLVulnerability(
                    vuln_type=GraphQLVulnerabilityType.NO_DEPTH_LIMIT,
                    severity="medium",
                    title="No Query Depth Limit",
                    description="GraphQL server does not enforce query depth limits",
                    evidence={
                        'max_depth_tested': 20,
                        'accepted': True,
                    },
                    remediation="Implement query depth limits (recommended: 5-10).",
                    cvss_score=6.5,
                    cwe_id="CWE-770",
                    owasp_category="API4:2023 Unrestricted Resource Consumption",
                )

        except Exception as e:
            self.logger.debug(f"Depth limit test error: {str(e)}")

        return None

    async def _execute_graphql_query(self, query: str) -> Optional[requests.Response]:
        """Execute GraphQL query."""
        try:
            url = f"{self.target_url}{self.graphql_endpoint}".rstrip('/')

            payload = {'query': query}

            headers = {**self.headers}
            headers['Content-Type'] = 'application/json'

            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )

            return response

        except Exception as e:
            self.logger.debug(f"GraphQL query execution error: {str(e)}")

        return None

    def _parse_introspection_response(self) -> Optional[Dict[str, Any]]:
        """Parse introspection response."""
        try:
            # Make introspection request
            response = self.session.post(
                f"{self.target_url}{self.graphql_endpoint}".rstrip('/'),
                json={'query': self.INTROSPECTION_QUERY},
                headers=self.headers,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    return data['data']['__schema']

        except Exception as e:
            self.logger.debug(f"Schema parsing error: {str(e)}")

        return None

    def _generate_batch_query(self, count: int = 100) -> str:
        """Generate batch query with N queries."""
        queries = []

        for i in range(count):
            queries.append(f'query{i}: user(id: {i}) {{ id name }}')

        return f"{{ {' '.join(queries)} }}"

    def _generate_circular_query(self, depth: int = 15) -> str:
        """Generate circular/nested query."""
        query = "{ user(id: 1) { "

        for _ in range(depth):
            query += "posts { author { "

        query += "id name"

        for _ in range(depth):
            query += " } }"

        query += " }"

        return query

    def _generate_alias_query(self, count: int = 50) -> str:
        """Generate query with many aliases."""
        aliases = []

        for i in range(count):
            aliases.append(f'user{i}: user(id: 1) {{ id name email }}')

        return f"{{ {' '.join(aliases)} }}"

    def _generate_deep_query(self, depth: int = 20) -> str:
        """Generate deeply nested query."""
        query = "{ user(id: 1) { "

        for _ in range(depth):
            query += "profile { "

        query += "id"

        for _ in range(depth):
            query += " } "

        query += "}"

        return query
