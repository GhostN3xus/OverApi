"""Security modules for OverApi."""

from .auth.jwt_analyzer import JWTAnalyzer, JWTVulnerability, JWTVulnerabilityType
from .business_logic.bl_scanner import (
    BusinessLogicScanner,
    BusinessLogicVulnerability,
    BusinessLogicVulnerabilityType,
)
from .injection.graphql_attacker import (
    GraphQLAttacker,
    GraphQLVulnerability,
    GraphQLVulnerabilityType,
)
from .injection.ssrf_tester import SSRFTester, SSRFVulnerability
from .reporting.advanced_reporter import AdvancedReporter, CVSSCalculator

__all__ = [
    'JWTAnalyzer',
    'JWTVulnerability',
    'JWTVulnerabilityType',
    'BusinessLogicScanner',
    'BusinessLogicVulnerability',
    'BusinessLogicVulnerabilityType',
    'GraphQLAttacker',
    'GraphQLVulnerability',
    'GraphQLVulnerabilityType',
    'SSRFTester',
    'SSRFVulnerability',
    'AdvancedReporter',
    'CVSSCalculator',
]
