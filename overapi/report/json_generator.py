"""JSON report generator."""

from typing import Dict, Any
import json
from datetime import datetime


class JSONGenerator:
    """Generates JSON reports."""

    def generate(self, results: Dict[str, Any], output_path: str):
        """
        Generate JSON report.

        Args:
            results: Scan results
            output_path: Output file path
        """
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "OverApi",
                "version": "1.0.0"
            },
            "target": {
                "url": results.get("target_url"),
                "detected_api_types": results.get("detected_api_types", []),
            },
            "scan_info": {
                "start_time": datetime.fromtimestamp(results.get("scan_start", 0)).isoformat(),
                "end_time": datetime.fromtimestamp(results.get("scan_end", 0)).isoformat(),
                "duration_seconds": results.get("scan_duration", 0)
            },
            "endpoints": results.get("endpoints", []),
            "vulnerabilities": self._format_vulnerabilities(results.get("vulnerabilities", [])),
            "summary": {
                "total_endpoints": len(results.get("endpoints", [])),
                "total_vulnerabilities": len(results.get("vulnerabilities", [])),
                "critical": len([v for v in results.get("vulnerabilities", []) if v.get("severity") == "Critical"]),
                "high": len([v for v in results.get("vulnerabilities", []) if v.get("severity") == "High"]),
                "medium": len([v for v in results.get("vulnerabilities", []) if v.get("severity") == "Medium"]),
                "low": len([v for v in results.get("vulnerabilities", []) if v.get("severity") == "Low"]),
            }
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

    def _format_vulnerabilities(self, vulnerabilities: list) -> list:
        """Format vulnerabilities for JSON output."""
        formatted = []

        for vuln in vulnerabilities:
            formatted.append({
                "type": vuln.get("type"),
                "severity": vuln.get("severity", "Unknown"),
                "endpoint": vuln.get("endpoint"),
                "parameter": vuln.get("parameter"),
                "payload": vuln.get("payload"),
                "evidence": vuln.get("evidence"),
                "owasp_category": vuln.get("owasp_category"),
                "status_code": vuln.get("status_code")
            })

        return formatted
