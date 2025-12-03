"""JSON report generator."""

import json
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ..core.logger import Logger
from ..core.context import ScanContext


class JSONReportGenerator:
    """Generates JSON reports from scan results."""

    def __init__(self, logger: Logger = None):
        """
        Initialize JSON report generator.

        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(__name__)

    def generate(
        self,
        context: ScanContext,
        output_dir: Path,
        filename_prefix: str = "scan"
    ) -> Path:
        """
        Generate JSON report.

        Args:
            context: ScanContext with scan results
            output_dir: Output directory
            filename_prefix: Filename prefix

        Returns:
            Path to generated JSON file
        """
        output_path = output_dir / f"{filename_prefix}.json"

        report_data = self._build_report_data(context)

        with output_path.open('w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)

        return output_path

    def _build_report_data(self, context: ScanContext) -> Dict[str, Any]:
        """Build structured report data."""
        return {
            "scan_info": {
                "target": context.target,
                "api_type": context.api_type,
                "status": context.status.value if hasattr(context.status, 'value') else str(context.status),
                "start_time": context.start_time.isoformat() if context.start_time else None,
                "end_time": context.end_time.isoformat() if context.end_time else None,
                "duration_seconds": self._calculate_duration(context),
                "tool": "OverApi",
                "version": "2.0.0"
            },
            "endpoints": {
                "discovered": len(context.endpoints),
                "tested": len([e for e in context.endpoints if hasattr(e, 'tested') and e.tested]),
                "details": [
                    {
                        "path": getattr(e, 'path', str(e)),
                        "method": getattr(e, 'method', 'GET'),
                        "tested": getattr(e, 'tested', False)
                    }
                    for e in context.endpoints[:100]  # Limit to first 100
                ]
            },
            "vulnerabilities": {
                "total": len(context.vulnerabilities),
                "by_severity": self._count_by_severity(context),
                "by_type": self._count_by_type(context),
                "findings": [
                    self._format_vulnerability(vuln)
                    for vuln in context.vulnerabilities
                ]
            },
            "statistics": {
                "endpoints_discovered": len(context.endpoints),
                "endpoints_tested": len([e for e in context.endpoints if hasattr(e, 'tested') and e.tested]),
                "vulnerabilities_found": len(context.vulnerabilities),
                "critical_vulnerabilities": self._count_severity(context, 'critical'),
                "high_vulnerabilities": self._count_severity(context, 'high'),
                "medium_vulnerabilities": self._count_severity(context, 'medium'),
                "low_vulnerabilities": self._count_severity(context, 'low'),
            },
            "risk_assessment": {
                "overall_risk": self._calculate_risk(context),
                "critical_issues": self._count_severity(context, 'critical'),
                "high_issues": self._count_severity(context, 'high'),
                "recommendations": self._generate_recommendations(context)
            }
        }

    def _format_vulnerability(self, vuln) -> Dict[str, Any]:
        """Format vulnerability for JSON output."""
        if isinstance(vuln, dict):
            return {
                "type": vuln.get('type', 'Unknown'),
                "severity": vuln.get('severity', 'unknown'),
                "endpoint": vuln.get('endpoint', ''),
                "method": vuln.get('method', 'GET'),
                "payload": vuln.get('payload', ''),
                "evidence": vuln.get('evidence', ''),
                "owasp_category": vuln.get('owasp_category', ''),
                "cwe_id": vuln.get('cwe_id', ''),
                "description": vuln.get('description', ''),
                "remediation": vuln.get('remediation', '')
            }
        else:
            return {
                "type": getattr(vuln, 'type', 'Unknown'),
                "severity": getattr(vuln, 'severity', 'unknown'),
                "endpoint": getattr(vuln, 'endpoint', ''),
                "method": getattr(vuln, 'method', 'GET'),
                "payload": getattr(vuln, 'payload', ''),
                "evidence": getattr(vuln, 'evidence', ''),
                "owasp_category": getattr(vuln, 'owasp_category', ''),
                "description": getattr(vuln, 'description', ''),
            }

    def _calculate_duration(self, context: ScanContext) -> Optional[int]:
        """Calculate scan duration in seconds."""
        if context.start_time and context.end_time:
            return int((context.end_time - context.start_time).total_seconds())
        return None

    def _count_by_severity(self, context: ScanContext) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in context.vulnerabilities:
            severity = self._get_severity(vuln).lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_type(self, context: ScanContext) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts = {}
        for vuln in context.vulnerabilities:
            vuln_type = self._get_type(vuln)
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts

    def _count_severity(self, context: ScanContext, severity: str) -> int:
        """Count vulnerabilities of specific severity."""
        count = 0
        for vuln in context.vulnerabilities:
            if self._get_severity(vuln).lower() == severity.lower():
                count += 1
        return count

    def _get_severity(self, vuln) -> str:
        """Get vulnerability severity."""
        if isinstance(vuln, dict):
            return vuln.get('severity', 'unknown')
        return getattr(vuln, 'severity', 'unknown')

    def _get_type(self, vuln) -> str:
        """Get vulnerability type."""
        if isinstance(vuln, dict):
            return vuln.get('type', 'Unknown')
        return getattr(vuln, 'type', 'Unknown')

    def _calculate_risk(self, context: ScanContext) -> str:
        """Calculate overall risk level."""
        critical = self._count_severity(context, 'critical')
        high = self._count_severity(context, 'high')

        if critical > 0:
            return "CRITICAL"
        elif high >= 3:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self, context: ScanContext) -> list:
        """Generate security recommendations."""
        recommendations = []

        critical = self._count_severity(context, 'critical')
        high = self._count_severity(context, 'high')

        if critical > 0:
            recommendations.append(
                "URGENT: Address critical vulnerabilities immediately before production deployment."
            )

        if high > 0:
            recommendations.append(
                "HIGH PRIORITY: Remediate high-severity vulnerabilities within 48 hours."
            )

        # Check for specific vulnerability types
        vuln_types = self._count_by_type(context)

        if any('SQL Injection' in vtype for vtype in vuln_types):
            recommendations.append(
                "Use parameterized queries to prevent SQL injection attacks."
            )

        if any('XSS' in vtype for vtype in vuln_types):
            recommendations.append(
                "Implement proper output encoding and Content Security Policy headers."
            )

        if any('Authentication' in vtype or 'JWT' in vtype for vtype in vuln_types):
            recommendations.append(
                "Review authentication mechanisms and implement proper token validation."
            )

        if any('BOLA' in vtype for vtype in vuln_types):
            recommendations.append(
                "Implement proper authorization checks for all object-level operations."
            )

        return recommendations
