"""HTML report generator."""

from typing import Dict, Any, List
from datetime import datetime
import html


class HTMLGenerator:
    """Generates professional HTML reports."""

    def generate(self, results: Dict[str, Any], output_path: str):
        """
        Generate HTML report.

        Args:
            results: Scan results
            output_path: Output file path
        """
        html_content = self._build_html(results)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _build_html(self, results: Dict[str, Any]) -> str:
        """Build complete HTML document."""
        vulnerabilities = results.get("vulnerabilities", [])
        endpoints = results.get("endpoints", [])

        # Calculate statistics
        stats = {
            "total_endpoints": len(endpoints),
            "total_vulns": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v.get("severity") == "Critical"]),
            "high": len([v for v in vulnerabilities if v.get("severity") == "High"]),
            "medium": len([v for v in vulnerabilities if v.get("severity") == "Medium"]),
            "low": len([v for v in vulnerabilities if v.get("severity") == "Low"]),
            "info": len([v for v in vulnerabilities if v.get("severity") == "Info"]),
        }

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OverApi Security Report</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._build_header(results)}
        {self._build_summary(stats, results)}
        {self._build_findings_section(vulnerabilities)}
        {self._build_endpoints_section(endpoints)}
        {self._build_footer(results)}
    </div>
</body>
</html>"""

    def _get_css(self) -> str:
        """Get CSS stylesheet."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px 30px;
            border-bottom: 4px solid #ff6b6b;
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .section {
            padding: 30px;
            border-bottom: 1px solid #ddd;
        }

        .section h2 {
            color: #1e3c72;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ff6b6b;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .summary-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #2a5298;
        }

        .summary-card.critical {
            border-left-color: #dc3545;
            background: linear-gradient(135deg, #ffeaea 0%, #ffcccc 100%);
        }

        .summary-card.high {
            border-left-color: #fd7e14;
            background: linear-gradient(135deg, #ffe8cc 0%, #ffd699 100%);
        }

        .summary-card.medium {
            border-left-color: #ffc107;
            background: linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%);
        }

        .summary-card.low {
            border-left-color: #28a745;
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        }

        .summary-card.info {
            border-left-color: #17a2b8;
            background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
        }

        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #1e3c72;
            margin: 10px 0;
        }

        .summary-card .label {
            font-size: 0.9em;
            color: #555;
            text-transform: uppercase;
            font-weight: 600;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 0.95em;
        }

        thead {
            background-color: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }

        thead th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #495057;
        }

        tbody td {
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }

        tbody tr:hover {
            background-color: #f8f9fa;
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-critical {
            background-color: #dc3545;
            color: white;
        }

        .severity-high {
            background-color: #fd7e14;
            color: white;
        }

        .severity-medium {
            background-color: #ffc107;
            color: #333;
        }

        .severity-low {
            background-color: #28a745;
            color: white;
        }

        .severity-info {
            background-color: #17a2b8;
            color: white;
        }

        .vulnerability-detail {
            background-color: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #ff6b6b;
            margin: 15px 0;
            border-radius: 4px;
        }

        .vulnerability-detail h4 {
            color: #1e3c72;
            margin-bottom: 10px;
        }

        .vulnerability-detail .field {
            margin: 8px 0;
            padding: 8px 0;
            border-bottom: 1px solid #dee2e6;
        }

        .vulnerability-detail .field:last-child {
            border-bottom: none;
        }

        .vulnerability-detail .label {
            font-weight: 600;
            color: #495057;
            display: inline-block;
            width: 120px;
        }

        .vulnerability-detail code {
            background-color: #fff3cd;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }

        footer {
            background-color: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
        }

        .risk-level {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 600;
            margin: 10px 0;
        }

        .risk-critical {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .risk-high {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }

        .risk-medium {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }

        .metadata {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 20px;
            font-size: 0.95em;
        }

        .metadata-item {
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }

        .metadata-item strong {
            color: #1e3c72;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }

        .empty-state p {
            font-size: 1.1em;
        }
        """

    def _build_header(self, results: Dict) -> str:
        """Build report header."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_url = results.get("target_url", "Unknown")
        api_types = ", ".join(results.get("detected_api_types", ["REST"]))

        return f"""
        <header>
            <h1>🔒 OverApi Security Assessment Report</h1>
            <div class="subtitle">Comprehensive API Security Analysis</div>
            <div class="metadata">
                <div class="metadata-item"><strong>Target URL:</strong> {html.escape(target_url)}</div>
                <div class="metadata-item"><strong>API Types:</strong> {html.escape(api_types)}</div>
                <div class="metadata-item"><strong>Report Generated:</strong> {timestamp}</div>
                <div class="metadata-item"><strong>Tool:</strong> OverApi v1.0.0</div>
            </div>
        </header>
        """

    def _build_summary(self, stats: Dict, results: Dict) -> str:
        """Build summary section."""
        duration = results.get("scan_duration", 0)
        duration_str = f"{duration:.2f}s"

        # Determine risk level
        if stats["critical"] > 0:
            risk_class = "risk-critical"
            risk_text = "🔴 CRITICAL"
        elif stats["high"] > 0:
            risk_class = "risk-high"
            risk_text = "🟠 HIGH"
        elif stats["medium"] > 0:
            risk_class = "risk-medium"
            risk_text = "🟡 MEDIUM"
        else:
            risk_class = "risk-low"
            risk_text = "🟢 LOW/INFO"

        return f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>

            <div class="risk-level {risk_class}">
                Overall Risk Level: {risk_text}
            </div>

            <div class="summary-grid">
                <div class="summary-card">
                    <div class="label">Total Endpoints</div>
                    <div class="number">{stats['total_endpoints']}</div>
                </div>
                <div class="summary-card critical">
                    <div class="label">Critical Issues</div>
                    <div class="number">{stats['critical']}</div>
                </div>
                <div class="summary-card high">
                    <div class="label">High Issues</div>
                    <div class="number">{stats['high']}</div>
                </div>
                <div class="summary-card medium">
                    <div class="label">Medium Issues</div>
                    <div class="number">{stats['medium']}</div>
                </div>
                <div class="summary-card low">
                    <div class="label">Low Issues</div>
                    <div class="number">{stats['low']}</div>
                </div>
                <div class="summary-card info">
                    <div class="label">Scan Duration</div>
                    <div class="number">{duration_str}</div>
                </div>
            </div>
        </div>
        """

    def _build_findings_section(self, vulnerabilities: List[Dict]) -> str:
        """Build findings section."""
        if not vulnerabilities:
            return """
            <div class="section">
                <h2>🛡️ Security Findings</h2>
                <div class="empty-state">
                    <p>✓ No vulnerabilities found during this assessment.</p>
                </div>
            </div>
            """

        # Group by severity
        grouped = {
            "Critical": [v for v in vulnerabilities if v.get("severity") == "Critical"],
            "High": [v for v in vulnerabilities if v.get("severity") == "High"],
            "Medium": [v for v in vulnerabilities if v.get("severity") == "Medium"],
            "Low": [v for v in vulnerabilities if v.get("severity") == "Low"],
            "Info": [v for v in vulnerabilities if v.get("severity") == "Info"],
        }

        html_content = '<div class="section"><h2>🛡️ Security Findings</h2>'

        for severity, vulns in grouped.items():
            if vulns:
                html_content += self._build_severity_group(severity, vulns)

        html_content += '</div>'
        return html_content

    def _build_severity_group(self, severity: str, vulnerabilities: List[Dict]) -> str:
        """Build severity group."""
        severity_class = f"severity-{severity.lower()}"

        html = f'<h3 style="margin-top: 20px; color: #1e3c72;">{severity.upper()} Severity Issues ({len(vulnerabilities)})</h3>'

        for vuln in vulnerabilities:
            html += self._build_vulnerability_detail(vuln)

        return html

    def _build_vulnerability_detail(self, vuln: Dict) -> str:
        """Build single vulnerability detail."""
        vuln_type = html.escape(vuln.get("type", "Unknown"))
        endpoint = html.escape(vuln.get("endpoint", "N/A"))
        severity = vuln.get("severity", "Unknown")
        severity_class = f"severity-{severity.lower()}"
        evidence = html.escape(str(vuln.get("evidence", "N/A")))[:200]
        payload = html.escape(str(vuln.get("payload", "N/A")))[:100]
        owasp = html.escape(vuln.get("owasp_category", "N/A"))

        return f"""
        <div class="vulnerability-detail">
            <h4>
                <span class="severity-badge {severity_class}">{severity}</span>
                {vuln_type}
            </h4>
            <div class="field">
                <span class="label">Endpoint:</span>
                <code>{endpoint}</code>
            </div>
            <div class="field">
                <span class="label">OWASP:</span>
                {owasp}
            </div>
            {'<div class="field"><span class="label">Payload:</span><code>' + payload + '</code></div>' if vuln.get('payload') else ''}
            <div class="field">
                <span class="label">Evidence:</span>
                {evidence}
            </div>
        </div>
        """

    def _build_endpoints_section(self, endpoints: List[Dict]) -> str:
        """Build endpoints section."""
        if not endpoints:
            return ""

        html = '<div class="section"><h2>🔗 Discovered Endpoints</h2>'
        html += f'<p>Total endpoints discovered: <strong>{len(endpoints)}</strong></p>'
        html += '<table><thead><tr><th>Endpoint</th><th>Methods</th><th>Source</th></tr></thead><tbody>'

        for ep in endpoints[:100]:  # Limit to 100 for readability
            path = html.escape(ep.get("path", "N/A"))
            methods = ", ".join(ep.get("methods", ["GET"]))
            source = ep.get("source", "unknown")
            html += f'<tr><td><code>{path}</code></td><td>{methods}</td><td>{source}</td></tr>'

        html += '</tbody></table></div>'
        return html

    def _build_footer(self, results: Dict) -> str:
        """Build report footer."""
        duration = results.get("scan_duration", 0)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""
        <footer>
            <p>This report was generated by <strong>OverApi v1.0.0</strong> on <strong>{timestamp}</strong></p>
            <p>Scan Duration: <strong>{duration:.2f} seconds</strong></p>
            <p style="margin-top: 10px; color: #999;">
                For security concerns, please contact your security team immediately.
                Do not share this report with unauthorized individuals.
            </p>
        </footer>
        """
