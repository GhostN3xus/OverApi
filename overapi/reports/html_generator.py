"""HTML report generator with professional templates."""

from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ..core.logger import Logger
from ..core.context import ScanContext


class HTMLReportGenerator:
    """Generates professional HTML reports from scan results."""

    def __init__(self, logger: Logger = None):
        """
        Initialize HTML report generator.

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
        Generate HTML report.

        Args:
            context: ScanContext with scan results
            output_dir: Output directory
            filename_prefix: Filename prefix

        Returns:
            Path to generated HTML file
        """
        output_path = output_dir / f"{filename_prefix}.html"

        html_content = self._build_html_report(context)

        with output_path.open('w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    def _build_html_report(self, context: ScanContext) -> str:
        """Build complete HTML report."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OverApi Security Scan Report</title>
    {self._get_css_styles()}
</head>
<body>
    <div class="container">
        {self._generate_header(context)}
        {self._generate_executive_summary(context)}
        {self._generate_statistics(context)}
        {self._generate_vulnerabilities_section(context)}
        {self._generate_endpoints_section(context)}
        {self._generate_footer()}
    </div>
    {self._get_javascript()}
</body>
</html>"""

    def _get_css_styles(self) -> str:
        """Get CSS styles for the report."""
        return """<style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }

        .card h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .summary-item {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .summary-item h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        .summary-item p {
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
        }

        .vuln-stats {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            margin: 30px 0;
        }

        .vuln-stat {
            text-align: center;
            padding: 20px;
            min-width: 150px;
        }

        .vuln-stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .vuln-stat-label {
            font-size: 0.9em;
            text-transform: uppercase;
            color: #666;
        }

        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        .info { color: #95a5a6; }

        .vulnerability {
            background: #f8f9fa;
            border-left: 4px solid;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
        }

        .vulnerability.critical { border-left-color: #e74c3c; }
        .vulnerability.high { border-left-color: #e67e22; }
        .vulnerability.medium { border-left-color: #f39c12; }
        .vulnerability.low { border-left-color: #3498db; }

        .vulnerability h3 {
            margin-bottom: 10px;
            font-size: 1.3em;
        }

        .vuln-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            margin-left: 10px;
        }

        .vuln-badge.critical {
            background: #e74c3c;
            color: white;
        }

        .vuln-badge.high {
            background: #e67e22;
            color: white;
        }

        .vuln-badge.medium {
            background: #f39c12;
            color: white;
        }

        .vuln-badge.low {
            background: #3498db;
            color: white;
        }

        .vuln-details {
            margin-top: 15px;
        }

        .vuln-detail-row {
            margin: 8px 0;
        }

        .vuln-detail-row strong {
            color: #666;
            display: inline-block;
            width: 120px;
        }

        .evidence {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }

        .endpoint-list {
            list-style: none;
        }

        .endpoint-item {
            background: #f8f9fa;
            padding: 12px 15px;
            margin-bottom: 8px;
            border-radius: 5px;
            display: flex;
            align-items: center;
        }

        .endpoint-method {
            background: #667eea;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: bold;
            margin-right: 15px;
            min-width: 60px;
            text-align: center;
            font-size: 0.85em;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: #7f8c8d;
            font-size: 0.9em;
        }

        .risk-level {
            display: inline-block;
            padding: 10px 25px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 1.2em;
            margin: 15px 0;
        }

        .risk-critical {
            background: #e74c3c;
            color: white;
        }

        .risk-high {
            background: #e67e22;
            color: white;
        }

        .risk-medium {
            background: #f39c12;
            color: white;
        }

        .risk-low {
            background: #27ae60;
            color: white;
        }

        @media print {
            body {
                background: white;
            }
            .container {
                max-width: 100%;
            }
            .card {
                box-shadow: none;
                border: 1px solid #ddd;
            }
        }
    </style>"""

    def _generate_header(self, context: ScanContext) -> str:
        """Generate report header."""
        return f"""
        <div class="header">
            <h1>🔒 OverApi Security Scan Report</h1>
            <p>Comprehensive API Security Assessment</p>
            <p style="margin-top: 10px; opacity: 0.8;">Target: {context.target}</p>
            <p style="opacity: 0.8;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        """

    def _generate_executive_summary(self, context: ScanContext) -> str:
        """Generate executive summary section."""
        risk_level = self._calculate_risk_level(context)
        risk_class = risk_level.lower().replace(" ", "-")

        duration = "N/A"
        if context.start_time and context.end_time:
            duration = str(context.end_time - context.start_time).split('.')[0]

        return f"""
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>Target</h3>
                    <p>{context.target}</p>
                </div>
                <div class="summary-item">
                    <h3>API Type</h3>
                    <p>{context.api_type.upper()}</p>
                </div>
                <div class="summary-item">
                    <h3>Scan Status</h3>
                    <p>{context.status.value if hasattr(context.status, 'value') else str(context.status)}</p>
                </div>
                <div class="summary-item">
                    <h3>Duration</h3>
                    <p>{duration}</p>
                </div>
            </div>
            <div style="margin-top: 25px;">
                <strong>Overall Risk Level:</strong>
                <span class="risk-level risk-{risk_class}">{risk_level}</span>
            </div>
        </div>
        """

    def _generate_statistics(self, context: ScanContext) -> str:
        """Generate statistics section."""
        vuln_counts = self._count_vulnerabilities_by_severity(context)

        return f"""
        <div class="card">
            <h2>Vulnerability Statistics</h2>
            <div class="vuln-stats">
                <div class="vuln-stat">
                    <div class="vuln-stat-number critical">{vuln_counts.get('critical', 0)}</div>
                    <div class="vuln-stat-label">Critical</div>
                </div>
                <div class="vuln-stat">
                    <div class="vuln-stat-number high">{vuln_counts.get('high', 0)}</div>
                    <div class="vuln-stat-label">High</div>
                </div>
                <div class="vuln-stat">
                    <div class="vuln-stat-number medium">{vuln_counts.get('medium', 0)}</div>
                    <div class="vuln-stat-label">Medium</div>
                </div>
                <div class="vuln-stat">
                    <div class="vuln-stat-number low">{vuln_counts.get('low', 0)}</div>
                    <div class="vuln-stat-label">Low</div>
                </div>
                <div class="vuln-stat">
                    <div class="vuln-stat-number info">{vuln_counts.get('info', 0)}</div>
                    <div class="vuln-stat-label">Info</div>
                </div>
            </div>
            <div class="summary-grid" style="margin-top: 30px;">
                <div class="summary-item">
                    <h3>Total Vulnerabilities</h3>
                    <p>{len(context.vulnerabilities)}</p>
                </div>
                <div class="summary-item">
                    <h3>Endpoints Discovered</h3>
                    <p>{len(context.endpoints)}</p>
                </div>
                <div class="summary-item">
                    <h3>Endpoints Tested</h3>
                    <p>{len([e for e in context.endpoints if hasattr(e, 'tested') and e.tested])}</p>
                </div>
            </div>
        </div>
        """

    def _generate_vulnerabilities_section(self, context: ScanContext) -> str:
        """Generate vulnerabilities section."""
        if not context.vulnerabilities:
            return """
            <div class="card">
                <h2>Vulnerabilities</h2>
                <p style="color: #27ae60; font-size: 1.2em;">✅ No vulnerabilities detected</p>
            </div>
            """

        vulns_html = []
        for vuln in context.vulnerabilities:
            vulns_html.append(self._format_vulnerability_html(vuln))

        return f"""
        <div class="card">
            <h2>Vulnerabilities ({len(context.vulnerabilities)})</h2>
            {''.join(vulns_html)}
        </div>
        """

    def _format_vulnerability_html(self, vuln) -> str:
        """Format individual vulnerability as HTML."""
        # Handle both dict and object formats
        if isinstance(vuln, dict):
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'unknown').lower()
            endpoint = vuln.get('endpoint', '')
            method = vuln.get('method', 'GET')
            payload = vuln.get('payload', '')
            evidence = vuln.get('evidence', '')
            owasp = vuln.get('owasp_category', '')
        else:
            vuln_type = getattr(vuln, 'type', 'Unknown')
            severity = getattr(vuln, 'severity', 'unknown').lower()
            endpoint = getattr(vuln, 'endpoint', '')
            method = getattr(vuln, 'method', 'GET')
            payload = getattr(vuln, 'payload', '')
            evidence = getattr(vuln, 'evidence', '')
            owasp = getattr(vuln, 'owasp_category', '')

        evidence_html = ""
        if evidence:
            evidence_truncated = evidence[:500] + "..." if len(evidence) > 500 else evidence
            evidence_html = f'<div class="evidence">{self._escape_html(evidence_truncated)}</div>'

        return f"""
        <div class="vulnerability {severity}">
            <h3>
                {vuln_type}
                <span class="vuln-badge {severity}">{severity}</span>
            </h3>
            <div class="vuln-details">
                <div class="vuln-detail-row">
                    <strong>Endpoint:</strong> {self._escape_html(endpoint)}
                </div>
                <div class="vuln-detail-row">
                    <strong>Method:</strong> {method}
                </div>
                {f'<div class="vuln-detail-row"><strong>OWASP Category:</strong> {owasp}</div>' if owasp else ''}
                {f'<div class="vuln-detail-row"><strong>Payload:</strong> {self._escape_html(payload)}</div>' if payload else ''}
                {evidence_html}
            </div>
        </div>
        """

    def _generate_endpoints_section(self, context: ScanContext) -> str:
        """Generate endpoints section."""
        if not context.endpoints:
            return ""

        endpoints_html = []
        for endpoint in context.endpoints[:50]:  # Limit to first 50
            if isinstance(endpoint, dict):
                path = endpoint.get('path', str(endpoint))
                method = endpoint.get('method', 'GET')
            else:
                path = getattr(endpoint, 'path', str(endpoint))
                method = getattr(endpoint, 'method', 'GET')

            endpoints_html.append(f"""
                <li class="endpoint-item">
                    <span class="endpoint-method">{method}</span>
                    <span>{self._escape_html(path)}</span>
                </li>
            """)

        return f"""
        <div class="card">
            <h2>Discovered Endpoints ({len(context.endpoints)})</h2>
            <ul class="endpoint-list">
                {''.join(endpoints_html)}
            </ul>
            {f'<p style="margin-top: 15px; color: #7f8c8d;">Showing first 50 of {len(context.endpoints)} endpoints</p>' if len(context.endpoints) > 50 else ''}
        </div>
        """

    def _generate_footer(self) -> str:
        """Generate report footer."""
        return f"""
        <div class="footer">
            <p>Generated by <strong>OverApi v2.0.0</strong> - Professional API Security Scanner</p>
            <p style="margin-top: 10px;">Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
        """

    def _get_javascript(self) -> str:
        """Get JavaScript for interactive features."""
        return """
        <script>
            // Add any interactive features here
            console.log('OverApi Report Loaded');
        </script>
        """

    def _count_vulnerabilities_by_severity(self, context: ScanContext) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in context.vulnerabilities:
            if isinstance(vuln, dict):
                severity = vuln.get('severity', 'unknown').lower()
            else:
                severity = getattr(vuln, 'severity', 'unknown').lower()

            if severity in counts:
                counts[severity] += 1

        return counts

    def _calculate_risk_level(self, context: ScanContext) -> str:
        """Calculate overall risk level."""
        counts = self._count_vulnerabilities_by_severity(context)

        if counts['critical'] > 0:
            return "CRITICAL"
        elif counts['high'] >= 3:
            return "HIGH"
        elif counts['high'] > 0 or counts['medium'] >= 5:
            return "MEDIUM"
        else:
            return "LOW"

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
