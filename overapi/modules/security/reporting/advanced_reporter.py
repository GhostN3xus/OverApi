"""Advanced Reporting Engine for OverApi."""

import json
import logging
import base64
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path


@dataclass
class CVSSVector:
    """CVSS 3.1 Vector Components."""
    av: str = "N"  # AV:N/L/A/P
    ac: str = "L"  # AC:L/H
    pr: str = "N"  # PR:N/L/H
    ui: str = "N"  # UI:N/R
    s: str = "U"   # S:U/C
    c: str = "H"   # C:N/L/H
    i: str = "H"   # I:N/L/H
    a: str = "N"   # A:N/L/H

    def to_vector_string(self) -> str:
        """Convert to CVSS vector string."""
        return f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"


class CVSSCalculator:
    """CVSS 3.1 Score Calculator."""

    # CVSS 3.1 Score mappings (simplified)
    BASE_SCORE_RANGES = {
        'Critical': (9.0, 10.0),
        'High': (7.0, 8.9),
        'Medium': (4.0, 6.9),
        'Low': (0.1, 3.9),
        'None': (0.0, 0.0),
    }

    @staticmethod
    def calculate_score(vector: CVSSVector) -> float:
        """
        Calculate CVSS 3.1 base score from vector.

        This is a simplified implementation.
        For production, use official NIST CVSS calculator.
        """
        # Start with impact calculation
        impact_factors = {
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},
            'A': {'N': 0, 'L': 0.22, 'H': 0.56},
        }

        impact = (
            1 - ((1 - impact_factors['C'][vector.c]) *
                 (1 - impact_factors['I'][vector.i]) *
                 (1 - impact_factors['A'][vector.a]))
        )

        # Exploitability factors
        av_factors = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        ac_factors = {'L': 0.77, 'H': 0.44}
        pr_factors_changed = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        pr_factors_unchanged = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        ui_factors = {'N': 0.85, 'R': 0.62}

        scope_changed = vector.s == 'C'
        pr_factors = pr_factors_changed if scope_changed else pr_factors_unchanged

        exploitability = (
            av_factors[vector.av] *
            ac_factors[vector.ac] *
            pr_factors[vector.pr] *
            ui_factors[vector.ui]
        )

        # Scope coefficient
        scope_coefficient = 1.08 if scope_changed else 1.0

        # Calculate base score
        if impact <= 0:
            base_score = 0
        else:
            base_score = scope_coefficient * (exploitability * 10 + (impact - exploitability) * 10)
            base_score = min(base_score, 10.0)

        return round(base_score, 1)

    @staticmethod
    def get_severity(score: float) -> str:
        """Get severity rating from score."""
        for severity, (min_score, max_score) in CVSSCalculator.BASE_SCORE_RANGES.items():
            if min_score <= score <= max_score:
                return severity
        return "None"


class ComplianceMapper:
    """Maps vulnerabilities to compliance frameworks."""

    COMPLIANCE_MAPPINGS = {
        'CWE-287': {  # Improper Authentication
            'OWASP_Top_10': 'API2:2023 Broken Authentication',
            'NIST': 'IA-2',
            'PCI_DSS': '6.5.10',
            'ISO_27001': 'A.9.4.2',
            'SOC2': 'CC6.2, CC9.2',
        },
        'CWE-347': {  # Improper Verification of Cryptographic Signature
            'OWASP_Top_10': 'API2:2023 Broken Authentication',
            'NIST': 'SC-12, SC-13',
            'PCI_DSS': '6.5.10',
            'ISO_27001': 'A.10.1.1',
            'SOC2': 'CC6.2',
        },
        'CWE-918': {  # Server-Side Request Forgery
            'OWASP_Top_10': 'API10:2023 Unsafe Consumption of APIs',
            'NIST': 'SI-10',
            'PCI_DSS': '6.5.1',
            'ISO_27001': 'A.13.1.1',
            'SOC2': 'CC6.1',
        },
        'CWE-521': {  # Weak Cryptography for Passwords
            'OWASP_Top_10': 'API2:2023 Broken Authentication',
            'NIST': 'IA-5',
            'PCI_DSS': '8.2.1, 8.2.4',
            'ISO_27001': 'A.9.4.3',
            'SOC2': 'CC6.2',
        },
    }

    @staticmethod
    def map_vulnerability(cwe_id: str) -> Dict[str, str]:
        """Get compliance mappings for vulnerability."""
        return ComplianceMapper.COMPLIANCE_MAPPINGS.get(cwe_id, {})


class AdvancedReporter:
    """Advanced reporting engine for API security findings."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize reporter."""
        self.logger = logger or logging.getLogger(__name__)

    def generate_html_report(self, findings: List[Dict[str, Any]], target_url: str,
                            output_path: str) -> str:
        """
        Generate professional HTML report.

        Args:
            findings: List of vulnerability findings
            target_url: Target URL that was scanned
            output_path: Path to save HTML report

        Returns:
            Path to generated report
        """
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'low'), 4)
        )

        # Generate HTML
        html = self._generate_html_template(sorted_findings, target_url)

        # Write to file
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html)

        self.logger.info(f"HTML report generated: {output_path}")
        return output_path

    def _generate_html_template(self, findings: List[Dict[str, Any]], target_url: str) -> str:
        """Generate HTML template."""
        # Calculate summary
        summary = self._calculate_summary(findings)

        # Generate findings HTML
        findings_html = self._generate_findings_html(findings)

        # Generate executive summary
        exec_summary = self._generate_executive_summary(summary, findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OverApi Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f9f9f9;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}

        .card.critical {{ border-left-color: #d32f2f; }}
        .card.high {{ border-left-color: #f57c00; }}
        .card.medium {{ border-left-color: #fbc02d; }}
        .card.low {{ border-left-color: #388e3c; }}

        .card-value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}

        .card-label {{
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }}

        .executive-summary {{
            padding: 30px;
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            margin: 20px;
            border-radius: 4px;
        }}

        .executive-summary h2 {{
            margin-bottom: 15px;
            color: #e65100;
        }}

        .executive-summary ul {{
            list-style: none;
            margin-left: 20px;
        }}

        .executive-summary li {{
            margin: 8px 0;
            padding-left: 20px;
            position: relative;
        }}

        .executive-summary li:before {{
            content: "▸";
            position: absolute;
            left: 0;
        }}

        .findings-section {{
            padding: 30px 20px;
        }}

        .finding {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}

        .finding-header {{
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
            transition: background 0.2s;
        }}

        .finding-header:hover {{
            background: #f5f5f5;
        }}

        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
            color: white;
        }}

        .severity-badge.critical {{ background: #d32f2f; }}
        .severity-badge.high {{ background: #f57c00; }}
        .severity-badge.medium {{ background: #fbc02d; color: #333; }}
        .severity-badge.low {{ background: #388e3c; }}

        .finding-content {{
            padding: 20px;
            display: none;
        }}

        .finding.expanded .finding-content {{
            display: block;
        }}

        .finding-section {{
            margin-bottom: 20px;
        }}

        .finding-section h3 {{
            font-size: 1em;
            color: #667eea;
            margin-bottom: 10px;
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 8px;
        }}

        .evidence {{
            background: #f5f5f5;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}

        .cvss-score {{
            display: inline-block;
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border-radius: 4px;
            font-weight: bold;
        }}

        .compliance-info {{
            background: #f0f4ff;
            padding: 12px;
            border-radius: 4px;
            margin-top: 10px;
        }}

        .compliance-info dt {{
            font-weight: bold;
            color: #667eea;
            margin-top: 8px;
        }}

        .compliance-info dd {{
            margin-left: 20px;
            margin-bottom: 8px;
        }}

        footer {{
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}

        .toggle-arrow {{
            display: inline-block;
            transition: transform 0.2s;
            margin-left: 10px;
        }}

        .finding.expanded .toggle-arrow {{
            transform: rotate(90deg);
        }}

        @media print {{
            .finding-content {{
                display: block !important;
            }}

            .finding {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 API Security Report</h1>
            <p>OverApi Comprehensive Security Assessment</p>
        </header>

        <div class="summary-cards">
            <div class="card critical">
                <div class="card-value">{summary['critical']}</div>
                <div class="card-label">Critical</div>
            </div>
            <div class="card high">
                <div class="card-value">{summary['high']}</div>
                <div class="card-label">High</div>
            </div>
            <div class="card medium">
                <div class="card-value">{summary['medium']}</div>
                <div class="card-label">Medium</div>
            </div>
            <div class="card low">
                <div class="card-value">{summary['low']}</div>
                <div class="card-label">Low</div>
            </div>
            <div class="card">
                <div class="card-value">{summary['total']}</div>
                <div class="card-label">Total Issues</div>
            </div>
        </div>

        <div class="executive-summary">
            <h2>Executive Summary</h2>
            {exec_summary}
        </div>

        <div class="findings-section">
            <h2 style="margin-bottom: 20px;">Detailed Findings</h2>
            {findings_html}
        </div>

        <footer>
            <p>Generated by OverApi on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {target_url}</p>
        </footer>
    </div>

    <script>
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', function() {{
                this.parentElement.classList.toggle('expanded');
            }});
        }});
    </script>
</body>
</html>"""

        return html

    def _generate_findings_html(self, findings: List[Dict[str, Any]]) -> str:
        """Generate HTML for findings."""
        findings_html = ""

        for finding in findings:
            severity = finding.get('severity', 'low')
            title = finding.get('title', 'Unknown Vulnerability')
            description = finding.get('description', '')
            remediation = finding.get('remediation', '')
            cwe_id = finding.get('cwe_id', '')
            owasp_category = finding.get('owasp_category', '')
            cvss_score = finding.get('cvss_score', 0)
            evidence = finding.get('evidence', {})

            # Get compliance mappings
            compliance_html = ""
            if cwe_id:
                mappings = ComplianceMapper.map_vulnerability(cwe_id)
                if mappings:
                    compliance_html = "<div class='compliance-info'><strong>Compliance Mappings:</strong><dl>"
                    for framework, mapping in mappings.items():
                        framework_display = framework.replace('_', ' ')
                        compliance_html += f"<dt>{framework_display}</dt><dd>{mapping}</dd>"
                    compliance_html += "</dl></div>"

            evidence_html = json.dumps(evidence, indent=2) if evidence else "No evidence collected"

            finding_html = f"""
            <div class="finding">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{title}</div>
                    </div>
                    <div style="display: flex; gap: 15px; align-items: center;">
                        <span class="severity-badge {severity}">{severity.upper()}</span>
                        <span class="cvss-score">CVSS {cvss_score}</span>
                        <span class="toggle-arrow">▶</span>
                    </div>
                </div>
                <div class="finding-content">
                    <div class="finding-section">
                        <h3>Description</h3>
                        <p>{description}</p>
                    </div>

                    <div class="finding-section">
                        <h3>Evidence</h3>
                        <pre class="evidence">{evidence_html}</pre>
                    </div>

                    <div class="finding-section">
                        <h3>Remediation</h3>
                        <p>{remediation}</p>
                    </div>

                    <div class="finding-section">
                        <h3>References</h3>
                        <p>CWE: {cwe_id} | OWASP: {owasp_category}</p>
                        {compliance_html}
                    </div>
                </div>
            </div>
            """

            findings_html += finding_html

        if not findings_html:
            findings_html = "<p style='color: #388e3c; font-size: 1.1em;'>✓ No vulnerabilities found!</p>"

        return findings_html

    def _calculate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate finding summary."""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}

        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            summary[severity] = summary.get(severity, 0) + 1
            summary['total'] += 1

        return summary

    def _generate_executive_summary(self, summary: Dict[str, int],
                                   findings: List[Dict[str, Any]]) -> str:
        """Generate executive summary HTML."""
        risk_level = "Critical" if summary['critical'] > 0 else \
                    "High" if summary['high'] > 0 else \
                    "Medium" if summary['medium'] > 0 else "Low"

        top_findings = findings[:3] if findings else []

        summary_html = f"""
        <ul>
            <li><strong>Risk Level:</strong> {risk_level}</li>
            <li><strong>Total Issues:</strong> {summary['total']}</li>
            <li><strong>Critical:</strong> {summary['critical']}</li>
            <li><strong>High:</strong> {summary['high']}</li>
            <li><strong>Medium:</strong> {summary['medium']}</li>
            <li><strong>Low:</strong> {summary['low']}</li>
        </ul>

        <h3 style="margin-top: 20px; color: #e65100;">Top Priorities</h3>
        <ul>
        """

        for finding in top_findings:
            title = finding.get('title', 'Unknown')
            remediation = finding.get('remediation', 'Apply recommended fixes')[:100]
            summary_html += f"<li><strong>{title}:</strong> {remediation}...</li>"

        summary_html += "</ul>"

        return summary_html

    def generate_json_report(self, findings: List[Dict[str, Any]], target_url: str,
                           output_path: str) -> str:
        """Generate JSON report."""
        report = {
            'metadata': {
                'target': target_url,
                'timestamp': datetime.now().isoformat(),
                'tool': 'OverApi',
                'version': '1.0.0',
            },
            'summary': {
                'total': len(findings),
                'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
                'high': sum(1 for f in findings if f.get('severity') == 'high'),
                'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
                'low': sum(1 for f in findings if f.get('severity') == 'low'),
            },
            'findings': findings,
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"JSON report generated: {output_path}")
        return output_path

    def generate_executive_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate executive summary.

        Returns dictionary suitable for C-level reporting.
        """
        summary_obj = self._calculate_summary(findings)

        risk_score = self._calculate_risk_score(findings)

        return {
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'finding_counts': summary_obj,
            'business_impact': self._assess_business_impact(findings),
            'compliance_status': self._assess_compliance_status(findings),
            'priority_actions': self._generate_priority_actions(findings),
            'estimated_fix_time_days': self._estimate_fix_time(findings),
        }

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score (0-100)."""
        if not findings:
            return 0

        total_cvss = sum(f.get('cvss_score', 0) for f in findings)
        avg_cvss = total_cvss / len(findings)

        # Weight by severity
        severity_weight = {
            'critical': 3,
            'high': 2,
            'medium': 1,
            'low': 0.5,
        }

        weighted_sum = sum(
            severity_weight.get(f.get('severity', 'low'), 1) * f.get('cvss_score', 0)
            for f in findings
        )

        risk_score = min(100, (weighted_sum / len(findings)) * 1.5)
        return round(risk_score, 1)

    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score."""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

    def _assess_business_impact(self, findings: List[Dict[str, Any]]) -> str:
        """Assess business impact."""
        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')

        if critical > 0:
            return "Critical - Immediate action required. Vulnerabilities allow full system compromise."
        elif high > 3:
            return "High - Significant risk. Multiple critical business functions are affected."
        elif high > 0:
            return "Medium - Notable vulnerabilities found. Business continuity at risk."
        else:
            return "Low - Minor issues. Security posture is acceptable."

    def _assess_compliance_status(self, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        """Assess compliance status against frameworks."""
        frameworks = {
            'OWASP_API_Top_10': 'Gaps identified',
            'PCI_DSS': 'Not compliant' if any(f.get('severity') == 'critical' for f in findings) else 'Compliant',
            'SOC2': 'Requires audit',
            'ISO_27001': 'Partial compliance',
        }

        return frameworks

    def _generate_priority_actions(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate priority actions."""
        actions = []

        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        for finding in critical_findings[:3]:
            actions.append(f"Fix {finding.get('title', 'vulnerability')} (24-48 hours)")

        actions.append("Implement comprehensive security testing")
        actions.append("Review and update security policies")

        return actions

    def _estimate_fix_time(self, findings: List[Dict[str, Any]]) -> int:
        """Estimate time to fix all issues in days."""
        severity_time = {
            'critical': 2,
            'high': 5,
            'medium': 10,
            'low': 15,
        }

        total_time = 0
        for finding in findings:
            severity = finding.get('severity', 'low')
            total_time += severity_time.get(severity, 10)

        # Assume 2-3 developers working in parallel
        return max(7, total_time // 3)
