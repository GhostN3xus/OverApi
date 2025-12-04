"""PDF report generator for vulnerability scan results using ReportLab."""

from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from ..core.logger import Logger
from ..core.context import ScanContext

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFReportGenerator:
    """
    Generates professional PDF reports from scan results.

    Creates formatted PDF documents with vulnerability findings,
    severity ratings, and remediation guidance using ReportLab.
    """

    # Severity colors
    SEVERITY_COLORS = {
        'Critical': colors.Color(0.8, 0, 0),       # Dark Red
        'High': colors.Color(1, 0.3, 0.3),          # Red
        'Medium': colors.Color(1, 0.6, 0),          # Orange
        'Low': colors.Color(0.2, 0.6, 0.2),         # Green
        'Info': colors.Color(0.2, 0.4, 0.8),        # Blue
    }

    def __init__(self, logger: Logger = None):
        """
        Initialize PDF report generator.

        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(__name__)
        self.styles = None
        self._init_styles()

    def _init_styles(self):
        """Initialize document styles."""
        if not REPORTLAB_AVAILABLE:
            return

        self.styles = getSampleStyleSheet()

        # Custom styles
        self.styles.add(ParagraphStyle(
            name='Title2',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.Color(0.1, 0.1, 0.4),
            spaceAfter=20
        ))

        self.styles.add(ParagraphStyle(
            name='Heading2Custom',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.Color(0.2, 0.2, 0.5),
            spaceBefore=15,
            spaceAfter=10
        ))

        self.styles.add(ParagraphStyle(
            name='BodyTextJustified',
            parent=self.styles['BodyText'],
            alignment=TA_JUSTIFY,
            fontSize=10
        ))

        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Code'],
            fontSize=8,
            backColor=colors.Color(0.95, 0.95, 0.95),
            borderColor=colors.Color(0.8, 0.8, 0.8),
            borderWidth=1,
            borderPadding=5,
            leftIndent=10
        ))

    def generate(self, context: ScanContext, output_path: str = None) -> str:
        """
        Generate PDF report from scan context.

        Args:
            context: Scan context with results
            output_path: Optional output file path

        Returns:
            Path to generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            self.logger.warning("ReportLab not installed. Install with: pip install reportlab")
            return self._generate_fallback(context, output_path)

        try:
            # Set default output path if not provided
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"overapi_report_{timestamp}.pdf"

            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)

            self.logger.info(f"Generating PDF report to {output_file}")

            # Create the document
            doc = SimpleDocTemplate(
                str(output_file),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )

            # Build content
            story = []

            # Title page
            story.extend(self._create_title_page(context))
            story.append(PageBreak())

            # Executive Summary
            story.extend(self._create_executive_summary(context))
            story.append(Spacer(1, 20))

            # Vulnerability Statistics
            story.extend(self._create_statistics_section(context))
            story.append(PageBreak())

            # Detailed Findings
            story.extend(self._create_findings_section(context))

            # Remediation Guidelines
            story.append(PageBreak())
            story.extend(self._create_remediation_section(context))

            # Build PDF
            doc.build(story)

            self.logger.info(f"PDF report generated successfully: {output_file}")
            return str(output_file)

        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {e}")
            raise

    def _create_title_page(self, context: ScanContext) -> List:
        """Create the title page."""
        elements = []

        elements.append(Spacer(1, 2 * inch))

        # Title
        elements.append(Paragraph(
            "OverApi Security Assessment Report",
            self.styles['Title2']
        ))

        elements.append(Spacer(1, 0.5 * inch))

        # Subtitle
        elements.append(Paragraph(
            f"Target: {context.target}",
            self.styles['Heading2Custom']
        ))

        elements.append(Spacer(1, 0.3 * inch))

        # Date
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Normal']
        ))

        elements.append(Spacer(1, 0.3 * inch))

        # API Type
        elements.append(Paragraph(
            f"API Type: {context.api_type.upper() if context.api_type else 'Unknown'}",
            self.styles['Normal']
        ))

        elements.append(Spacer(1, 1 * inch))

        # Classification
        classification_style = ParagraphStyle(
            name='Classification',
            parent=self.styles['Normal'],
            alignment=TA_CENTER,
            textColor=colors.red,
            fontSize=12,
            fontName='Helvetica-Bold'
        )
        elements.append(Paragraph(
            "CONFIDENTIAL - FOR AUTHORIZED USE ONLY",
            classification_style
        ))

        return elements

    def _create_executive_summary(self, context: ScanContext) -> List:
        """Create executive summary section."""
        elements = []

        elements.append(Paragraph(
            "Executive Summary",
            self.styles['Heading1']
        ))

        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in context.vulnerabilities:
            severity = vuln.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Summary text
        total_vulns = len(context.vulnerabilities)
        total_endpoints = len(context.endpoints)

        summary_text = f"""
        This security assessment was conducted against <b>{context.target}</b>.
        The scan analyzed <b>{total_endpoints}</b> endpoints and discovered
        <b>{total_vulns}</b> potential security issues.
        """

        elements.append(Paragraph(summary_text, self.styles['BodyTextJustified']))
        elements.append(Spacer(1, 10))

        # Risk breakdown
        if total_vulns > 0:
            risk_text = f"""
            <b>Risk Breakdown:</b><br/>
            - Critical: {severity_counts['Critical']} findings<br/>
            - High: {severity_counts['High']} findings<br/>
            - Medium: {severity_counts['Medium']} findings<br/>
            - Low: {severity_counts['Low']} findings<br/>
            - Informational: {severity_counts['Info']} findings
            """
            elements.append(Paragraph(risk_text, self.styles['BodyText']))

        return elements

    def _create_statistics_section(self, context: ScanContext) -> List:
        """Create statistics section with tables."""
        elements = []

        elements.append(Paragraph(
            "Vulnerability Statistics",
            self.styles['Heading1']
        ))

        # Count by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in context.vulnerabilities:
            severity = vuln.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Create table data
        table_data = [['Severity', 'Count', 'Percentage']]
        total = max(len(context.vulnerabilities), 1)

        for severity, count in severity_counts.items():
            percentage = (count / total) * 100
            table_data.append([severity, str(count), f"{percentage:.1f}%"])

        table_data.append(['Total', str(total), '100%'])

        # Create table
        table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.2, 0.5)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
            ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 20))

        # Vulnerability types
        elements.append(Paragraph(
            "Vulnerability Types Found",
            self.styles['Heading2Custom']
        ))

        type_counts = {}
        for vuln in context.vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        if type_counts:
            type_data = [['Vulnerability Type', 'Count']]
            for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                type_data.append([vtype[:50], str(count)])

            type_table = Table(type_data, colWidths=[4*inch, 1*inch])
            type_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.3, 0.3, 0.6)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ]))
            elements.append(type_table)

        return elements

    def _create_findings_section(self, context: ScanContext) -> List:
        """Create detailed findings section."""
        elements = []

        elements.append(Paragraph(
            "Detailed Findings",
            self.styles['Heading1']
        ))

        if not context.vulnerabilities:
            elements.append(Paragraph(
                "No vulnerabilities were detected during this scan.",
                self.styles['BodyText']
            ))
            return elements

        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_vulns = sorted(
            context.vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'Info'), 5)
        )

        for i, vuln in enumerate(sorted_vulns[:50], 1):  # Limit to 50 for PDF size
            severity = vuln.get('severity', 'Info')
            color = self.SEVERITY_COLORS.get(severity, colors.grey)

            # Vulnerability title
            title_style = ParagraphStyle(
                name=f'VulnTitle{i}',
                parent=self.styles['Heading3'],
                textColor=color
            )

            elements.append(Paragraph(
                f"{i}. [{severity}] {vuln.get('type', 'Unknown Vulnerability')}",
                title_style
            ))

            # Details table
            details = []
            if vuln.get('endpoint'):
                details.append(['Endpoint', vuln.get('endpoint', '')[:80]])
            if vuln.get('owasp_category'):
                details.append(['OWASP Category', vuln.get('owasp_category', '')])
            if vuln.get('cwe'):
                details.append(['CWE', vuln.get('cwe', '')])
            if vuln.get('evidence'):
                evidence = str(vuln.get('evidence', ''))[:200]
                details.append(['Evidence', evidence])

            if details:
                detail_table = Table(details, colWidths=[1.2*inch, 4.5*inch])
                detail_table.setStyle(TableStyle([
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(detail_table)

            # Remediation
            if vuln.get('remediation'):
                elements.append(Paragraph(
                    f"<b>Remediation:</b> {vuln.get('remediation', '')}",
                    self.styles['BodyText']
                ))

            elements.append(Spacer(1, 15))

        return elements

    def _create_remediation_section(self, context: ScanContext) -> List:
        """Create remediation guidelines section."""
        elements = []

        elements.append(Paragraph(
            "Remediation Guidelines",
            self.styles['Heading1']
        ))

        guidelines = [
            ("Input Validation", "Validate and sanitize all user inputs. Use parameterized queries for database operations."),
            ("Authentication", "Implement strong authentication mechanisms. Use MFA where possible. Use secure token management."),
            ("Authorization", "Implement proper access controls. Check authorization for every request. Use principle of least privilege."),
            ("API Security", "Implement rate limiting. Use API versioning. Validate API schemas. Monitor for abnormal behavior."),
            ("Security Headers", "Configure security headers (HSTS, CSP, X-Frame-Options, etc.). Disable verbose error messages."),
            ("Encryption", "Use TLS 1.2+ for all connections. Encrypt sensitive data at rest. Use strong encryption algorithms."),
            ("Logging", "Implement comprehensive logging. Monitor for security events. Set up alerting for anomalies."),
        ]

        for title, description in guidelines:
            elements.append(Paragraph(f"<b>{title}</b>", self.styles['Heading3']))
            elements.append(Paragraph(description, self.styles['BodyText']))
            elements.append(Spacer(1, 5))

        return elements

    def _generate_fallback(self, context: ScanContext, output_path: str) -> str:
        """Generate a simple text report when ReportLab is not available."""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"overapi_report_{timestamp}.txt"

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("OverApi Security Assessment Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target: {context.target}\n")
            f.write(f"API Type: {context.api_type}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total Vulnerabilities: {len(context.vulnerabilities)}\n")
            f.write(f"Total Endpoints: {len(context.endpoints)}\n\n")

            f.write("-" * 60 + "\n")
            f.write("FINDINGS\n")
            f.write("-" * 60 + "\n\n")

            for i, vuln in enumerate(context.vulnerabilities, 1):
                f.write(f"{i}. [{vuln.get('severity', 'Info')}] {vuln.get('type', 'Unknown')}\n")
                f.write(f"   Endpoint: {vuln.get('endpoint', 'N/A')}\n")
                if vuln.get('evidence'):
                    f.write(f"   Evidence: {str(vuln.get('evidence', ''))[:100]}\n")
                f.write("\n")

        self.logger.info(f"Fallback text report generated: {output_file}")
        return str(output_file)
