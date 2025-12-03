"""Main report generator orchestrator."""

from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

from ..core.logger import Logger
from ..core.context import ScanContext
from .html_generator import HTMLReportGenerator
from .json_generator import JSONReportGenerator
from .pdf_generator import PDFReportGenerator
from .csv_generator import CSVReportGenerator


class ReportGenerator:
    """
    Orchestrates report generation in multiple formats.

    Generates professional security reports from scan results
    in HTML, JSON, PDF, and CSV formats.
    """

    def __init__(self, logger: Logger = None):
        """
        Initialize report generator.

        Args:
            logger: Logger instance for reporting generation logs
        """
        self.logger = logger or Logger(__name__)
        self.html_gen = HTMLReportGenerator(logger=self.logger)
        self.json_gen = JSONReportGenerator(logger=self.logger)
        self.pdf_gen = PDFReportGenerator(logger=self.logger)
        self.csv_gen = CSVReportGenerator(logger=self.logger)

    def generate(
        self,
        context: ScanContext,
        output_dir: Optional[Path] = None,
        formats: Optional[List[str]] = None,
        filename_prefix: Optional[str] = None,
        output_html: Optional[str] = None,
        output_json: Optional[str] = None,
        output_pdf: Optional[str] = None,
        output_csv: Optional[str] = None
    ) -> Dict[str, Path]:
        """
        Generate reports in specified formats.

        Args:
            context: ScanContext with scan results
            output_dir: Output directory (default: ./reports)
            formats: List of formats ['html', 'json', 'pdf', 'csv'] (default: ['html', 'json'])
            filename_prefix: Custom filename prefix (default: scan_<timestamp>)
            output_html: Specific HTML output path
            output_json: Specific JSON output path
            output_pdf: Specific PDF output path
            output_csv: Specific CSV output path

        Returns:
            Dict mapping format to generated file path

        Example:
            ```python
            generator = ReportGenerator()
            reports = generator.generate(
                context,
                formats=['html', 'json', 'pdf', 'csv'],
                output_dir=Path('./my_reports')
            )
            print(f"HTML report: {reports['html']}")
            ```
        """
        if formats is None:
            formats = ['html', 'json']

        output_dir = output_dir or Path('./reports')
        output_dir.mkdir(parents=True, exist_ok=True)

        if filename_prefix is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename_prefix = f"scan_{timestamp}"

        results = {}

        try:
            if 'html' in formats or output_html:
                self.logger.info("Generating HTML report...")
                html_filename = Path(output_html).name if output_html else f"{filename_prefix}.html"
                html_path = self.html_gen.generate(
                    context,
                    Path(output_html).parent if output_html else output_dir,
                    html_filename
                )
                results['html'] = html_path
                self.logger.info(f"HTML report generated: {html_path}")

            if 'json' in formats or output_json:
                self.logger.info("Generating JSON report...")
                json_filename = Path(output_json).name if output_json else f"{filename_prefix}.json"
                json_path = self.json_gen.generate(
                    context,
                    Path(output_json).parent if output_json else output_dir,
                    json_filename
                )
                results['json'] = json_path
                self.logger.info(f"JSON report generated: {json_path}")

            if 'pdf' in formats or output_pdf:
                try:
                    self.logger.info("Generating PDF report...")
                    pdf_filename = Path(output_pdf).name if output_pdf else f"{filename_prefix}.pdf"
                    pdf_path = self.pdf_gen.generate(
                        context,
                        Path(output_pdf).parent if output_pdf else output_dir,
                        pdf_filename
                    )
                    results['pdf'] = pdf_path
                    self.logger.info(f"PDF report generated: {pdf_path}")
                except ImportError:
                    self.logger.warning("PDF generation skipped: WeasyPrint not installed")
                except Exception as e:
                    self.logger.error(f"PDF generation failed: {str(e)}")

            if 'csv' in formats or output_csv:
                self.logger.info("Generating CSV reports...")
                csv_filename = Path(output_csv).name if output_csv else f"{filename_prefix}.csv"
                csv_path = self.csv_gen.generate(
                    context,
                    Path(output_csv).parent if output_csv else output_dir,
                    csv_filename
                )
                results['csv'] = csv_path
                self.logger.info(f"CSV reports generated: {csv_path}")

            self.logger.info(f"Reports generated successfully: {len(results)} files")
            return results

        except Exception as e:
            self.logger.error(f"Failed to generate reports: {str(e)}")
            raise

    def generate_summary(self, context: ScanContext) -> str:
        """
        Generate a text summary of scan results.

        Args:
            context: ScanContext with scan results

        Returns:
            Formatted text summary
        """
        vuln_counts = self._count_vulnerabilities_by_severity(context)

        summary = f"""
╔══════════════════════════════════════════════════════════╗
║              OVERAPI SCAN SUMMARY                        ║
╚══════════════════════════════════════════════════════════╝

Target:           {context.target}
API Type:         {context.api_type}
Scan Status:      {context.status.value}
Start Time:       {context.start_time}
Duration:         {self._format_duration(context)}

Endpoints:
  - Discovered:   {len(context.endpoints)}
  - Tested:       {len([e for e in context.endpoints if hasattr(e, 'tested') and e.tested])}

Vulnerabilities Found: {len(context.vulnerabilities)}
  - Critical:     {vuln_counts.get('critical', 0)}
  - High:         {vuln_counts.get('high', 0)}
  - Medium:       {vuln_counts.get('medium', 0)}
  - Low:          {vuln_counts.get('low', 0)}
  - Info:         {vuln_counts.get('info', 0)}

"""
        return summary

    def _count_vulnerabilities_by_severity(
        self,
        context: ScanContext
    ) -> Dict[str, int]:
        """Count vulnerabilities grouped by severity."""
        counts = {}
        for vuln in context.vulnerabilities:
            severity = getattr(vuln, 'severity', 'unknown').lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _format_duration(self, context: ScanContext) -> str:
        """Format scan duration in human-readable format."""
        if not context.start_time or not context.end_time:
            return "N/A"

        duration = context.end_time - context.start_time
        seconds = int(duration.total_seconds())

        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60

        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
