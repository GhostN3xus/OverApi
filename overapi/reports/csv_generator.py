"""CSV report generator for vulnerability scan results."""

import csv
from pathlib import Path
from datetime import datetime

from ..core.logger import Logger
from ..core.context import ScanContext


class CSVReportGenerator:
    """
    Generates CSV reports from scan results.

    Creates spreadsheet-compatible CSV files with vulnerability data
    for easy analysis and integration with other tools.
    """

    def __init__(self, logger: Logger = None):
        """
        Initialize CSV report generator.

        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(__name__)

    def generate(self, context: ScanContext, output_path: str = None) -> str:
        """
        Generate CSV report from scan context.

        Args:
            context: Scan context with results
            output_path: Optional output file path

        Returns:
            Path to generated CSV file
        """
        try:
            # Set default output path if not provided
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"overapi_report_{timestamp}.csv"

            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)

            self.logger.info(f"Generating CSV report to {output_file}")

            # Write vulnerabilities to CSV
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write header
                writer.writerow([
                    'Endpoint',
                    'Method',
                    'Vulnerability Type',
                    'Severity',
                    'Description',
                    'Evidence',
                    'Recommendation'
                ])

                # Write vulnerability data
                for vuln in context.vulnerabilities:
                    writer.writerow([
                        vuln.get('endpoint', 'N/A'),
                        vuln.get('method', 'N/A'),
                        vuln.get('type', 'N/A'),
                        vuln.get('severity', 'N/A'),
                        vuln.get('description', 'N/A'),
                        vuln.get('evidence', 'N/A'),
                        vuln.get('recommendation', 'N/A')
                    ])

            self.logger.info(f"CSV report generated successfully: {output_file}")
            return str(output_file)

        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
            raise
