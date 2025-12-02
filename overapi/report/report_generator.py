"""Main report generator."""

from typing import Dict, Any
from pathlib import Path
import json
from datetime import datetime

from ..core.logger import Logger
from .html_generator import HTMLGenerator
from .json_generator import JSONGenerator


class ReportGenerator:
    """Generates HTML and JSON reports from scan results."""

    def __init__(self, logger: Logger = None):
        """
        Initialize report generator.

        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(__name__)
        self.html_gen = HTMLGenerator()
        self.json_gen = JSONGenerator()

    def generate(self, results: Dict[str, Any], output_html: str = None,
                output_json: str = None, output_dir: str = "./reports"):
        """
        Generate reports.

        Args:
            results: Scan results
            output_html: HTML output path
            output_json: JSON output path
            output_dir: Output directory
        """
        try:
            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            # Generate JSON report
            if output_json:
                self.logger.info(f"Generating JSON report: {output_json}")
                self.json_gen.generate(results, output_json)
                self.logger.success(f"JSON report saved to {output_json}")
            else:
                json_path = Path(output_dir) / f"report_{int(datetime.now().timestamp())}.json"
                self.json_gen.generate(results, str(json_path))
                self.logger.success(f"JSON report saved to {json_path}")

            # Generate HTML report
            if output_html:
                self.logger.info(f"Generating HTML report: {output_html}")
                self.html_gen.generate(results, output_html)
                self.logger.success(f"HTML report saved to {output_html}")
            else:
                html_path = Path(output_dir) / f"report_{int(datetime.now().timestamp())}.html"
                self.html_gen.generate(results, str(html_path))
                self.logger.success(f"HTML report saved to {html_path}")

        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            raise
