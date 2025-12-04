#!/usr/bin/env python3
"""
OverApi - Universal API Security Scanner
A robust, modular tool for offensive and defensive API scanning.
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Add overapi to path
sys.path.insert(0, str(Path(__file__).parent))

from overapi.core.logger import Logger
from overapi.core.config import Config, ScanMode, ProxyConfig
from overapi.core.exceptions import OverApiException
from overapi.scanners.orchestrator import Orchestrator
from overapi.reports.report_generator import ReportGenerator

# Rich library for beautiful CLI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich.layout import Layout
    from rich import box
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Initialize Rich console
console = Console() if RICH_AVAILABLE else None


def print_banner():
    """Print application banner with Rich styling."""
    if RICH_AVAILABLE:
        banner_text = Text()
        banner_text.append("   ___                  _            _ \n", style="bold cyan")
        banner_text.append("  / _ \\__   _____ _ __ / \\   _ __(_)\n", style="bold cyan")
        banner_text.append(" | | | \\ \\ / / _ \\ '__/ _ \\ | '_ \\| |\n", style="bold bright_cyan")
        banner_text.append(" | |_| |\\ V /  __/ | / ___ \\| |_) | |\n", style="bold bright_cyan")
        banner_text.append("  \\___/  \\_/ \\___|_|/_/   \\_\\ .__/|_|\n", style="bold blue")
        banner_text.append("                            |_|      \n", style="bold blue")

        subtitle = Text()
        subtitle.append("\n    Universal API Security Scanner v2.0.0 Enterprise    \n", style="bold white")
        subtitle.append("  Comprehensive Offensive & Defensive API Testing  \n", style="dim white")
        subtitle.append("\n         Powered by GhostN3xus Security Team         \n", style="italic cyan")

        panel = Panel(
            Align.center(banner_text + subtitle),
            box=box.DOUBLE_EDGE,
            border_style="bold cyan",
            padding=(1, 2)
        )
        console.print(panel)
    else:
        banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║          🔒 OverApi - API Security Scanner 🔒             ║
    ║                  v2.0.0 Enterprise                        ║
    ║  Comprehensive Offensive & Defensive API Testing         ║
    ╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="OverApi - Universal API Security Scanner",
        epilog="Example: python main.py --url https://api.example.com --threads 10 --out report.html"
    )

    # Target options
    parser.add_argument('--url', required=True, help='Target API URL')
    parser.add_argument('--type', dest='api_type', help='Force API type (rest, graphql, soap, grpc, websocket)')

    # Scanning options
    parser.add_argument('--mode', choices=['safe', 'normal', 'aggressive'],
                       default='normal', help='Scan mode (default: normal)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')

    # Security options
    parser.add_argument('--proxy', help='Proxy URL (http://ip:port)')
    parser.add_argument('--verify-ssl', action='store_true', default=True,
                       help='Verify SSL certificates (default: enabled)')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl',
                       help='Disable SSL certificate verification (NOT recommended)')
    parser.add_argument('--custom-ca', dest='custom_ca_path',
                       help='Path to custom CA certificate bundle')
    parser.add_argument('--header', action='append', help='Custom header (format: "Key: Value")')

    # Output options
    parser.add_argument('--out', dest='output_html', help='Output HTML report path')
    parser.add_argument('--json', dest='output_json', help='Output JSON report path')
    parser.add_argument('--outdir', dest='output_dir', default='./reports', help='Output directory (default: ./reports)')

    # Feature options
    parser.add_argument('--wordlist', help='Custom wordlist path')
    parser.add_argument('--max-endpoints', type=int, default=1000, help='Maximum endpoints to test')

    # Testing options
    parser.add_argument('--no-fuzzing', action='store_true', help='Disable fuzzing')
    parser.add_argument('--no-injection', action='store_true', help='Disable injection tests')
    parser.add_argument('--no-ratelimit', action='store_true', help='Disable rate limit tests')
    parser.add_argument('--no-bola', action='store_true', help='Disable BOLA tests')

    # General options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--log-file', help='Log file path')

    return parser.parse_args()


def print_config_table(config):
    """Print configuration table using Rich."""
    if not RICH_AVAILABLE:
        return

    table = Table(title="🔧 Scan Configuration", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Parameter", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Target URL", f"[bold]{config.url}[/bold]")
    table.add_row("API Type", config.api_type or "Auto-detect")
    table.add_row("Scan Mode", f"[yellow]{config.mode.value.upper()}[/yellow]")
    table.add_row("Threads", str(config.threads))
    table.add_row("Timeout", f"{config.timeout}s")
    table.add_row("SSL Verification", "✅ Enabled" if config.verify_ssl else "❌ Disabled")

    if config.proxy:
        table.add_row("Proxy", config.proxy.http or "None")

    # Feature status
    features = []
    if config.enable_fuzzing:
        features.append("🎯 Fuzzing")
    if config.enable_injection_tests:
        features.append("💉 Injection")
    if config.enable_ratelimit_tests:
        features.append("⏱️ Rate Limit")
    if config.enable_bola_tests:
        features.append("🔓 BOLA")

    table.add_row("Enabled Tests", " | ".join(features) if features else "None")
    table.add_row("Output Directory", config.output_dir)

    console.print()
    console.print(table)
    console.print()


def print_results_summary(results):
    """Print results summary using Rich."""
    if not RICH_AVAILABLE:
        return

    # Count vulnerabilities by severity
    vuln_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

    if hasattr(results, 'vulnerabilities'):
        for vuln in results.vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            vuln_count[severity] = vuln_count.get(severity, 0) + 1

    total = sum(vuln_count.values())

    # Create summary table
    table = Table(title="📊 Scan Results Summary", box=box.DOUBLE_EDGE, show_header=True, header_style="bold green")
    table.add_column("Severity", style="bold", justify="center")
    table.add_column("Count", justify="center")
    table.add_column("Percentage", justify="center")

    # Add rows with color coding
    if vuln_count['CRITICAL'] > 0:
        pct = (vuln_count['CRITICAL'] / total * 100) if total > 0 else 0
        table.add_row(
            f"[bold red]🔴 CRITICAL[/bold red]",
            f"[bold red]{vuln_count['CRITICAL']}[/bold red]",
            f"[red]{pct:.1f}%[/red]"
        )

    if vuln_count['HIGH'] > 0:
        pct = (vuln_count['HIGH'] / total * 100) if total > 0 else 0
        table.add_row(
            f"[bold orange1]🟠 HIGH[/bold orange1]",
            f"[bold orange1]{vuln_count['HIGH']}[/bold orange1]",
            f"[orange1]{pct:.1f}%[/orange1]"
        )

    if vuln_count['MEDIUM'] > 0:
        pct = (vuln_count['MEDIUM'] / total * 100) if total > 0 else 0
        table.add_row(
            f"[bold yellow]🟡 MEDIUM[/bold yellow]",
            f"[bold yellow]{vuln_count['MEDIUM']}[/bold yellow]",
            f"[yellow]{pct:.1f}%[/yellow]"
        )

    if vuln_count['LOW'] > 0:
        pct = (vuln_count['LOW'] / total * 100) if total > 0 else 0
        table.add_row(
            f"[bold blue]🔵 LOW[/bold blue]",
            f"[bold blue]{vuln_count['LOW']}[/bold blue]",
            f"[blue]{pct:.1f}%[/blue]"
        )

    if vuln_count['INFO'] > 0:
        pct = (vuln_count['INFO'] / total * 100) if total > 0 else 0
        table.add_row(
            f"[dim]ℹ️ INFO[/dim]",
            f"[dim]{vuln_count['INFO']}[/dim]",
            f"[dim]{pct:.1f}%[/dim]"
        )

    table.add_row("[bold]TOTAL[/bold]", f"[bold]{total}[/bold]", "[bold]100%[/bold]")

    console.print()
    console.print(table)
    console.print()

    # Risk assessment
    if vuln_count['CRITICAL'] > 0 or vuln_count['HIGH'] > 0:
        risk_panel = Panel(
            "[bold red]⚠️  HIGH RISK DETECTED[/bold red]\n\n"
            "Critical or high severity vulnerabilities were found.\n"
            "Immediate action is recommended!",
            border_style="bold red",
            box=box.DOUBLE
        )
        console.print(risk_panel)
    elif vuln_count['MEDIUM'] > 0:
        risk_panel = Panel(
            "[bold yellow]⚠️  MEDIUM RISK DETECTED[/bold yellow]\n\n"
            "Medium severity vulnerabilities were found.\n"
            "Review and remediate as appropriate.",
            border_style="bold yellow",
            box=box.ROUNDED
        )
        console.print(risk_panel)
    else:
        risk_panel = Panel(
            "[bold green]✅ LOW RISK[/bold green]\n\n"
            "No critical or high severity vulnerabilities detected.\n"
            "Continue monitoring and testing.",
            border_style="bold green",
            box=box.ROUNDED
        )
        console.print(risk_panel)


def main():
    """Main entry point."""
    start_time = datetime.now()

    try:
        # Print banner
        print_banner()

        # Parse arguments
        args = parse_arguments()

        # Initialize logger
        logger = Logger(
            level=10 if args.verbose else 20,  # DEBUG=10, INFO=20
            log_file=args.log_file,
            verbose=args.verbose
        )

        # Parse custom headers
        custom_headers = {}
        if args.header:
            for header in args.header:
                if ': ' in header:
                    key, value = header.split(': ', 1)
                    custom_headers[key] = value

        # Parse proxy
        proxy = None
        if args.proxy:
            proxy = ProxyConfig(http=args.proxy, https=args.proxy)

        # Create configuration
        config = Config(
            url=args.url,
            api_type=args.api_type,
            mode=ScanMode(args.mode),
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            proxy=proxy,
            custom_headers=custom_headers,
            custom_ca_path=args.custom_ca_path,
            output_html=args.output_html,
            output_json=args.output_json,
            output_dir=args.output_dir,
            log_file=args.log_file,
            wordlist=args.wordlist,
            max_endpoints=args.max_endpoints,
            enable_fuzzing=not args.no_fuzzing,
            enable_injection_tests=not args.no_injection,
            enable_ratelimit_tests=not args.no_ratelimit,
            enable_bola_tests=not args.no_bola,
            verbose=args.verbose
        )

        # Print configuration
        print_config_table(config)

        # Initialization message
        if RICH_AVAILABLE:
            console.print("[bold cyan]🚀 Initializing OverApi Scanner...[/bold cyan]\n")
        else:
            logger.info("Initializing OverApi Scanner...")

        # Run scanner with progress
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                scan_task = progress.add_task("[cyan]Scanning API...", total=None)
                orchestrator = Orchestrator(config, logger)
                results = orchestrator.scan()
                progress.update(scan_task, completed=True)
        else:
            orchestrator = Orchestrator(config, logger)
            results = orchestrator.scan()

        # Generate reports
        if RICH_AVAILABLE:
            console.print("\n[bold cyan]📄 Generating reports...[/bold cyan]")
        else:
            logger.info("\nGenerating reports...")

        report_gen = ReportGenerator(logger)
        report_gen.generate(
            results,
            output_html=args.output_html,
            output_json=args.output_json,
            output_dir=args.output_dir
        )

        # Calculate duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Print results summary
        print_results_summary(results)

        # Success message
        if RICH_AVAILABLE:
            success_panel = Panel(
                f"[bold green]✅ OverApi scan completed successfully![/bold green]\n\n"
                f"Duration: [cyan]{duration:.2f} seconds[/cyan]\n"
                f"Reports saved to: [yellow]{config.output_dir}[/yellow]",
                border_style="bold green",
                box=box.DOUBLE_EDGE,
                padding=(1, 2)
            )
            console.print()
            console.print(success_panel)
        else:
            logger.info("\n" + "=" * 70)
            logger.success("OverApi scan completed successfully!")
            logger.info("=" * 70)

        return 0

    except OverApiException as e:
        if RICH_AVAILABLE:
            console.print(f"\n[bold red]❌ OverApi Error:[/bold red] {str(e)}", style="red")
        else:
            print(f"\n❌ OverApi Error: {str(e)}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n\n[bold yellow]⚠️  Scan interrupted by user[/bold yellow]")
        else:
            print("\n\n⚠️  Scan interrupted by user", file=sys.stderr)
        return 130

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"\n[bold red]❌ Unexpected error:[/bold red] {str(e)}", style="red")
        else:
            print(f"\n❌ Unexpected error: {str(e)}", file=sys.stderr)

        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
