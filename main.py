#!/usr/bin/env python3
"""
OverApi - Universal API Security Scanner
A robust, modular tool for offensive and defensive API scanning.
"""

import argparse
import sys
import os
from pathlib import Path

# Add overapi to path
sys.path.insert(0, str(Path(__file__).parent))

from overapi.core.logger import Logger
from overapi.core.config import Config, ScanMode, ProxyConfig
from overapi.core.exceptions import OverApiException
from overapi.scanner.scanner import Scanner
from overapi.report.report_generator import ReportGenerator


def print_banner():
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║          🔒 OverApi - API Security Scanner 🔒             ║
    ║                    v1.0.0                                 ║
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


def main():
    """Main entry point."""
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

        logger.info("Initializing OverApi Scanner...")

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

        # Run scanner
        scanner = Scanner(config, logger)
        results = scanner.scan()

        # Generate reports
        logger.info("\nGenerating reports...")
        report_gen = ReportGenerator(logger)
        report_gen.generate(
            results,
            output_html=args.output_html,
            output_json=args.output_json,
            output_dir=args.output_dir
        )

        logger.info("\n" + "=" * 70)
        logger.success("OverApi scan completed successfully!")
        logger.info("=" * 70)

        return 0

    except OverApiException as e:
        print(f"\n❌ OverApi Error: {str(e)}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user", file=sys.stderr)
        return 130

    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}", file=sys.stderr)
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
