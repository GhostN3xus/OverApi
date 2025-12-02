#!/usr/bin/env python3
"""
OverApi - Universal API Security Scanner
Enhanced CLI interface with improved argument parsing
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional

from overapi.core.logger import Logger
from overapi.core.config import Config, ScanMode, ProxyConfig
from overapi.core.exceptions import OverApiException
from overapi.scanner.scanner import Scanner
from overapi.report.report_generator import ReportGenerator

__version__ = "1.0.0"


def print_banner():
    """Print application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║          🔒 OverApi - API Security Scanner 🔒             ║
║                    v{version}                                 ║
║  Comprehensive Offensive & Defensive API Testing         ║
╚═══════════════════════════════════════════════════════════╝
    """.format(version=__version__)
    print(banner)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser with organized groups."""
    parser = argparse.ArgumentParser(
        prog="overapi",
        description="🔒 OverApi - Universal API Security Scanner",
        epilog="""
Examples:
  # Basic scan
  overapi scan --url https://api.example.com

  # Aggressive scan with custom options
  overapi scan --url https://api.example.com --mode aggressive --threads 20

  # With authentication and proxy
  overapi scan --url https://api.example.com \\
    --header "Authorization: Bearer token123" \\
    --proxy http://127.0.0.1:8080

  # GraphQL API scan
  overapi scan --url https://api.example.com/graphql --type graphql

For more information: https://github.com/GhostN3xus/OverApi
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Version
    parser.add_argument(
        '-V', '--version',
        action='version',
        version=f'OverApi v{__version__}'
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Perform API security scan',
        description='Scan target API for security vulnerabilities'
    )
    configure_scan_parser(scan_parser)

    # Info command
    info_parser = subparsers.add_parser(
        'info',
        help='Display system and tool information',
        description='Show OverApi version and system information'
    )

    return parser


def configure_scan_parser(parser: argparse.ArgumentParser):
    """Configure scan subcommand parser with organized argument groups."""

    # === Target Configuration ===
    target_group = parser.add_argument_group(
        '🎯 Target Configuration',
        'Define the target API and basic settings'
    )
    target_group.add_argument(
        '--url',
        required=True,
        metavar='URL',
        help='Target API URL (required)'
    )
    target_group.add_argument(
        '--type',
        dest='api_type',
        choices=['rest', 'graphql', 'soap', 'grpc', 'websocket', 'auto'],
        default='auto',
        metavar='TYPE',
        help='API type: rest, graphql, soap, grpc, websocket, auto (default: auto)'
    )

    # === Scan Configuration ===
    scan_group = parser.add_argument_group(
        '⚙️  Scan Configuration',
        'Configure scan behavior and performance'
    )
    scan_group.add_argument(
        '--mode',
        choices=['safe', 'normal', 'aggressive'],
        default='normal',
        help='Scan mode: safe (minimal), normal (balanced), aggressive (intensive) (default: normal)'
    )
    scan_group.add_argument(
        '--threads',
        type=int,
        default=10,
        metavar='N',
        help='Number of concurrent threads (default: 10, max: 50)'
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=30,
        metavar='SEC',
        help='Request timeout in seconds (default: 30)'
    )
    scan_group.add_argument(
        '--max-endpoints',
        type=int,
        default=1000,
        metavar='N',
        help='Maximum endpoints to discover (default: 1000)'
    )
    scan_group.add_argument(
        '--delay',
        type=float,
        default=0,
        metavar='SEC',
        help='Delay between requests in seconds (default: 0)'
    )

    # === Authentication & Headers ===
    auth_group = parser.add_argument_group(
        '🔑 Authentication & Headers',
        'Configure authentication and custom headers'
    )
    auth_group.add_argument(
        '--header',
        action='append',
        metavar='HEADER',
        help='Custom header (format: "Key: Value"). Can be used multiple times'
    )
    auth_group.add_argument(
        '--auth-token',
        metavar='TOKEN',
        help='Authentication token (added as Authorization: Bearer <token>)'
    )
    auth_group.add_argument(
        '--cookie',
        metavar='COOKIE',
        help='Cookie header value'
    )
    auth_group.add_argument(
        '--user-agent',
        metavar='UA',
        default='OverApi/1.0',
        help='Custom User-Agent string (default: OverApi/1.0)'
    )

    # === Network & SSL ===
    network_group = parser.add_argument_group(
        '🌐 Network & SSL Configuration',
        'Configure network settings and SSL/TLS'
    )
    network_group.add_argument(
        '--proxy',
        metavar='URL',
        help='Proxy URL (format: http://ip:port or socks5://ip:port)'
    )
    network_group.add_argument(
        '--verify-ssl',
        action='store_true',
        default=True,
        help='Verify SSL certificates (default: enabled)'
    )
    network_group.add_argument(
        '--no-verify-ssl',
        action='store_false',
        dest='verify_ssl',
        help='Disable SSL certificate verification (NOT recommended for production)'
    )
    network_group.add_argument(
        '--custom-ca',
        dest='custom_ca_path',
        metavar='PATH',
        help='Path to custom CA certificate bundle'
    )

    # === Testing Modules ===
    testing_group = parser.add_argument_group(
        '🧪 Testing Modules',
        'Enable/disable specific security tests'
    )
    testing_group.add_argument(
        '--no-fuzzing',
        action='store_true',
        help='Disable endpoint fuzzing/discovery'
    )
    testing_group.add_argument(
        '--no-injection',
        action='store_true',
        help='Disable injection tests (SQLi, XSS, NoSQL, etc.)'
    )
    testing_group.add_argument(
        '--no-ratelimit',
        action='store_true',
        help='Disable rate limit testing'
    )
    testing_group.add_argument(
        '--no-bola',
        action='store_true',
        help='Disable BOLA (Broken Object Level Authorization) tests'
    )
    testing_group.add_argument(
        '--no-auth-bypass',
        action='store_true',
        help='Disable authentication bypass tests'
    )

    # === Wordlists & Data ===
    data_group = parser.add_argument_group(
        '📚 Wordlists & Data',
        'Configure custom wordlists and payloads'
    )
    data_group.add_argument(
        '--wordlist',
        metavar='PATH',
        help='Custom wordlist for endpoint discovery'
    )
    data_group.add_argument(
        '--payload-file',
        metavar='PATH',
        help='Custom payload file for injection tests'
    )

    # === Output Configuration ===
    output_group = parser.add_argument_group(
        '📊 Output Configuration',
        'Configure report generation and output'
    )
    output_group.add_argument(
        '--out',
        dest='output_html',
        metavar='PATH',
        help='HTML report output path (e.g., report.html)'
    )
    output_group.add_argument(
        '--json',
        dest='output_json',
        metavar='PATH',
        help='JSON report output path (e.g., results.json)'
    )
    output_group.add_argument(
        '--outdir',
        dest='output_dir',
        default='./reports',
        metavar='DIR',
        help='Output directory for reports (default: ./reports)'
    )
    output_group.add_argument(
        '--log-file',
        metavar='PATH',
        help='Log file path (default: stdout only)'
    )

    # === General Options ===
    general_group = parser.add_argument_group(
        '🔧 General Options',
        'General application settings'
    )
    general_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (debug mode)'
    )
    general_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (minimal output)'
    )
    general_group.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )


def validate_args(args) -> bool:
    """Validate parsed arguments."""
    errors = []

    # Validate threads
    if hasattr(args, 'threads') and (args.threads < 1 or args.threads > 50):
        errors.append("⚠️  Threads must be between 1 and 50")

    # Validate timeout
    if hasattr(args, 'timeout') and (args.timeout < 1 or args.timeout > 300):
        errors.append("⚠️  Timeout must be between 1 and 300 seconds")

    # Validate max endpoints
    if hasattr(args, 'max_endpoints') and args.max_endpoints < 1:
        errors.append("⚠️  Max endpoints must be at least 1")

    # Validate wordlist exists
    if hasattr(args, 'wordlist') and args.wordlist:
        if not Path(args.wordlist).exists():
            errors.append(f"⚠️  Wordlist file not found: {args.wordlist}")

    # Validate custom CA
    if hasattr(args, 'custom_ca_path') and args.custom_ca_path:
        if not Path(args.custom_ca_path).exists():
            errors.append(f"⚠️  Custom CA file not found: {args.custom_ca_path}")

    # Validate URL format
    if hasattr(args, 'url') and args.url:
        if not args.url.startswith(('http://', 'https://', 'ws://', 'wss://')):
            errors.append("⚠️  URL must start with http://, https://, ws://, or wss://")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return False

    return True


def show_info():
    """Display system and tool information."""
    import platform
    import sys

    print_banner()
    print("\n📋 System Information:")
    print(f"  • Python version: {sys.version.split()[0]}")
    print(f"  • Platform: {platform.system()} {platform.release()}")
    print(f"  • Architecture: {platform.machine()}")
    print(f"  • OverApi version: {__version__}")
    print("\n🔗 Links:")
    print("  • GitHub: https://github.com/GhostN3xus/OverApi")
    print("  • Issues: https://github.com/GhostN3xus/OverApi/issues")
    print("  • Documentation: https://github.com/GhostN3xus/OverApi/wiki")
    print("\n✨ Features:")
    print("  • REST, GraphQL, SOAP, gRPC, WebSocket support")
    print("  • OWASP API Top 10 testing")
    print("  • Injection testing (SQLi, XSS, NoSQL, Command Injection)")
    print("  • BOLA & authentication bypass detection")
    print("  • Rate limit & business logic testing")
    print("  • HTML & JSON reporting")
    print()


def handle_scan(args, logger: Logger) -> int:
    """Handle scan command."""
    try:
        # Parse custom headers
        custom_headers = {}
        if args.header:
            for header in args.header:
                if ': ' in header:
                    key, value = header.split(': ', 1)
                    custom_headers[key] = value
                else:
                    logger.warning(f"Invalid header format (ignored): {header}")

        # Add auth token if provided
        if args.auth_token:
            custom_headers['Authorization'] = f'Bearer {args.auth_token}'

        # Add cookie if provided
        if args.cookie:
            custom_headers['Cookie'] = args.cookie

        # Add User-Agent
        custom_headers['User-Agent'] = args.user_agent

        # Parse proxy
        proxy = None
        if args.proxy:
            proxy = ProxyConfig(http=args.proxy, https=args.proxy)

        # Create configuration
        config = Config(
            url=args.url,
            api_type=args.api_type if args.api_type != 'auto' else None,
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

        logger.info(f"🎯 Target: {args.url}")
        logger.info(f"⚙️  Mode: {args.mode}")
        logger.info(f"🧵 Threads: {args.threads}")
        logger.info("")

        # Run scanner
        scanner = Scanner(config, logger)
        results = scanner.scan()

        # Generate reports
        logger.info("\n📊 Generating reports...")
        report_gen = ReportGenerator(logger)
        report_gen.generate(
            results,
            output_html=args.output_html,
            output_json=args.output_json,
            output_dir=args.output_dir
        )

        logger.info("\n" + "=" * 70)
        logger.success("✅ OverApi scan completed successfully!")
        logger.info("=" * 70)

        return 0

    except OverApiException as e:
        logger.error(f"OverApi Error: {str(e)}")
        return 1

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Main entry point for CLI."""
    try:
        # Parse arguments
        parser = create_parser()
        args = parser.parse_args()

        # Show help if no command
        if not args.command:
            parser.print_help()
            return 0

        # Handle info command
        if args.command == 'info':
            show_info()
            return 0

        # Handle scan command
        if args.command == 'scan':
            # Show banner
            if not args.no_banner:
                print_banner()

            # Validate arguments
            if not validate_args(args):
                return 1

            # Initialize logger
            log_level = 10 if args.verbose else (30 if args.quiet else 20)
            logger = Logger(
                level=log_level,
                log_file=args.log_file,
                verbose=args.verbose
            )

            logger.info("🚀 Initializing OverApi Scanner...\n")

            return handle_scan(args, logger)

        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  Operation interrupted by user", file=sys.stderr)
        return 130

    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}", file=sys.stderr)
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
