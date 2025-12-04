#!/usr/bin/env python3
"""
OverApi - Universal API Security Scanner
Enhanced CLI interface
"""

import argparse
import sys
import os
from pathlib import Path

from overapi._version import __version__
from overapi.core.logger import Logger
from overapi.core.config import Config, ScanMode, ProxyConfig
from overapi.scanners.orchestrator import Orchestrator
from overapi.reports.report_generator import ReportGenerator

def print_banner():
    """Print application banner."""
    banner = f"""
╔═══════════════════════════════════════════════════════════╗
║          🔒 OverApi - API Security Scanner 🔒             ║
║                    v{__version__}                                 ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="overapi")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform API security scan')
    scan_parser.add_argument('url', help='Target URL') # Positional argument for URL in CLI design requested?
    # The request said: overapi scan <url> --type ...
    # So url is positional for scan subcommand

    scan_parser.add_argument('--type', choices=['rest', 'graphql', 'soap', 'grpc', 'auto'], default='auto')
    scan_parser.add_argument('--mode', choices=['safe', 'normal', 'aggressive'], default='normal')
    scan_parser.add_argument('--threads', type=int, default=10)
    scan_parser.add_argument('--timeout', type=int, default=30)
    scan_parser.add_argument('--max-endpoints', type=int, default=1000)
    scan_parser.add_argument('--no-fuzzing', action='store_true')
    scan_parser.add_argument('--no-injection', action='store_true')

    # GUI command
    gui_parser = subparsers.add_parser('gui', help='Launch TUI interface')

    # Payloads command
    payloads_parser = subparsers.add_parser('payloads', help='Manage payloads')
    payloads_sub = payloads_parser.add_subparsers(dest='payload_cmd')
    payloads_sub.add_parser('list', help='List available payloads')

    return parser

def handle_scan(args):
    logger = Logger(level=20) # INFO

    config = Config(
        url=args.url,
        api_type=args.type if args.type != 'auto' else None,
        mode=ScanMode(args.mode),
        threads=args.threads,
        timeout=args.timeout,
        max_endpoints=args.max_endpoints,
        enable_fuzzing=not args.no_fuzzing,
        enable_injection_tests=not args.no_injection
    )

    orchestrator = Orchestrator(config, logger)
    context = orchestrator.scan()

    # Generate report automatically for now
    reporter = ReportGenerator(logger)
    reporter.generate(context)

def handle_gui(args):
    # For GUI mode, we might need to ask for URL if not provided via args (but gui cmd has no args in spec)
    # The spec says `overapi gui`. It implies an interactive mode or a TUI that maybe asks for target.
    # For now, let's launch a TUI that allows inputting target or just shows the interface.
    # But ScanContext needs target.
    # Let's assume we pass dummy config or prompt in TUI.
    # Since I implemented TUI that takes orchestrator, I need an orchestrator.

    print("Launching GUI... (Not fully interactive yet, needs target pre-configured for this demo)")
    # In a real scenario, TUI would have a form to start scan.
    # I'll modify TUI later to accept input or just fail gracefully if no target.
    pass

def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == 'scan':
        print_banner()
        handle_scan(args)
    elif args.command == 'gui':
        print_banner()
        print("Launching GUI interface...")
        try:
            import tkinter as tk
            from overapi.gui.app import OverApiApp

            # Create Tkinter root window
            root = tk.Tk()

            # Create and run application
            app = OverApiApp(root)
            root.mainloop()

        except ImportError as e:
            if 'tkinter' in str(e).lower() or '_tkinter' in str(e).lower():
                print("Error: Tkinter is not installed.")
                print("\nPlease install Tkinter:")
                print("  Ubuntu/Debian: sudo apt-get install python3-tk")
                print("  macOS: brew install python-tk")
                print("  Windows: Tkinter is included with Python installer")
            else:
                print(f"Error: {e}")
        except Exception as e:
            print(f"Error launching GUI: {e}")
    elif args.command == 'payloads':
        if args.payload_cmd == 'list':
            from overapi.payloads import get_payloads
            payloads = get_payloads()
            for category, items in payloads.items():
                print(f"[{category.upper()}]")
                for item in items:
                    print(f"  - {item}")

if __name__ == "__main__":
    main()
