#!/usr/bin/env python3
"""
OverApi Enterprise - GUI Launcher
Launch the professional Tkinter interface
"""

import sys
import os

# Add overapi to path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from overapi.gui.tkinter_app import main

    if __name__ == '__main__':
        print("🔒 Starting OverApi Enterprise GUI...")
        print("=" * 60)
        main()
except ImportError as e:
    print(f"Error: Failed to import GUI module: {e}")
    print("\nMake sure tkinter is installed:")
    print("  - Ubuntu/Debian: sudo apt-get install python3-tk")
    print("  - Fedora/RHEL: sudo dnf install python3-tkinter")
    print("  - macOS: brew install python-tk")
    sys.exit(1)
except Exception as e:
    print(f"Error starting GUI: {e}")
    sys.exit(1)
