#!/usr/bin/env python3
"""
OverApi GUI Launcher
Launch the graphical user interface for OverApi Scanner
"""

import sys
import tkinter as tk
from pathlib import Path

# Add overapi to path
sys.path.insert(0, str(Path(__file__).parent))

from overapi.gui.app import OverApiApp


def main():
    """Main entry point for GUI."""
    try:
        # Create main window
        root = tk.Tk()

        # Create application
        app = OverApiApp(root)

        # Run main loop
        root.mainloop()

    except ImportError as e:
        print(f"❌ Error: Missing dependency - {e}")
        print("\n📦 Please install GUI dependencies:")
        print("   Ubuntu/Debian: sudo apt-get install python3-tk")
        print("   macOS: brew install python-tk")
        print("   Windows: Tkinter is included with Python")
        sys.exit(1)

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
