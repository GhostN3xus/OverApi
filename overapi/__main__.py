#!/usr/bin/env python3
"""
OverApi - Universal API Security Scanner
Entry point when running as: python -m overapi
"""

import sys
from overapi.cli import main

if __name__ == "__main__":
    sys.exit(main())
