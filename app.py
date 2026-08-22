#!/usr/bin/env python3
"""
SentinelLog — Main Application Entry Point

Launches SentinelLog with default configurations or web interface.
"""

import sys
from sentinel import main

if __name__ == "__main__":
    # If no arguments provided, default to web dashboard
    if len(sys.argv) == 1:
        sys.argv.append("--web")
    main()
