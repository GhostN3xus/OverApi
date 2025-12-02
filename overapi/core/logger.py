"""Logging system for OverApi."""

import logging
import sys
from datetime import datetime
from pathlib import Path


class Logger:
    """Centralized logging system for OverApi."""

    def __init__(self, name: str = "OverApi", level: int = logging.INFO,
                 log_file: str = None, verbose: bool = False):
        """
        Initialize logger.

        Args:
            name: Logger name
            level: Logging level
            log_file: Optional file to write logs
            verbose: Enable verbose mode
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.verbose = verbose

        # Clear existing handlers
        self.logger.handlers.clear()

        # Console handler with color
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message: str):
        """Debug level message."""
        if self.verbose:
            self.logger.debug(message)

    def info(self, message: str):
        """Info level message."""
        self.logger.info(message)

    def warning(self, message: str):
        """Warning level message."""
        self.logger.warning(message)

    def error(self, message: str):
        """Error level message."""
        self.logger.error(message)

    def critical(self, message: str):
        """Critical level message."""
        self.logger.critical(message)

    def success(self, message: str):
        """Success message (info level)."""
        self.logger.info(f"✓ {message}")

    def failure(self, message: str):
        """Failure message (warning level)."""
        self.logger.warning(f"✗ {message}")
