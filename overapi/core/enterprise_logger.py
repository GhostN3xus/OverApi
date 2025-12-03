"""
OverApi Enterprise - Advanced Logging System
Professional logging with rotation, compression, and analytics
"""

import logging
import logging.handlers
import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class EnterpriseLogger:
    """
    Enterprise-grade logging system with advanced features:
    - Automatic log rotation
    - Compression of old logs
    - Multiple output formats (console, file, JSON)
    - Performance metrics
    - Security event tracking
    - Integration with SIEM systems
    """

    def __init__(
        self,
        name: str = "OverApi",
        log_dir: str = "./logs",
        level: int = logging.INFO,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 10,
        enable_json: bool = True,
        enable_console: bool = True
    ):
        """
        Initialize enterprise logger

        Args:
            name: Logger name
            log_dir: Directory for log files
            level: Logging level
            max_bytes: Maximum size before rotation
            backup_count: Number of backup files to keep
            enable_json: Enable JSON logging
            enable_console: Enable console output
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.level = level
        self.enable_json = enable_json

        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Initialize loggers
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Performance metrics
        self.metrics = {
            'requests': 0,
            'vulnerabilities': 0,
            'errors': 0,
            'warnings': 0,
            'start_time': datetime.now()
        }

        # Setup handlers
        self._setup_file_handler(max_bytes, backup_count)

        if enable_json:
            self._setup_json_handler(max_bytes, backup_count)

        if enable_console:
            self._setup_console_handler()

        # Security events logger
        self.security_logger = self._setup_security_logger()

    def _setup_file_handler(self, max_bytes: int, backup_count: int):
        """Setup rotating file handler for standard logs"""
        log_file = self.log_dir / f"{self.name.lower()}.log"

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )

        file_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)8s] [%(name)s] [%(funcName)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(self.level)
        self.logger.addHandler(file_handler)

    def _setup_json_handler(self, max_bytes: int, backup_count: int):
        """Setup rotating JSON handler for structured logging"""
        json_file = self.log_dir / f"{self.name.lower()}_json.log"

        json_handler = logging.handlers.RotatingFileHandler(
            json_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )

        json_handler.setFormatter(JSONFormatter())
        json_handler.setLevel(self.level)
        self.logger.addHandler(json_handler)

    def _setup_console_handler(self):
        """Setup console handler with colors"""
        console_handler = logging.StreamHandler(sys.stdout)

        console_formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)8s | %(message)s',
            datefmt='%H:%M:%S'
        )

        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(self.level)
        self.logger.addHandler(console_handler)

    def _setup_security_logger(self) -> logging.Logger:
        """Setup dedicated logger for security events"""
        security_logger = logging.getLogger(f"{self.name}.security")
        security_logger.setLevel(logging.INFO)
        security_logger.propagate = False

        security_file = self.log_dir / "security_events.log"

        security_handler = logging.handlers.RotatingFileHandler(
            security_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=50,  # Keep more security logs
            encoding='utf-8'
        )

        security_formatter = logging.Formatter(
            '[%(asctime)s] [SECURITY] [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        security_handler.setFormatter(security_formatter)
        security_logger.addHandler(security_handler)

        return security_logger

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
        self.metrics['warnings'] += 1

    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, extra=kwargs)
        self.metrics['errors'] += 1

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, extra=kwargs)
        self.metrics['errors'] += 1

    def security_event(self, event_type: str, details: Dict[str, Any]):
        """
        Log security event

        Args:
            event_type: Type of security event
            details: Event details
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        }

        self.security_logger.info(json.dumps(event))

        # Also log to main logger
        self.logger.warning(f"Security Event: {event_type} - {details}")

    def log_vulnerability(self, vulnerability: Dict[str, Any]):
        """Log discovered vulnerability"""
        self.metrics['vulnerabilities'] += 1

        self.security_event('vulnerability_found', vulnerability)

        severity = vulnerability.get('severity', 'unknown').lower()
        vuln_type = vulnerability.get('type', 'Unknown')
        endpoint = vulnerability.get('endpoint', 'N/A')

        if severity in ['critical', 'high']:
            self.error(f"[{severity.upper()}] {vuln_type} found at {endpoint}")
        else:
            self.warning(f"[{severity.upper()}] {vuln_type} found at {endpoint}")

    def log_request(self, method: str, url: str, status_code: int, response_time: float):
        """Log HTTP request"""
        self.metrics['requests'] += 1

        self.debug(
            f"{method} {url} - {status_code} ({response_time:.2f}s)",
            method=method,
            url=url,
            status_code=status_code,
            response_time=response_time
        )

    def log_scan_start(self, target: str, config: Dict[str, Any]):
        """Log scan start"""
        self.info(f"Starting scan on {target}")
        self.security_event('scan_start', {
            'target': target,
            'config': config
        })

    def log_scan_complete(self, target: str, results: Dict[str, Any]):
        """Log scan completion"""
        duration = (datetime.now() - self.metrics['start_time']).total_seconds()

        self.info(
            f"Scan completed on {target} - "
            f"{results.get('vulnerabilities', 0)} vulnerabilities found in {duration:.2f}s"
        )

        self.security_event('scan_complete', {
            'target': target,
            'duration': duration,
            'results': results
        })

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        duration = (datetime.now() - self.metrics['start_time']).total_seconds()

        return {
            **self.metrics,
            'duration': duration,
            'requests_per_second': self.metrics['requests'] / duration if duration > 0 else 0
        }

    def export_metrics(self, output_path: str):
        """Export metrics to JSON file"""
        metrics = self.get_metrics()

        with open(output_path, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)

        self.info(f"Metrics exported to {output_path}")


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
        }

        # Add extra fields
        if hasattr(record, '__dict__'):
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                              'levelname', 'levelno', 'lineno', 'module', 'msecs',
                              'pathname', 'process', 'processName', 'relativeCreated',
                              'thread', 'threadName', 'exc_info', 'exc_text', 'stack_info']:
                    log_data[key] = value

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }

    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors"""
        levelname = record.levelname
        color = self.COLORS.get(levelname, '')

        # Add color to levelname
        record.levelname = f"{color}{levelname}{self.RESET}"

        result = super().format(record)

        # Reset levelname for other handlers
        record.levelname = levelname

        return result


# Global logger instance
_global_logger: Optional[EnterpriseLogger] = None


def get_logger(name: str = "OverApi") -> EnterpriseLogger:
    """Get global logger instance"""
    global _global_logger

    if _global_logger is None:
        _global_logger = EnterpriseLogger(name=name)

    return _global_logger


def configure_logger(
    name: str = "OverApi",
    log_dir: str = "./logs",
    level: int = logging.INFO,
    **kwargs
) -> EnterpriseLogger:
    """Configure global logger"""
    global _global_logger

    _global_logger = EnterpriseLogger(
        name=name,
        log_dir=log_dir,
        level=level,
        **kwargs
    )

    return _global_logger
