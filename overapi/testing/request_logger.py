"""Advanced request/response logger inspired by HTTP Workbench."""

import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
import httpx


@dataclass
class RequestLog:
    """Detailed request log entry."""

    timestamp: str
    method: str
    url: str
    headers: Dict[str, str]
    query_params: Optional[Dict[str, Any]]
    body: Optional[str]
    body_size: int
    content_type: Optional[str]

    # Response data
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_size: Optional[int] = None
    response_time: Optional[float] = None

    # Metadata
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class RequestLogger:
    """
    Advanced HTTP request/response logger with detailed capture capabilities.

    Inspired by HTTP Workbench's request logging features:
    - Captures complete headers (request and response)
    - Logs request/response bodies
    - Tracks timing and metadata
    - Stores IP addresses and user agents
    - Supports filtering and searching logs
    """

    def __init__(self, enabled: bool = True, max_body_size: int = 10000):
        """
        Initialize request logger.

        Args:
            enabled: Enable logging
            max_body_size: Maximum body size to log (bytes)
        """
        self.enabled = enabled
        self.max_body_size = max_body_size
        self.logs: List[RequestLog] = []

    def log_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        client_ip: Optional[str] = None
    ) -> RequestLog:
        """
        Log HTTP request details.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            params: Query parameters
            body: Request body
            client_ip: Client IP address

        Returns:
            RequestLog entry
        """
        if not self.enabled:
            return None

        headers = headers or {}

        # Process body
        body_str = None
        body_size = 0
        if body is not None:
            if isinstance(body, (dict, list)):
                body_str = json.dumps(body)
                body_size = len(body_str)
            elif isinstance(body, str):
                body_str = body
                body_size = len(body)
            elif isinstance(body, bytes):
                body_size = len(body)
                body_str = body.decode('utf-8', errors='ignore')

            # Truncate large bodies
            if body_size > self.max_body_size:
                body_str = body_str[:self.max_body_size] + f"... (truncated, total: {body_size} bytes)"

        log_entry = RequestLog(
            timestamp=datetime.utcnow().isoformat(),
            method=method.upper(),
            url=url,
            headers=dict(headers),
            query_params=params,
            body=body_str,
            body_size=body_size,
            content_type=headers.get('Content-Type'),
            client_ip=client_ip,
            user_agent=headers.get('User-Agent')
        )

        self.logs.append(log_entry)
        return log_entry

    def log_response(
        self,
        log_entry: RequestLog,
        response: httpx.Response,
        response_time: float
    ):
        """
        Add response details to existing log entry.

        Args:
            log_entry: Original request log entry
            response: HTTP response
            response_time: Response time in seconds
        """
        if not self.enabled or log_entry is None:
            return

        # Process response body
        response_body = None
        response_size = 0
        try:
            response_body = response.text
            response_size = len(response_body)

            # Truncate large responses
            if response_size > self.max_body_size:
                response_body = response_body[:self.max_body_size] + f"... (truncated, total: {response_size} bytes)"
        except Exception:
            response_body = "<binary data>"
            response_size = len(response.content) if hasattr(response, 'content') else 0

        log_entry.status_code = response.status_code
        log_entry.response_headers = dict(response.headers)
        log_entry.response_body = response_body
        log_entry.response_size = response_size
        log_entry.response_time = round(response_time, 3)

    def log_error(self, log_entry: RequestLog, error: Exception):
        """
        Log error for a request.

        Args:
            log_entry: Original request log entry
            error: Exception that occurred
        """
        if not self.enabled or log_entry is None:
            return

        log_entry.error = f"{type(error).__name__}: {str(error)}"

    def get_logs(
        self,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        url_contains: Optional[str] = None,
        has_error: Optional[bool] = None
    ) -> List[RequestLog]:
        """
        Get filtered logs.

        Args:
            method: Filter by HTTP method
            status_code: Filter by status code
            url_contains: Filter by URL substring
            has_error: Filter by error presence

        Returns:
            Filtered list of log entries
        """
        filtered_logs = self.logs

        if method:
            filtered_logs = [log for log in filtered_logs if log.method == method.upper()]

        if status_code:
            filtered_logs = [log for log in filtered_logs if log.status_code == status_code]

        if url_contains:
            filtered_logs = [log for log in filtered_logs if url_contains in log.url]

        if has_error is not None:
            filtered_logs = [log for log in filtered_logs if (log.error is not None) == has_error]

        return filtered_logs

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of logged requests.

        Returns:
            Summary dictionary
        """
        if not self.logs:
            return {
                "total_requests": 0,
                "methods": {},
                "status_codes": {},
                "errors": 0,
                "avg_response_time": 0
            }

        methods = {}
        status_codes = {}
        errors = 0
        response_times = []

        for log in self.logs:
            # Count methods
            methods[log.method] = methods.get(log.method, 0) + 1

            # Count status codes
            if log.status_code:
                status_codes[log.status_code] = status_codes.get(log.status_code, 0) + 1

            # Count errors
            if log.error:
                errors += 1

            # Collect response times
            if log.response_time:
                response_times.append(log.response_time)

        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        return {
            "total_requests": len(self.logs),
            "methods": methods,
            "status_codes": status_codes,
            "errors": errors,
            "avg_response_time": round(avg_response_time, 3)
        }

    def export_logs(self, filepath: Path, format: str = "json"):
        """
        Export logs to file.

        Args:
            filepath: Output file path
            format: Export format (json, txt)
        """
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump([log.to_dict() for log in self.logs], f, indent=2, default=str)
        elif format == "txt":
            with open(filepath, 'w') as f:
                for log in self.logs:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"[{log.timestamp}] {log.method} {log.url}\n")
                    f.write(f"Status: {log.status_code or 'N/A'}\n")
                    f.write(f"Response Time: {log.response_time or 'N/A'}s\n")
                    if log.error:
                        f.write(f"Error: {log.error}\n")
                    f.write(f"{'='*80}\n")

    def clear(self):
        """Clear all logs."""
        self.logs.clear()

    def __len__(self) -> int:
        """Return number of logged requests."""
        return len(self.logs)

    def __repr__(self) -> str:
        """String representation."""
        return f"<RequestLogger enabled={self.enabled} logs={len(self.logs)}>"
