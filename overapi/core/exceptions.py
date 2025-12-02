"""Custom exceptions for OverApi."""


class OverApiException(Exception):
    """Base exception for OverApi."""
    pass


class APIDetectionError(OverApiException):
    """Raised when API type detection fails."""
    pass


class ScanningError(OverApiException):
    """Raised when scanning fails."""
    pass


class EndpointDiscoveryError(OverApiException):
    """Raised when endpoint discovery fails."""
    pass


class VulnerabilityTestError(OverApiException):
    """Raised when vulnerability test fails."""
    pass


class ReportGenerationError(OverApiException):
    """Raised when report generation fails."""
    pass


class NetworkError(OverApiException):
    """Raised when network error occurs."""
    pass


class AuthenticationError(OverApiException):
    """Raised when authentication fails."""
    pass
