"""Single source of truth for version information."""

__version__ = "2.0.0"
__version_info__ = (2, 0, 0)
__edition__ = "Enterprise"
__build__ = "20241203"

__author__ = "GhostN3xus & OverApi Team"
__email__ = "security@overapi.dev"
__license__ = "MIT"
__url__ = "https://github.com/GhostN3xus/OverApi"

# Feature flags
FEATURES = {
    'enterprise_payloads': True,
    'pdf_reports': True,
    'plugin_system': True,
    'advanced_exporters': True,
    'tkinter_gui': True,
    'ml_detection': False,  # Future feature
    'cicd_integration': True,
}
