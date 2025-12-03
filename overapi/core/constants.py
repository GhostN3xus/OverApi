"""Application-wide constants for OverApi."""

# Timeout constants (seconds)
DEFAULT_REQUEST_TIMEOUT = 30
MIN_REQUEST_TIMEOUT = 1
MAX_REQUEST_TIMEOUT = 300

# Thread pool constants
DEFAULT_THREAD_COUNT = 10
MIN_THREAD_COUNT = 1
MAX_THREAD_COUNT = 200

# Endpoint limits
DEFAULT_MAX_ENDPOINTS = 1000
MIN_MAX_ENDPOINTS = 1
MAX_MAX_ENDPOINTS = 100000

# Wordlist limits
MAX_WORDLIST_SIZE_MB = 100
MAX_WORDLIST_SIZE_BYTES = MAX_WORDLIST_SIZE_MB * 1024 * 1024

# Scanning constants
DEFAULT_SQLI_PAYLOAD_LIMIT = 5
DEFAULT_XSS_PAYLOAD_LIMIT = 3
DEFAULT_CMD_INJECTION_PAYLOAD_LIMIT = 3
RATE_LIMIT_TEST_REQUESTS = 15
RATE_LIMIT_TEST_DELAY = 0.05

# JWT constants
MAX_JWT_TOKENS_PER_ENDPOINT = 5

# Response size limits
MAX_RESPONSE_BODY_SIZE_MB = 10

# Retry constants
DEFAULT_MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds
RETRY_BACKOFF_MULTIPLIER = 2

# HTTP status codes indicating errors (not vulnerabilities)
NON_VULNERABILITY_STATUS_CODES = [404, 405, 502, 503]

# Sensitive data keywords for detection
SENSITIVE_KEYWORDS = [
    'user', 'admin', 'key', 'token', 'password', 'config',
    'credential', 'secret', 'api_key', 'auth', 'session'
]

# Security headers that should be present
REQUIRED_SECURITY_HEADERS = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-XSS-Protection'
]

# Bypass test limits
MAX_BYPASS_ENDPOINTS = 20  # Limit bypass testing for performance

# Progress logging intervals
FUZZING_PROGRESS_INTERVAL = 100
ENDPOINT_TESTING_PROGRESS_INTERVAL = 10

# URL schemes
VALID_HTTP_SCHEMES = ['http', 'https']
VALID_WS_SCHEMES = ['ws', 'wss']
VALID_URL_SCHEMES = VALID_HTTP_SCHEMES + VALID_WS_SCHEMES

# API types
VALID_API_TYPES = ['rest', 'graphql', 'soap', 'grpc', 'websocket', 'webhook']

# Severity levels
SEVERITY_CRITICAL = 'Critical'
SEVERITY_HIGH = 'High'
SEVERITY_MEDIUM = 'Medium'
SEVERITY_LOW = 'Low'
SEVERITY_INFO = 'Info'

# OWASP API Security Top 10
OWASP_API1_BOLA = 'API1:2023 Broken Object Level Authorization'
OWASP_API2_AUTH = 'API2:2023 Broken Authentication'
OWASP_API3_DATA_EXPOSURE = 'API3:2023 Excessive Data Exposure'
OWASP_API4_RESOURCES = 'API4:2023 Lack of Resources & Rate Limiting'
OWASP_API5_BFLA = 'API5:2023 Broken Function Level Authorization'
OWASP_API6_MASS_ASSIGNMENT = 'API6:2023 Mass Assignment'
OWASP_API7_SECURITY_MISCONFIG = 'API7:2023 Security Misconfiguration'
OWASP_API8_INJECTION = 'API8:2023 Injection'
OWASP_API9_ASSET_MANAGEMENT = 'API9:2023 Improper Assets Management'
OWASP_API10_LOGGING = 'API10:2023 Insufficient Logging & Monitoring'

# Logging formats
LOG_FORMAT_STANDARD = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FORMAT_DETAILED = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'

# Report formats
REPORT_FORMAT_HTML = 'html'
REPORT_FORMAT_JSON = 'json'
REPORT_FORMAT_CSV = 'csv'
