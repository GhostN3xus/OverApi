from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"

@dataclass
class Vulnerability:
    name: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    evidence: str
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: Optional[str] = None
    cvss: Optional[float] = None

@dataclass
class Endpoint:
    path: str
    method: str
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    is_authenticated: bool = False

@dataclass
class ScanContext:
    target: str
    api_type: str
    auth_config: Dict[str, Any] = field(default_factory=dict)
    bypass_options: Dict[str, Any] = field(default_factory=dict)

    # State
    status: ScanStatus = ScanStatus.PENDING
    endpoints: List[Endpoint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # Metrics
    requests_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    # Internal
    payloads_used: List[str] = field(default_factory=list)
    session_data: Dict[str, Any] = field(default_factory=dict)

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)

    def add_endpoint(self, endpoint: Endpoint):
        self.endpoints.append(endpoint)
