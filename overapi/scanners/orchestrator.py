"""Scanner Orchestrator."""

from typing import List, Dict, Any
from overapi.core.logger import Logger
from overapi.core.config import Config, ScanMode
from overapi.core.context import ScanContext, ScanStatus
from overapi.protocols.rest.scanner import RestScanner
# from overapi.protocols.graphql.scanner import GraphQLScanner
# from overapi.protocols.soap.scanner import SOAPScanner
# from overapi.protocols.grpc.scanner import GRPCScanner
from overapi.fuzzers.engine import FuzzingEngine
from overapi.bypass.engine import BypassEngine

class Orchestrator:
    def __init__(self, config: Config, logger: Logger = None):
        self.config = config
        self.logger = logger or Logger(__name__)
        self.context = ScanContext(
            target=config.url,
            api_type=config.api_type or "auto"
        )
        self.context.status = ScanStatus.RUNNING

        # Initialize engines
        self.fuzzer = FuzzingEngine(self.context, self.logger)
        self.bypass = BypassEngine()

    def scan(self) -> ScanContext:
        """Run the full scan pipeline."""
        self.logger.info("Starting scan pipeline...")

        try:
            # 1. Recon & Identification
            self._identify_api_type()

            # 2. Discovery
            self._discover_endpoints()

            # 3. Validation & Fuzzing
            if self.config.enable_fuzzing:
                self._fuzz_endpoints()

            # 4. Vulnerability Detection (e.g. Bypass, Injection)
            if self.config.enable_injection_tests:
                 self._detect_vulnerabilities()

            self.context.status = ScanStatus.COMPLETED

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted.")
            self.context.status = ScanStatus.STOPPED
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            self.context.status = ScanStatus.FAILED

        return self.context

    def _identify_api_type(self):
        """Identify API type if set to auto."""
        if self.context.api_type == "auto":
            # Simple heuristic
            # TODO: Implement robust detection
            self.context.api_type = "rest" # Default fallback
            self.logger.info(f"API Type identified as: {self.context.api_type}")

    def _discover_endpoints(self):
        """Discover endpoints based on API type."""
        self.logger.info("Discovering endpoints...")

        if self.context.api_type == "rest":
            scanner = RestScanner(self.context, self.config, self.logger)
            endpoints = scanner.discover_endpoints()
            # endpoints are already added to context by scanner

        # TODO: Implement other protocols

        self.logger.info(f"Discovered {len(self.context.endpoints)} endpoints.")

    def _fuzz_endpoints(self):
        """Fuzz discovered endpoints."""
        self.logger.info("Fuzzing endpoints...")
        for endpoint in self.context.endpoints:
            # Generate fuzz cases
            for case in self.fuzzer.fuzz_endpoint(endpoint):
                # Execute fuzz request (simplified)
                # In real impl, we would use http_client to send request
                pass

    def _detect_vulnerabilities(self):
        """Run vulnerability detectors."""
        self.logger.info("Running vulnerability detection...")
        # TODO: Integrate with specific scanners in overapi/scanners/
        pass
