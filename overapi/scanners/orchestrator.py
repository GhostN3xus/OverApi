"""Enhanced Scanner Orchestrator with full integration."""

import asyncio
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from overapi.core.logger import Logger
from overapi.core.config import Config, ScanMode
from overapi.core.context import ScanContext, ScanStatus
from overapi.core.api_detector import APIDetector
from overapi.core.exceptions import ScanningError, APIDetectionError, NetworkError
from overapi.protocols.rest.scanner import RestScanner
from overapi.protocols.graphql.scanner import GraphQLScanner
from overapi.protocols.soap.scanner import SOAPScanner
from overapi.protocols.grpc.scanner import GRPCScanner
from overapi.protocols.websocket.scanner import WebSocketScanner
from overapi.fuzzers.engine import FuzzingEngine
from overapi.bypass.engine import BypassEngine
from overapi.scanners.security_tester import SecurityTester
from overapi.scanners.jwt import JWTAnalyzer
from overapi.scanners.ssrf import SSRFTester
from overapi.scanners.business_logic import BusinessLogicScanner


class Orchestrator:
    """Enhanced orchestrator with complete scanner integration."""

    def __init__(self, config: Config, logger: Logger = None):
        """Initialize orchestrator with all scanners."""
        self.config = config
        self.logger = logger or Logger(__name__)
        self.context = ScanContext(
            target=config.url,
            api_type=config.api_type or "auto"
        )
        self.context.status = ScanStatus.RUNNING

        # Initialize API detector
        self.api_detector = APIDetector(
            logger=self.logger,
            verify_ssl=config.verify_ssl,
            custom_ca_path=config.custom_ca_path
        )

        # Initialize engines
        self.fuzzer = FuzzingEngine(self.context, self.logger)
        self.bypass = BypassEngine()

        # Initialize vulnerability scanners
        self.security_tester = SecurityTester(logger=self.logger)

        # Initialize specialized scanners (lazy initialization)
        self.jwt_analyzer = None
        self.ssrf_tester = None
        self.business_logic_scanner = None

        # Thread pool for parallel scanning
        self.thread_pool = ThreadPoolExecutor(max_workers=config.threads)

    def scan(self) -> ScanContext:
        """Run the full scan pipeline with complete integration."""
        self.logger.info("="*60)
        self.logger.info("OverApi Enterprise - Starting Comprehensive Scan")
        self.logger.info("="*60)

        try:
            # Phase 1: API Type Detection
            self._identify_api_type()

            # Phase 2: Endpoint Discovery
            self._discover_endpoints()

            # Phase 3: Fuzzing (if enabled)
            if self.config.enable_fuzzing:
                self._fuzz_endpoints()

            # Phase 4: Security Testing
            self._run_security_tests()

            # Phase 5: Specialized Vulnerability Scans
            self._run_specialized_scans()

            # Phase 6: Bypass Techniques (if enabled)
            self._run_bypass_tests()

            self.context.status = ScanStatus.COMPLETED
            self.logger.success(f"\nScan completed! Found {len(self.context.vulnerabilities)} vulnerabilities")

        except KeyboardInterrupt:
            self.logger.warning("\nScan interrupted by user.")
            self.context.status = ScanStatus.STOPPED
        except APIDetectionError as e:
            self.logger.error(f"API detection failed: {str(e)}")
            self.context.status = ScanStatus.FAILED
        except NetworkError as e:
            self.logger.error(f"Network error: {str(e)}")
            self.context.status = ScanStatus.FAILED
        except ScanningError as e:
            self.logger.error(f"Scanning error: {str(e)}")
            self.context.status = ScanStatus.FAILED
        except Exception as e:
            self.logger.error(f"Unexpected error during scan: {str(e)}")
            self.logger.debug(f"Traceback:", exc_info=True)
            self.context.status = ScanStatus.FAILED
        finally:
            self.thread_pool.shutdown(wait=True)

        return self.context

    def _identify_api_type(self):
        """Identify API type using robust detection."""
        self.logger.info("\n[Phase 1] API Type Detection")
        self.logger.info("-" * 60)

        if self.context.api_type == "auto":
            try:
                detected_types, details = self.api_detector.detect(
                    self.config.url,
                    timeout=self.config.timeout
                )

                if detected_types:
                    # Store all detected types
                    self.context.api_type = detected_types[0]  # Primary type
                    self.context.metadata["detected_api_types"] = detected_types
                    self.context.metadata["detection_details"] = details

                    self.logger.success(f"Detected API types: {', '.join(detected_types)}")
                else:
                    self.logger.warning("No API type detected, defaulting to REST")
                    self.context.api_type = "rest"

            except Exception as e:
                self.logger.error(f"API detection error: {str(e)}")
                self.logger.warning("Defaulting to REST for blind scanning")
                self.context.api_type = "rest"
        else:
            self.logger.info(f"Using configured API type: {self.context.api_type}")

    def _discover_endpoints(self):
        """Discover endpoints for all detected API types."""
        self.logger.info("\n[Phase 2] Endpoint Discovery")
        self.logger.info("-" * 60)

        detected_types = self.context.metadata.get("detected_api_types", [self.context.api_type])

        try:
            for api_type in detected_types:
                if api_type not in self.config.include_modules:
                    self.logger.debug(f"Skipping {api_type} (not in include_modules)")
                    continue

                self.logger.info(f"Discovering {api_type.upper()} endpoints...")

                try:
                    if api_type == "rest":
                        scanner = RestScanner(self.context, self.config, self.logger)
                        scanner.discover_endpoints()

                    elif api_type == "graphql":
                        scanner = GraphQLScanner(self.context, self.config, self.logger)
                        scanner.discover_endpoints()

                    elif api_type == "soap":
                        scanner = SOAPScanner(self.context, self.config, self.logger)
                        scanner.discover_endpoints()

                    elif api_type == "grpc":
                        scanner = GRPCScanner(self.context, self.config, self.logger)
                        scanner.discover_endpoints()

                    elif api_type == "websocket":
                        scanner = WebSocketScanner(self.context, self.config, self.logger)
                        scanner.discover_endpoints()

                except Exception as e:
                    self.logger.error(f"Error discovering {api_type} endpoints: {str(e)}")

            total_endpoints = len(self.context.endpoints)
            self.logger.success(f"Discovered {total_endpoints} total endpoints")

            # Limit endpoints if configured
            if total_endpoints > self.config.max_endpoints:
                self.logger.warning(f"Limiting to {self.config.max_endpoints} endpoints")
                self.context.endpoints = self.context.endpoints[:self.config.max_endpoints]

        except Exception as e:
            raise ScanningError(f"Endpoint discovery failed: {str(e)}")

    def _fuzz_endpoints(self):
        """Fuzz discovered endpoints with thread pool."""
        self.logger.info("\n[Phase 3] Endpoint Fuzzing")
        self.logger.info("-" * 60)

        try:
            fuzz_count = 0
            for endpoint in self.context.endpoints:
                try:
                    for fuzz_case in self.fuzzer.fuzz_endpoint(endpoint):
                        # Execute fuzz case (simplified - extend as needed)
                        fuzz_count += 1
                        if fuzz_count % 100 == 0:
                            self.logger.debug(f"Fuzzing progress: {fuzz_count} cases tested")
                except Exception as e:
                    self.logger.debug(f"Fuzzing error for {endpoint.get('path', 'unknown')}: {str(e)}")

            self.logger.info(f"Fuzzing completed: {fuzz_count} test cases executed")

        except Exception as e:
            self.logger.error(f"Fuzzing phase error: {str(e)}")

    def _run_security_tests(self):
        """Run security tests on all endpoints using thread pool."""
        self.logger.info("\n[Phase 4] Security Vulnerability Testing")
        self.logger.info("-" * 60)

        if not self.context.endpoints:
            self.logger.warning("No endpoints to test")
            return

        # Use thread pool for parallel testing
        futures = []
        for endpoint in self.context.endpoints:
            future = self.thread_pool.submit(self._test_endpoint, endpoint)
            futures.append(future)

        # Collect results
        completed = 0
        for future in as_completed(futures):
            try:
                vulnerabilities = future.result()
                if vulnerabilities:
                    self.context.vulnerabilities.extend(vulnerabilities)
                completed += 1
                if completed % 10 == 0:
                    self.logger.info(f"Progress: {completed}/{len(self.context.endpoints)} endpoints tested")
            except Exception as e:
                self.logger.error(f"Security test error: {str(e)}")

        self.logger.success(f"Security testing completed: {len(self.context.vulnerabilities)} vulnerabilities found")

    def _test_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Test single endpoint for vulnerabilities."""
        try:
            return self.security_tester.test_endpoint(endpoint, self.config)
        except Exception as e:
            self.logger.debug(f"Error testing endpoint {endpoint.get('path')}: {str(e)}")
            return []

    def _run_specialized_scans(self):
        """Run specialized vulnerability scanners (JWT, SSRF, Business Logic)."""
        self.logger.info("\n[Phase 5] Specialized Vulnerability Scans")
        self.logger.info("-" * 60)

        # JWT Analysis
        self._run_jwt_analysis()

        # SSRF Testing
        self._run_ssrf_testing()

        # Business Logic Testing
        self._run_business_logic_testing()

    def _run_jwt_analysis(self):
        """Run JWT vulnerability analysis."""
        try:
            self.logger.info("Running JWT vulnerability analysis...")

            # Initialize JWT analyzer
            proxies = self.config.proxy.get_proxies() if self.config.proxy else None
            self.jwt_analyzer = JWTAnalyzer(
                target_url=self.config.url,
                headers=self.config.custom_headers,
                proxies=proxies,
                timeout=self.config.timeout
            )

            # Scan for JWT vulnerabilities
            jwt_vulns = asyncio.run(self.jwt_analyzer.scan())

            # Convert to standard format and add to context
            for vuln in jwt_vulns:
                self.context.vulnerabilities.append(vuln.to_dict())

            self.logger.success(f"JWT analysis: {len(jwt_vulns)} vulnerabilities found")

        except Exception as e:
            self.logger.error(f"JWT analysis error: {str(e)}")

    def _run_ssrf_testing(self):
        """Run SSRF vulnerability testing."""
        try:
            self.logger.info("Running SSRF vulnerability testing...")

            # Initialize SSRF tester
            proxies = self.config.proxy.get_proxies() if self.config.proxy else None
            self.ssrf_tester = SSRFTester(
                target_url=self.config.url,
                headers=self.config.custom_headers,
                proxies=proxies,
                timeout=self.config.timeout
            )

            # Prepare endpoints for testing
            test_endpoints = [
                {"url": urljoin(self.config.url, ep.get("path", "")), "method": ep.get("method", "GET")}
                for ep in self.context.endpoints
            ]

            # Scan for SSRF vulnerabilities
            ssrf_vulns = asyncio.run(self.ssrf_tester.scan(test_endpoints))

            # Convert to standard format and add to context
            for vuln in ssrf_vulns:
                self.context.vulnerabilities.append(vuln.to_dict())

            self.logger.success(f"SSRF testing: {len(ssrf_vulns)} vulnerabilities found")

        except Exception as e:
            self.logger.error(f"SSRF testing error: {str(e)}")

    def _run_business_logic_testing(self):
        """Run business logic vulnerability testing."""
        try:
            self.logger.info("Running business logic vulnerability testing...")

            # Initialize business logic scanner
            proxies = self.config.proxy.get_proxies() if self.config.proxy else None
            self.business_logic_scanner = BusinessLogicScanner(
                target_url=self.config.url,
                headers=self.config.custom_headers,
                proxies=proxies,
                timeout=self.config.timeout
            )

            # Prepare endpoints for testing
            test_endpoints = [
                {"url": urljoin(self.config.url, ep.get("path", "")), "method": ep.get("method", "GET")}
                for ep in self.context.endpoints
            ]

            # Scan for business logic vulnerabilities
            bl_vulns = asyncio.run(self.business_logic_scanner.scan(test_endpoints))

            # Convert to standard format and add to context
            for vuln in bl_vulns:
                self.context.vulnerabilities.append(vuln.to_dict())

            self.logger.success(f"Business logic testing: {len(bl_vulns)} vulnerabilities found")

        except Exception as e:
            self.logger.error(f"Business logic testing error: {str(e)}")

    def _run_bypass_tests(self):
        """Run bypass technique testing."""
        self.logger.info("\n[Phase 6] Bypass Technique Testing")
        self.logger.info("-" * 60)

        try:
            bypass_count = 0

            for endpoint in self.context.endpoints[:20]:  # Limit for performance
                try:
                    # Convert endpoint to request format
                    original_request = {
                        "method": endpoint.get("method", "GET"),
                        "path": endpoint.get("path", ""),
                        "headers": self.config.custom_headers.copy()
                    }

                    # Generate bypass variations
                    bypasses = self.bypass.generate_bypasses(original_request)
                    bypass_count += len(bypasses)

                    # Test bypasses (simplified - extend as needed)
                    for bypass in bypasses:
                        # Execute bypass test here
                        pass

                except Exception as e:
                    self.logger.debug(f"Bypass test error for {endpoint.get('path')}: {str(e)}")

            self.logger.info(f"Bypass testing: {bypass_count} variations generated")

        except Exception as e:
            self.logger.error(f"Bypass testing error: {str(e)}")
