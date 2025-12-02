"""Main scanner module for OverApi."""

from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from ..core.logger import Logger
from ..core.config import Config
from ..core.api_detector import APIDetector
from ..modules.rest.scanner import RestScanner
from ..modules.graphql.scanner import GraphQLScanner
from ..modules.soap.scanner import SoapScanner
from .security_tester import SecurityTester
from .fuzzer import Fuzzer


class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: Config, logger: Logger = None):
        """
        Initialize scanner.

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or Logger(__name__)
        self.detector = APIDetector(self.logger)
        self.security_tester = SecurityTester(self.logger)
        self.fuzzer = Fuzzer(self.logger)

        # Results collection
        self.results = {
            "target_url": config.url,
            "scan_start": time.time(),
            "detected_api_types": [],
            "endpoints": [],
            "vulnerabilities": [],
            "info": [],
            "errors": []
        }

    def scan(self) -> Dict[str, Any]:
        """
        Execute full scan.

        Returns:
            Scan results
        """
        try:
            self.logger.info("=" * 70)
            self.logger.info("Starting OverApi Security Scan")
            self.logger.info("=" * 70)

            # Step 1: Detect API type
            self.logger.info("\n[1/4] Detecting API type...")
            api_types, detection_details = self.detector.detect(self.config.url, self.config.timeout)
            self.results["detected_api_types"] = api_types
            self.results["detection_details"] = detection_details

            # Step 2: Discover endpoints
            self.logger.info("\n[2/4] Discovering endpoints...")
            endpoints = self._discover_endpoints(api_types)
            self.results["endpoints"] = endpoints
            self.logger.success(f"Discovered {len(endpoints)} endpoints")

            # Step 3: Security testing
            self.logger.info("\n[3/4] Running security tests...")
            vulnerabilities = self._run_security_tests(endpoints)
            self.results["vulnerabilities"] = vulnerabilities
            self.logger.success(f"Found {len(vulnerabilities)} potential vulnerabilities")

            # Step 4: Fuzzing (if enabled)
            if self.config.enable_fuzzing:
                self.logger.info("\n[4/4] Running intelligent fuzzing...")
                fuzzing_results = self._run_fuzzing(endpoints)
                self.results["vulnerabilities"].extend(fuzzing_results)
                self.logger.success(f"Fuzzing completed")

            self.results["scan_end"] = time.time()
            self.results["scan_duration"] = self.results["scan_end"] - self.results["scan_start"]

            self.logger.info("\n" + "=" * 70)
            self.logger.success("Scan completed successfully")
            self.logger.info("=" * 70)

            return self.results

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            self.results["errors"].append(str(e))
            raise

    def _discover_endpoints(self, api_types: List[str]) -> List[Dict]:
        """
        Discover endpoints for detected API types.

        Args:
            api_types: List of detected API types

        Returns:
            List of discovered endpoints
        """
        all_endpoints = []

        # REST discovery
        if "rest" in api_types:
            self.logger.debug("Running REST endpoint discovery...")
            rest_scanner = RestScanner(self.config, self.logger)
            endpoints = rest_scanner.discover_endpoints()
            all_endpoints.extend(endpoints)
            self.logger.debug(f"REST discovered {len(endpoints)} endpoints")

        # GraphQL discovery
        if "graphql" in api_types:
            self.logger.debug("Running GraphQL endpoint discovery...")
            graphql_scanner = GraphQLScanner(self.config, self.logger)
            endpoints = graphql_scanner.discover_fields()
            all_endpoints.extend(endpoints)
            self.logger.debug(f"GraphQL discovered {len(endpoints)} fields")

        # SOAP discovery
        if "soap" in api_types:
            self.logger.debug("Running SOAP endpoint discovery...")
            soap_scanner = SoapScanner(self.config, self.logger)
            endpoints = soap_scanner.discover_methods()
            all_endpoints.extend(endpoints)
            self.logger.debug(f"SOAP discovered {len(endpoints)} methods")

        return all_endpoints

    def _run_security_tests(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Run security tests on endpoints.

        Args:
            endpoints: List of endpoints

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []

            for endpoint in endpoints:
                future = executor.submit(
                    self.security_tester.test_endpoint,
                    endpoint,
                    self.config
                )
                futures.append(future)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"Test failed: {str(e)}")

        return vulnerabilities

    def _run_fuzzing(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Run intelligent fuzzing on endpoints.

        Args:
            endpoints: List of endpoints

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []

            for endpoint in endpoints[:self.config.max_endpoints]:
                future = executor.submit(
                    self.fuzzer.fuzz_endpoint,
                    endpoint,
                    self.config
                )
                futures.append(future)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.debug(f"Fuzzing failed: {str(e)}")

        return vulnerabilities
