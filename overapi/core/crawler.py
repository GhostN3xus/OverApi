"""
API Crawler/Spider for automatic endpoint discovery.

This module implements intelligent crawling of APIs to automatically discover
endpoints beyond simple wordlist-based bruteforcing.
"""

from typing import Set, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import deque
import re
import json

from .logger import Logger
from .config import Config
from .context import ScanContext, Endpoint
from ..utils.http_client import HTTPClient


class APICrawler:
    """
    Intelligent API crawler that discovers endpoints through:
    - Response parsing for links and references
    - Header analysis
    - JavaScript endpoint extraction
    - API documentation parsing
    - Path parameter inference
    - Endpoint relationship mapping
    """

    def __init__(self, context: ScanContext, config: Config, logger: Logger = None):
        """
        Initialize API crawler.

        Args:
            context: Scan context
            config: Configuration
            logger: Logger instance
        """
        self.context = context
        self.config = config
        self.logger = logger or Logger(__name__)
        self.http_client = HTTPClient(
            logger=self.logger,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
            proxy=config.proxy.get_proxies() if config.proxy else None,
            custom_ca_path=config.custom_ca_path
        )

        # Tracking structures
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.queue: deque = deque()
        self.max_depth = 5
        self.max_endpoints = config.max_endpoints

    def crawl(self, seed_urls: List[str] = None) -> List[Endpoint]:
        """
        Crawl API starting from seed URLs.

        Args:
            seed_urls: Initial URLs to start crawling from

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        if not seed_urls:
            seed_urls = [self.config.url]

        # Initialize queue
        for url in seed_urls:
            self.queue.append((url, 0))  # (url, depth)

        self.logger.info(f"Starting API crawl from {len(seed_urls)} seed URL(s)")

        while self.queue and len(self.discovered_endpoints) < self.max_endpoints:
            url, depth = self.queue.popleft()

            if url in self.visited_urls or depth > self.max_depth:
                continue

            self.visited_urls.add(url)

            try:
                # Crawl this URL
                new_endpoints = self._crawl_url(url, depth)
                endpoints.extend(new_endpoints)

                self.logger.debug(f"Crawled {url} (depth {depth}): found {len(new_endpoints)} endpoints")

            except Exception as e:
                self.logger.debug(f"Error crawling {url}: {str(e)}")

        self.logger.info(f"Crawl complete: discovered {len(endpoints)} unique endpoints")
        return endpoints

    def _crawl_url(self, url: str, depth: int) -> List[Endpoint]:
        """
        Crawl a single URL and extract endpoints.

        Args:
            url: URL to crawl
            depth: Current crawl depth

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        try:
            # Make request
            resp = self.http_client.get(url, timeout=self.config.timeout)

            if resp.status_code >= 400:
                return endpoints

            # Extract endpoints from response
            endpoints.extend(self._extract_from_json(resp, url))
            endpoints.extend(self._extract_from_html(resp, url))
            endpoints.extend(self._extract_from_headers(resp, url))
            endpoints.extend(self._extract_from_javascript(resp, url))

            # Queue new URLs for crawling
            if depth < self.max_depth:
                new_urls = self._extract_links(resp, url)
                for new_url in new_urls:
                    if new_url not in self.visited_urls:
                        self.queue.append((new_url, depth + 1))

        except Exception as e:
            self.logger.debug(f"Error in _crawl_url for {url}: {str(e)}")

        return endpoints

    def _extract_from_json(self, resp, base_url: str) -> List[Endpoint]:
        """Extract API endpoints from JSON responses."""
        endpoints = []

        try:
            if 'application/json' not in resp.headers.get('Content-Type', ''):
                return endpoints

            data = resp.json()

            # Look for common API patterns in JSON
            endpoints.extend(self._extract_json_urls(data, base_url))
            endpoints.extend(self._extract_json_paths(data, base_url))

        except Exception as e:
            self.logger.debug(f"JSON extraction error: {str(e)}")

        return endpoints

    def _extract_json_urls(self, data: Any, base_url: str, path: str = "") -> List[Endpoint]:
        """Recursively extract URLs from JSON data."""
        endpoints = []

        try:
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key

                    # Check if value is a URL
                    if isinstance(value, str):
                        if self._is_api_url(value):
                            endpoint = self._create_endpoint_from_url(value, base_url, "json_response")
                            if endpoint:
                                endpoints.append(endpoint)

                        # Common API keys that contain URLs
                        if key in ['url', 'href', 'link', 'endpoint', 'path', 'uri']:
                            endpoint = self._create_endpoint_from_url(value, base_url, f"json_{key}")
                            if endpoint:
                                endpoints.append(endpoint)

                    # Recurse into nested structures
                    elif isinstance(value, (dict, list)):
                        endpoints.extend(self._extract_json_urls(value, base_url, current_path))

            elif isinstance(data, list):
                for item in data:
                    endpoints.extend(self._extract_json_urls(item, base_url, path))

        except Exception as e:
            self.logger.debug(f"JSON URL extraction error: {str(e)}")

        return endpoints

    def _extract_json_paths(self, data: Any, base_url: str) -> List[Endpoint]:
        """Extract API paths from JSON keys that suggest endpoints."""
        endpoints = []

        try:
            if isinstance(data, dict):
                # Look for keys that might represent API endpoints
                api_keys = ['endpoints', 'routes', 'paths', 'apis', 'resources']

                for key in api_keys:
                    if key in data:
                        paths = data[key]

                        if isinstance(paths, list):
                            for path in paths:
                                if isinstance(path, str):
                                    endpoint = self._create_endpoint_from_path(path, base_url, f"json_{key}")
                                    if endpoint:
                                        endpoints.append(endpoint)

                        elif isinstance(paths, dict):
                            for path in paths.keys():
                                endpoint = self._create_endpoint_from_path(path, base_url, f"json_{key}")
                                if endpoint:
                                    endpoints.append(endpoint)

        except Exception as e:
            self.logger.debug(f"JSON path extraction error: {str(e)}")

        return endpoints

    def _extract_from_html(self, resp, base_url: str) -> List[Endpoint]:
        """Extract API endpoints from HTML content."""
        endpoints = []

        try:
            if 'text/html' not in resp.headers.get('Content-Type', ''):
                return endpoints

            html = resp.text

            # Extract from <a> tags
            links = re.findall(r'href=["\']([^"\']+)["\']', html)
            for link in links:
                if self._is_api_url(link):
                    endpoint = self._create_endpoint_from_url(link, base_url, "html_link")
                    if endpoint:
                        endpoints.append(endpoint)

            # Extract from <form> tags
            forms = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html)
            for action in forms:
                endpoint = self._create_endpoint_from_url(action, base_url, "html_form")
                if endpoint:
                    endpoint.method = "POST"  # Forms typically POST
                    endpoints.append(endpoint)

        except Exception as e:
            self.logger.debug(f"HTML extraction error: {str(e)}")

        return endpoints

    def _extract_from_headers(self, resp, base_url: str) -> List[Endpoint]:
        """Extract API endpoints from HTTP headers."""
        endpoints = []

        try:
            # Location header (redirects)
            if 'Location' in resp.headers:
                location = resp.headers['Location']
                endpoint = self._create_endpoint_from_url(location, base_url, "header_location")
                if endpoint:
                    endpoints.append(endpoint)

            # Link header (RFC 8288)
            if 'Link' in resp.headers:
                links = resp.headers['Link'].split(',')
                for link in links:
                    match = re.search(r'<([^>]+)>', link)
                    if match:
                        url = match.group(1)
                        endpoint = self._create_endpoint_from_url(url, base_url, "header_link")
                        if endpoint:
                            endpoints.append(endpoint)

            # Content-Location header
            if 'Content-Location' in resp.headers:
                location = resp.headers['Content-Location']
                endpoint = self._create_endpoint_from_url(location, base_url, "header_content_location")
                if endpoint:
                    endpoints.append(endpoint)

        except Exception as e:
            self.logger.debug(f"Header extraction error: {str(e)}")

        return endpoints

    def _extract_from_javascript(self, resp, base_url: str) -> List[Endpoint]:
        """Extract API endpoints from JavaScript code."""
        endpoints = []

        try:
            text = resp.text

            # Extract fetch() calls
            fetch_patterns = [
                r"fetch\(['\"]([^'\"]+)['\"]",
                r"fetch\(`([^`]+)`",
            ]

            for pattern in fetch_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    endpoint = self._create_endpoint_from_url(match, base_url, "js_fetch")
                    if endpoint:
                        endpoints.append(endpoint)

            # Extract axios calls
            axios_patterns = [
                r"axios\.get\(['\"]([^'\"]+)['\"]",
                r"axios\.post\(['\"]([^'\"]+)['\"]",
                r"axios\(['\"]([^'\"]+)['\"]",
            ]

            for pattern in axios_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    endpoint = self._create_endpoint_from_url(match, base_url, "js_axios")
                    if endpoint:
                        endpoints.append(endpoint)

            # Extract XMLHttpRequest calls
            xhr_patterns = [
                r"\.open\(['\"]GET['\"],\s*['\"]([^'\"]+)['\"]",
                r"\.open\(['\"]POST['\"],\s*['\"]([^'\"]+)['\"]",
            ]

            for pattern in xhr_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    endpoint = self._create_endpoint_from_url(match, base_url, "js_xhr")
                    if endpoint:
                        endpoints.append(endpoint)

            # Extract URL strings (conservative - must look like API endpoints)
            api_url_pattern = r'["\']/(api|v\d+)/[^"\']+["\']'
            matches = re.findall(api_url_pattern, text)
            for match in matches:
                # Remove quotes
                url = match.strip('"').strip("'")
                endpoint = self._create_endpoint_from_path(url, base_url, "js_string")
                if endpoint:
                    endpoints.append(endpoint)

        except Exception as e:
            self.logger.debug(f"JavaScript extraction error: {str(e)}")

        return endpoints

    def _extract_links(self, resp, base_url: str) -> List[str]:
        """Extract all links from response for further crawling."""
        links = []

        try:
            # From JSON
            try:
                if 'application/json' in resp.headers.get('Content-Type', ''):
                    data = resp.json()
                    links.extend(self._extract_json_links(data, base_url))
            except:
                pass

            # From HTML
            if 'text/html' in resp.headers.get('Content-Type', ''):
                html_links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                for link in html_links:
                    absolute_url = urljoin(base_url, link)
                    if self._should_crawl(absolute_url, base_url):
                        links.append(absolute_url)

        except Exception as e:
            self.logger.debug(f"Link extraction error: {str(e)}")

        return list(set(links))  # Deduplicate

    def _extract_json_links(self, data: Any, base_url: str) -> List[str]:
        """Recursively extract URLs from JSON for crawling."""
        links = []

        try:
            if isinstance(data, dict):
                for value in data.values():
                    if isinstance(value, str) and self._should_crawl(value, base_url):
                        links.append(urljoin(base_url, value))
                    elif isinstance(value, (dict, list)):
                        links.extend(self._extract_json_links(value, base_url))

            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and self._should_crawl(item, base_url):
                        links.append(urljoin(base_url, item))
                    elif isinstance(item, (dict, list)):
                        links.extend(self._extract_json_links(item, base_url))

        except:
            pass

        return links

    def _is_api_url(self, url: str) -> bool:
        """Check if URL looks like an API endpoint."""
        if not url:
            return False

        # Must be HTTP/HTTPS
        if not url.startswith(('http://', 'https://', '/')):
            return False

        # Common API patterns
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'\.json',
            r'/graphql',
            r'/rest/',
            r'/services/',
        ]

        for pattern in api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False

    def _should_crawl(self, url: str, base_url: str) -> bool:
        """Determine if URL should be crawled."""
        try:
            if not url:
                return False

            # Skip external domains (unless explicitly allowed)
            base_domain = urlparse(base_url).netloc
            url_domain = urlparse(urljoin(base_url, url)).netloc

            if url_domain != base_domain:
                return False

            # Skip certain file types
            skip_extensions = ['.jpg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False

            return True

        except:
            return False

    def _create_endpoint_from_url(self, url: str, base_url: str, source: str) -> Optional[Endpoint]:
        """Create Endpoint object from URL."""
        try:
            # Make URL absolute
            absolute_url = urljoin(base_url, url)

            # Parse URL
            parsed = urlparse(absolute_url)
            path = parsed.path

            if not path or path == '/':
                return None

            # Check if already discovered
            if path in self.discovered_endpoints:
                return None

            self.discovered_endpoints.add(path)

            # Create endpoint
            endpoint = Endpoint(
                path=path,
                method="GET",
                metadata={
                    "source": f"crawler_{source}",
                    "query_params": parse_qs(parsed.query),
                    "full_url": absolute_url
                }
            )

            # Add to context
            if self.context:
                self.context.add_endpoint(endpoint)

            return endpoint

        except Exception as e:
            self.logger.debug(f"Error creating endpoint from URL {url}: {str(e)}")
            return None

    def _create_endpoint_from_path(self, path: str, base_url: str, source: str) -> Optional[Endpoint]:
        """Create Endpoint object from path."""
        try:
            if not path:
                return None

            # Ensure path starts with /
            if not path.startswith('/'):
                path = '/' + path

            # Check if already discovered
            if path in self.discovered_endpoints:
                return None

            self.discovered_endpoints.add(path)

            # Create endpoint
            endpoint = Endpoint(
                path=path,
                method="GET",
                metadata={
                    "source": f"crawler_{source}",
                    "full_url": urljoin(base_url, path)
                }
            )

            # Add to context
            if self.context:
                self.context.add_endpoint(endpoint)

            return endpoint

        except Exception as e:
            self.logger.debug(f"Error creating endpoint from path {path}: {str(e)}")
            return None
