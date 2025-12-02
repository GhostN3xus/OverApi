"""SecLists integration for advanced wordlist management."""

import os
import gzip
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import urljoin
import requests


logger = logging.getLogger(__name__)


class SecListsLoader:
    """Manage and download wordlists from SecLists repository."""

    # SecLists GitHub raw content URL
    GITHUB_BASE_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

    # Common directories in SecLists
    WORDLISTS = {
        "discovery": {
            "common_directories": "Discovery/Web-Content/common.txt",
            "web_content": "Discovery/Web-Content/raft-medium-words.txt",
            "api_endpoints": "Discovery/Web-Content/api/common.txt",
            "parameters": "Discovery/Web-Content/burp-parameter-names.txt",
            "subdomains": "Discovery/DNS/subdomains-top1million-5000.txt",
        },
        "payloads": {
            "sqli": "Payloads/SQL-Injection/sql-injection-payload-list.txt",
            "xss": "Payloads/XSS/xss-payload-list.txt",
            "xxe": "Payloads/XXE/xml-external-entity-injection-payloads.txt",
            "lfi": "Payloads/LFI/lfi-payload-list.txt",
            "command_injection": "Payloads/Command-Injection/command-injection-payload-list.txt",
        },
        "fuzzing": {
            "http_methods": "Discovery/Web-Content/http-methods.txt",
            "status_codes": "Payloads/HTTP-Status-Codes/http-status-codes.txt",
            "headers": "Payloads/HTTP-Headers/http-headers.txt",
        },
    }

    def __init__(self, cache_dir: Optional[str] = None, offline: bool = False):
        """
        Initialize SecLists loader.

        Args:
            cache_dir: Directory to cache downloaded wordlists (default: ~/.overapi/wordlists)
            offline: If True, only use cached wordlists (no downloads)
        """
        self.offline = offline
        self.cache_dir = Path(cache_dir or Path.home() / ".overapi" / "wordlists")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "OverApi/1.0 (Security Testing Tool)"
        })

    def _get_cache_path(self, wordlist_key: str) -> Path:
        """Get cache file path for a wordlist."""
        safe_name = wordlist_key.replace("/", "_").replace("-", "_")
        return self.cache_dir / f"{safe_name}.txt"

    def _download_wordlist(self, url: str, cache_path: Path, timeout: int = 30) -> bool:
        """
        Download wordlist from GitHub with retries.

        Args:
            url: Full URL to download
            cache_path: Local path to save wordlist
            timeout: Request timeout in seconds

        Returns:
            True if successful, False otherwise
        """
        if self.offline:
            logger.warning(f"Offline mode: cannot download {url}")
            return False

        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Downloading wordlist: {url} (attempt {attempt + 1}/{max_retries})")

                response = self.session.get(url, timeout=timeout, allow_redirects=True)
                response.raise_for_status()

                # Save to cache
                cache_path.write_bytes(response.content)
                logger.info(f"Successfully cached wordlist: {cache_path.name}")
                return True

            except requests.Timeout:
                logger.warning(f"Timeout downloading {url} (attempt {attempt + 1})")
            except requests.ConnectionError:
                logger.warning(f"Connection error downloading {url} (attempt {attempt + 1})")
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    logger.error(f"Wordlist not found: {url}")
                    return False
                logger.warning(f"HTTP error {e.response.status_code} (attempt {attempt + 1})")
            except Exception as e:
                logger.error(f"Error downloading wordlist: {str(e)}")

        return False

    def load_wordlist(self, category: str, name: str, merge_default: bool = True) -> List[str]:
        """
        Load a wordlist by category and name.

        Args:
            category: Category ('discovery', 'payloads', 'fuzzing')
            name: Wordlist name within category
            merge_default: Whether to merge with default wordlist

        Returns:
            List of wordlist entries
        """
        if category not in self.WORDLISTS or name not in self.WORDLISTS[category]:
            logger.warning(f"Unknown wordlist: {category}/{name}")
            return []

        wordlist_path = self.WORDLISTS[category][name]
        cache_path = self._get_cache_path(wordlist_path)

        # Try to load from cache first
        if cache_path.exists():
            return self._read_wordlist(cache_path)

        # Try to download if not offline
        if not self.offline:
            url = urljoin(self.GITHUB_BASE_URL, wordlist_path)
            if self._download_wordlist(url, cache_path):
                return self._read_wordlist(cache_path)

        logger.warning(f"Could not load wordlist: {category}/{name}")
        return []

    def load_local_wordlist(self, path: str) -> List[str]:
        """Load wordlist from local file."""
        try:
            return self._read_wordlist(Path(path))
        except Exception as e:
            logger.error(f"Error loading local wordlist: {str(e)}")
            return []

    def _read_wordlist(self, path: Path) -> List[str]:
        """
        Read wordlist from file (handles .gz and plain text).

        Args:
            path: Path to wordlist file

        Returns:
            List of cleaned wordlist entries
        """
        try:
            # Handle gzipped files
            if str(path).endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            else:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

            # Clean entries
            entries = []
            for line in lines:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#") and not line.startswith("//"):
                    entries.append(line)

            logger.info(f"Loaded {len(entries)} entries from {path.name}")
            return entries

        except Exception as e:
            logger.error(f"Error reading wordlist {path}: {str(e)}")
            return []

    def get_available_wordlists(self) -> Dict[str, List[str]]:
        """Get all available wordlists organized by category."""
        return self.WORDLISTS.copy()

    def list_cached_wordlists(self) -> List[str]:
        """List all cached wordlists."""
        if not self.cache_dir.exists():
            return []
        return [f.name for f in self.cache_dir.glob("*.txt")]

    def clear_cache(self, pattern: Optional[str] = None) -> int:
        """
        Clear cached wordlists.

        Args:
            pattern: Pattern to match (e.g., 'discovery_*'). If None, clear all.

        Returns:
            Number of files cleared
        """
        count = 0
        if not self.cache_dir.exists():
            return 0

        for file_path in self.cache_dir.glob("*.txt"):
            if pattern is None or pattern in file_path.name:
                try:
                    file_path.unlink()
                    count += 1
                except Exception as e:
                    logger.warning(f"Could not delete {file_path}: {str(e)}")

        logger.info(f"Cleared {count} cached wordlist(s)")
        return count

    def get_wordlist_info(self, category: str, name: str) -> Dict:
        """Get information about a specific wordlist."""
        if category not in self.WORDLISTS or name not in self.WORDLISTS[category]:
            return {}

        wordlist_path = self.WORDLISTS[category][name]
        cache_path = self._get_cache_path(wordlist_path)

        info = {
            "category": category,
            "name": name,
            "source_path": wordlist_path,
            "github_url": urljoin(self.GITHUB_BASE_URL, wordlist_path),
            "cached": cache_path.exists(),
            "cache_path": str(cache_path) if cache_path.exists() else None,
            "cache_size": cache_path.stat().st_size if cache_path.exists() else 0,
        }

        if cache_path.exists():
            entries = self._read_wordlist(cache_path)
            info["entry_count"] = len(entries)

        return info
