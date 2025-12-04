"""
Wordlist Manager for OverApi

Manages custom wordlists for fuzzing, parameter discovery, and payload generation.
"""

import os
from pathlib import Path
from typing import List, Dict, Optional, Set
import json
import logging


logger = logging.getLogger(__name__)


class WordlistManager:
    """
    Manages wordlists for fuzzing and discovery operations.

    Provides functionality to load, merge, filter, and manage
    custom wordlists for API security testing.
    """

    def __init__(self, wordlist_dir: Optional[Path] = None):
        """
        Initialize wordlist manager.

        Args:
            wordlist_dir: Directory containing wordlists
        """
        if wordlist_dir is None:
            # Default to wordlists directory in project
            wordlist_dir = Path(__file__).parent.parent.parent / "wordlists"

        self.wordlist_dir = Path(wordlist_dir)
        self.wordlist_dir.mkdir(parents=True, exist_ok=True)

        # Cache for loaded wordlists
        self._cache: Dict[str, List[str]] = {}

        # Built-in wordlists
        self._builtin_wordlists = {
            'api_endpoints': self._get_api_endpoints_wordlist(),
            'api_parameters': self._get_api_parameters_wordlist(),
            'http_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'],
            'common_paths': self._get_common_paths_wordlist(),
            'graphql_keywords': ['query', 'mutation', 'subscription', '__schema', '__type', 'IntrospectionQuery'],
            'soap_actions': ['GetInfo', 'GetData', 'PostData', 'UpdateData', 'DeleteData', 'Login', 'Logout'],
        }

    def _get_api_endpoints_wordlist(self) -> List[str]:
        """Get built-in API endpoints wordlist."""
        return [
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'soap',
            'users', 'user', 'account', 'accounts', 'admin', 'administrator',
            'auth', 'login', 'logout', 'register', 'signup', 'signin', 'signout',
            'token', 'tokens', 'refresh', 'oauth', 'oauth2',
            'profile', 'profiles', 'settings', 'config', 'configuration',
            'data', 'info', 'information', 'details',
            'list', 'search', 'find', 'query', 'filter',
            'create', 'update', 'delete', 'remove', 'modify',
            'get', 'post', 'put', 'patch',
            'products', 'product', 'items', 'item',
            'orders', 'order', 'cart', 'checkout', 'payment', 'payments',
            'billing', 'invoice', 'invoices', 'transactions', 'transaction',
            'customers', 'customer', 'clients', 'client',
            'reports', 'report', 'analytics', 'stats', 'statistics',
            'files', 'file', 'upload', 'download', 'documents', 'document',
            'images', 'image', 'photos', 'photo', 'media',
            'comments', 'comment', 'reviews', 'review', 'feedback',
            'messages', 'message', 'notifications', 'notification',
            'events', 'event', 'logs', 'log', 'audit',
            'dashboard', 'panel', 'console', 'management',
            'export', 'import', 'sync', 'backup', 'restore',
            'webhooks', 'webhook', 'callbacks', 'callback',
            'health', 'status', 'ping', 'version', 'info',
            'swagger', 'openapi', 'docs', 'documentation',
            'debug', 'test', 'dev', 'development', 'staging',
        ]

    def _get_api_parameters_wordlist(self) -> List[str]:
        """Get built-in API parameters wordlist."""
        return [
            'id', 'user_id', 'userId', 'uid', 'username', 'user',
            'email', 'mail', 'e-mail', 'address',
            'password', 'pass', 'passwd', 'pwd', 'secret',
            'token', 'auth', 'authorization', 'bearer',
            'api_key', 'apikey', 'key', 'access_key', 'secret_key',
            'name', 'first_name', 'last_name', 'full_name', 'fullname',
            'phone', 'telephone', 'mobile', 'cell',
            'address', 'street', 'city', 'state', 'country', 'zip', 'zipcode', 'postal_code',
            'date', 'time', 'datetime', 'timestamp', 'created_at', 'updated_at',
            'limit', 'offset', 'page', 'per_page', 'count', 'size',
            'sort', 'order', 'order_by', 'sort_by', 'direction',
            'filter', 'search', 'query', 'q', 'term',
            'status', 'state', 'active', 'enabled', 'disabled',
            'type', 'kind', 'category', 'class', 'group',
            'price', 'cost', 'amount', 'total', 'subtotal',
            'quantity', 'qty', 'count', 'number', 'num',
            'title', 'description', 'content', 'body', 'text',
            'url', 'link', 'href', 'uri', 'path',
            'file', 'filename', 'filepath', 'document',
            'image', 'photo', 'picture', 'avatar', 'thumbnail',
            'role', 'permission', 'permissions', 'access', 'rights',
            'callback', 'redirect', 'return_url', 'next', 'continue',
            'format', 'output', 'encoding', 'charset',
            'lang', 'language', 'locale', 'timezone',
            'debug', 'verbose', 'test', 'dry_run',
        ]

    def _get_common_paths_wordlist(self) -> List[str]:
        """Get built-in common paths wordlist."""
        return [
            '/', '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/graphql/', '/soap/',
            '/admin/', '/administrator/', '/management/',
            '/auth/', '/oauth/', '/oauth2/',
            '/users/', '/accounts/', '/profiles/',
            '/dashboard/', '/panel/', '/console/',
            '/docs/', '/documentation/', '/swagger/',
            '/health/', '/status/', '/ping/',
            '/.well-known/', '/robots.txt', '/sitemap.xml',
            '/config/', '/settings/', '/preferences/',
            '/upload/', '/download/', '/files/',
            '/images/', '/media/', '/assets/',
            '/backup/', '/tmp/', '/temp/',
            '/.git/', '/.svn/', '/.env',
        ]

    def load_wordlist(self, name: str, use_cache: bool = True) -> List[str]:
        """
        Load a wordlist by name.

        Args:
            name: Wordlist name (file name without extension or built-in name)
            use_cache: Whether to use cached wordlist if available

        Returns:
            List of words/entries
        """
        # Check cache first
        if use_cache and name in self._cache:
            logger.debug(f"Loading wordlist '{name}' from cache")
            return self._cache[name]

        # Check built-in wordlists
        if name in self._builtin_wordlists:
            logger.debug(f"Loading built-in wordlist '{name}'")
            wordlist = self._builtin_wordlists[name]
            self._cache[name] = wordlist
            return wordlist

        # Load from file
        wordlist_path = self.wordlist_dir / f"{name}.txt"
        if not wordlist_path.exists():
            # Try without adding .txt
            wordlist_path = self.wordlist_dir / name
            if not wordlist_path.exists():
                logger.warning(f"Wordlist '{name}' not found")
                return []

        logger.info(f"Loading wordlist from {wordlist_path}")
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            self._cache[name] = wordlist
            return wordlist

        except Exception as e:
            logger.error(f"Error loading wordlist '{name}': {e}")
            return []

    def save_wordlist(self, name: str, words: List[str], overwrite: bool = False):
        """
        Save a wordlist to file.

        Args:
            name: Wordlist name
            words: List of words to save
            overwrite: Whether to overwrite existing file
        """
        wordlist_path = self.wordlist_dir / f"{name}.txt"

        if wordlist_path.exists() and not overwrite:
            raise FileExistsError(f"Wordlist '{name}' already exists. Use overwrite=True to replace it.")

        logger.info(f"Saving wordlist to {wordlist_path}")
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(words))

        # Update cache
        self._cache[name] = words

    def merge_wordlists(self, names: List[str], deduplicate: bool = True) -> List[str]:
        """
        Merge multiple wordlists.

        Args:
            names: List of wordlist names to merge
            deduplicate: Whether to remove duplicates

        Returns:
            Merged wordlist
        """
        merged = []
        for name in names:
            wordlist = self.load_wordlist(name)
            merged.extend(wordlist)

        if deduplicate:
            # Preserve order while removing duplicates
            seen: Set[str] = set()
            unique = []
            for word in merged:
                if word not in seen:
                    seen.add(word)
                    unique.append(word)
            return unique

        return merged

    def filter_wordlist(self, wordlist: List[str], min_length: Optional[int] = None,
                       max_length: Optional[int] = None,
                       contains: Optional[str] = None,
                       starts_with: Optional[str] = None,
                       ends_with: Optional[str] = None) -> List[str]:
        """
        Filter wordlist based on criteria.

        Args:
            wordlist: Input wordlist
            min_length: Minimum word length
            max_length: Maximum word length
            contains: Must contain this substring
            starts_with: Must start with this string
            ends_with: Must end with this string

        Returns:
            Filtered wordlist
        """
        filtered = wordlist

        if min_length is not None:
            filtered = [w for w in filtered if len(w) >= min_length]

        if max_length is not None:
            filtered = [w for w in filtered if len(w) <= max_length]

        if contains is not None:
            filtered = [w for w in filtered if contains in w]

        if starts_with is not None:
            filtered = [w for w in filtered if w.startswith(starts_with)]

        if ends_with is not None:
            filtered = [w for w in filtered if w.endswith(ends_with)]

        return filtered

    def list_wordlists(self) -> Dict[str, Dict[str, any]]:
        """
        List all available wordlists.

        Returns:
            Dictionary with wordlist information
        """
        wordlists = {}

        # Built-in wordlists
        for name, wordlist in self._builtin_wordlists.items():
            wordlists[name] = {
                'type': 'built-in',
                'size': len(wordlist),
                'path': None
            }

        # File-based wordlists
        if self.wordlist_dir.exists():
            for wordlist_file in self.wordlist_dir.glob("*.txt"):
                name = wordlist_file.stem
                try:
                    size = sum(1 for _ in open(wordlist_file, 'r', encoding='utf-8', errors='ignore'))
                    wordlists[name] = {
                        'type': 'file',
                        'size': size,
                        'path': str(wordlist_file)
                    }
                except Exception as e:
                    logger.error(f"Error reading wordlist {wordlist_file}: {e}")

        return wordlists

    def get_stats(self, name: str) -> Dict[str, any]:
        """
        Get statistics about a wordlist.

        Args:
            name: Wordlist name

        Returns:
            Statistics dictionary
        """
        wordlist = self.load_wordlist(name)

        if not wordlist:
            return {
                'name': name,
                'exists': False
            }

        lengths = [len(w) for w in wordlist]

        return {
            'name': name,
            'exists': True,
            'total_entries': len(wordlist),
            'unique_entries': len(set(wordlist)),
            'duplicates': len(wordlist) - len(set(wordlist)),
            'min_length': min(lengths) if lengths else 0,
            'max_length': max(lengths) if lengths else 0,
            'avg_length': sum(lengths) / len(lengths) if lengths else 0,
            'total_characters': sum(lengths)
        }

    def create_custom_wordlist(self, name: str, base_words: List[str],
                              transformations: Optional[List[str]] = None) -> List[str]:
        """
        Create a custom wordlist with transformations.

        Args:
            name: Name for the new wordlist
            base_words: Base words to start from
            transformations: List of transformation types to apply

        Returns:
            Generated wordlist
        """
        if transformations is None:
            transformations = ['lowercase', 'uppercase', 'capitalize']

        wordlist = set(base_words)

        for word in base_words:
            if 'lowercase' in transformations:
                wordlist.add(word.lower())

            if 'uppercase' in transformations:
                wordlist.add(word.upper())

            if 'capitalize' in transformations:
                wordlist.add(word.capitalize())

            if 'snake_case' in transformations:
                wordlist.add(word.replace(' ', '_').lower())

            if 'camelCase' in transformations:
                words = word.split()
                if len(words) > 1:
                    camel = words[0].lower() + ''.join(w.capitalize() for w in words[1:])
                    wordlist.add(camel)

            if 'PascalCase' in transformations:
                pascal = ''.join(w.capitalize() for w in word.split())
                wordlist.add(pascal)

            if 'kebab-case' in transformations:
                wordlist.add(word.replace(' ', '-').lower())

        result = sorted(list(wordlist))
        self.save_wordlist(name, result, overwrite=True)
        return result

    def import_seclists(self, category: str = 'Discovery') -> Dict[str, List[str]]:
        """
        Import wordlists from SecLists format.

        Args:
            category: Category to import (Discovery, Fuzzing, etc.)

        Returns:
            Dictionary of imported wordlists
        """
        # This would integrate with the existing seclists_loader.py
        from overapi.utils.seclists_loader import SecListsLoader

        loader = SecListsLoader()
        return loader.load_category(category)

    def export_config(self, output_path: str):
        """
        Export wordlist configuration to JSON.

        Args:
            output_path: Path to output file
        """
        config = {
            'wordlist_dir': str(self.wordlist_dir),
            'wordlists': self.list_wordlists(),
            'built_in': list(self._builtin_wordlists.keys())
        }

        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)

        logger.info(f"Exported wordlist configuration to {output_path}")

    def clear_cache(self):
        """Clear the wordlist cache."""
        self._cache.clear()
        logger.info("Wordlist cache cleared")
