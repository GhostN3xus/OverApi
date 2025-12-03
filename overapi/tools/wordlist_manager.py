"""
Wordlist Manager for OverApi
"""

import os
from typing import List, Dict

class WordlistManager:
    """
    Manages wordlists for fuzzing and scanning.
    """

    def __init__(self, base_path: str = None):
        self.base_path = base_path or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'payloads', 'wordlists')
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path, exist_ok=True)

    def list_wordlists(self) -> List[str]:
        """List available wordlist files."""
        if not os.path.exists(self.base_path):
            return []
        return [f for f in os.listdir(self.base_path) if os.path.isfile(os.path.join(self.base_path, f))]

    def get_wordlist_path(self, name: str) -> str:
        """Get full path for a wordlist."""
        return os.path.join(self.base_path, name)

    def load_wordlist(self, name: str) -> List[str]:
        """Load content of a wordlist."""
        path = self.get_wordlist_path(name)
        if not os.path.exists(path):
            return []

        try:
            with open(path, 'r', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading wordlist {name}: {e}")
            return []

    def create_wordlist(self, name: str, content: List[str]):
        """Create a new wordlist."""
        path = self.get_wordlist_path(name)
        try:
            with open(path, 'w') as f:
                f.write('\n'.join(content))
        except Exception as e:
            print(f"Error creating wordlist {name}: {e}")

    def delete_wordlist(self, name: str):
        """Delete a wordlist."""
        path = self.get_wordlist_path(name)
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                print(f"Error deleting wordlist {name}: {e}")
