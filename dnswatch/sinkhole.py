"""In-memory domain blocklist matcher for sinkholing operations."""

from __future__ import annotations

import os


class SinkholeBlocklist:
    """Fast in-memory domain blocklist supporting exact and wildcard suffix matching."""

    def __init__(self) -> None:
        self._exact: set[str] = set()
        self._wildcards: set[str] = set()

    def add(self, rule: str) -> None:
        """Add a domain rule to the blocklist.

        Supports:
        - Exact domain: 'ads.example.com'
        - Wildcard domain: '*.malware.test' (matches 'malware.test' and all subdomains)
        - Hosts file format: '0.0.0.0 bad.org' or '127.0.0.1 tracker.com'
        """
        line = rule.strip()
        if not line or line.startswith("#"):
            return

        # Strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        # Handle hosts file format (e.g. "0.0.0.0 bad.org" or "127.0.0.1 bad.org")
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            domain = parts[1].strip().lower().rstrip(".")
        else:
            domain = parts[0].strip().lower().rstrip(".")

        if not domain:
            return

        if domain.startswith("*."):
            suffix = domain[2:]
            if suffix:
                self._wildcards.add(suffix)
                self._exact.add(suffix)
        else:
            self._exact.add(domain)

    def load_file(self, filepath: str) -> int:
        """Load blocklist entries from a flat text or hosts-format file.

        Returns total active rules in the blocklist.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"blocklist file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self.add(line)

        return len(self)

    def load_text(self, text: str) -> int:
        """Load blocklist entries from a multi-line string.

        Returns total active rules in the blocklist.
        """
        for line in text.splitlines():
            self.add(line)
        return len(self)

    def is_blocked(self, domain: str) -> bool:
        """Check if domain matches any exact or wildcard blocklist rule."""
        clean = domain.strip().lower().rstrip(".")
        if not clean:
            return False

        if clean in self._exact:
            return True

        # Check wildcard parent domain suffixes
        labels = clean.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent in self._wildcards:
                return True

        return False

    def __contains__(self, domain: str) -> bool:
        return self.is_blocked(domain)

    def __len__(self) -> int:
        return len(self._exact) + len(self._wildcards)
