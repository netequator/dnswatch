"""Sliding-window anomaly tracking for DNS queries and NXDOMAIN bursts."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class NXDOMAINBurstAnomaly:
    """Telemetry event emitted when a client exceeds the NXDOMAIN burst threshold."""

    client_ip: str
    window_sec: float
    total_queries: int
    nxdomain_count: int
    nxdomain_ratio: float
    timestamp: float


class NXDOMAINTracker:
    """Sliding-window tracker for per-client NXDOMAIN query anomalies."""

    def __init__(
        self,
        window_sec: float = 60.0,
        min_queries: int = 10,
        min_nxdomain: int = 5,
        ratio_threshold: float = 0.5,
    ) -> None:
        self.window_sec = window_sec
        self.min_queries = min_queries
        self.min_nxdomain = min_nxdomain
        self.ratio_threshold = ratio_threshold
        # Map of client_ip -> deque of (timestamp, is_nxdomain)
        self._history: dict[str, deque[tuple[float, bool]]] = defaultdict(deque)

    def record_query(
        self, client_ip: str, rcode: str, now: float | None = None
    ) -> NXDOMAINBurstAnomaly | None:
        """Record a DNS response event and evaluate whether a burst threshold is met.

        Args:
            client_ip: Client IPv4 or IPv6 address.
            rcode: Response code string (e.g. "NXDOMAIN", "NOERROR").
            now: Event timestamp (defaults to time.time() if None for real-time capture).

        Returns:
            NXDOMAINBurstAnomaly if threshold exceeded, otherwise None.
        """
        ts = now if now is not None else time.time()
        is_nx = rcode.upper() == "NXDOMAIN"
        cutoff = ts - self.window_sec

        q = self._history[client_ip]
        q.append((ts, is_nx))

        # Evict events outside the sliding window
        while q and q[0][0] < cutoff:
            q.popleft()

        total = len(q)
        nx_count = sum(1 for _, is_nxdomain in q if is_nxdomain)

        if total >= self.min_queries and nx_count >= self.min_nxdomain:
            ratio = nx_count / total
            if ratio >= self.ratio_threshold:
                return NXDOMAINBurstAnomaly(
                    client_ip=client_ip,
                    window_sec=self.window_sec,
                    total_queries=total,
                    nxdomain_count=nx_count,
                    nxdomain_ratio=round(ratio, 4),
                    timestamp=ts,
                )

        return None

    def prune_stale(self, now: float | None = None) -> None:
        """Prune inactive client histories to conserve memory."""
        ts = now if now is not None else time.time()
        cutoff = ts - self.window_sec
        stale_clients = []

        for client_ip, q in self._history.items():
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                stale_clients.append(client_ip)

        for client_ip in stale_clients:
            del self._history[client_ip]
