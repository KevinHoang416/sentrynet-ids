"""Thread-safe, time-windowed state primitives shared by detector modules.

Every detector needs some notion of "recent history" (distinct ports hit by
an IP in the last N seconds, a rolling baseline rate, a table of IP->MAC
bindings) without state growing without bound as the tool runs for hours.
These three primitives cover that for the whole project.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Hashable, Iterable, Optional, Tuple


class ExpiringSet:
    """Tracks distinct values seen per key within a rolling time window.

    Used for things like "distinct destination ports hit by source IP in
    the last N seconds" without the underlying set growing unbounded --
    entries older than the window are evicted lazily on access.
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._entries: Dict[Hashable, Deque[Tuple[float, Hashable]]] = defaultdict(deque)

    def add(self, key: Hashable, value: Hashable, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._entries[key]
            dq.append((now, value))
            self._evict(dq, now)

    def distinct_count(self, key: Hashable, now: Optional[float] = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._entries.get(key)
            if not dq:
                return 0
            self._evict(dq, now)
            return len({v for _, v in dq})

    def distinct_values(self, key: Hashable, now: Optional[float] = None) -> set:
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._entries.get(key)
            if not dq:
                return set()
            self._evict(dq, now)
            return {v for _, v in dq}

    def _evict(self, dq: Deque[Tuple[float, Hashable]], now: float) -> None:
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def keys(self) -> Iterable[Hashable]:
        with self._lock:
            return list(self._entries.keys())


class RollingRate:
    """EWMA-based rate tracker used for spike detection.

    Maintains an exponentially-weighted moving average and variance
    estimate of some per-interval value (e.g. packets/sec) for each key, so
    a new observation can be scored with a z-score against that key's own
    recent history instead of a fixed, hand-tuned threshold.
    """

    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self._lock = threading.Lock()
        self._mean: Dict[Hashable, float] = {}
        self._var: Dict[Hashable, float] = {}

    def update(self, key: Hashable, value: float) -> Tuple[float, float]:
        """Feed a new observation for `key`.

        Returns (mean, stddev) as they were *before* this observation was
        folded in, which is what you want to score the observation against.
        """
        with self._lock:
            prev_mean = self._mean.get(key, value)
            prev_var = self._var.get(key, 0.0)
            stddev_before = prev_var ** 0.5

            diff = value - prev_mean
            new_mean = prev_mean + self.alpha * diff
            new_var = (1 - self.alpha) * (prev_var + self.alpha * diff * diff)

            self._mean[key] = new_mean
            self._var[key] = new_var
            return prev_mean, stddev_before

    def zscore(self, key: Hashable, value: float) -> float:
        with self._lock:
            mean = self._mean.get(key, value)
            var = self._var.get(key, 0.0)
        stddev = var ** 0.5
        if stddev < 1e-6:
            return 0.0
        return (value - mean) / stddev


@dataclass
class MacBinding:
    mac: str
    first_seen: float
    last_seen: float
    seen_count: int = 1


class MacTable:
    """Thread-safe IP -> MAC binding table, used for ARP spoofing detection."""

    def __init__(self):
        self._lock = threading.Lock()
        self._bindings: Dict[str, MacBinding] = {}

    def observe(self, ip: str, mac: str, now: Optional[float] = None) -> Optional[MacBinding]:
        """Record an observed IP->MAC mapping.

        Returns the *previous* binding if this observation conflicts with
        it (i.e. the IP now maps to a different MAC than before), else
        None. The caller decides what a conflict means (alert, severity).
        """
        now = now if now is not None else time.time()
        with self._lock:
            existing = self._bindings.get(ip)
            if existing is None:
                self._bindings[ip] = MacBinding(mac=mac, first_seen=now, last_seen=now)
                return None
            if existing.mac == mac:
                existing.last_seen = now
                existing.seen_count += 1
                return None
            conflicting = MacBinding(**existing.__dict__)
            self._bindings[ip] = MacBinding(mac=mac, first_seen=now, last_seen=now)
            return conflicting

    def get(self, ip: str) -> Optional[MacBinding]:
        with self._lock:
            return self._bindings.get(ip)
