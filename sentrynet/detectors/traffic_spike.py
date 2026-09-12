"""Volumetric traffic spike detection.

Buckets packet counts per key (by default, per source IP) into fixed-size
time intervals. When an interval closes, each key's rate for that interval
is scored against an EWMA baseline built from its own history using a
z-score, and a spike is only reported once the rate is both statistically
anomalous *and* past a minimum packet count (so a host going from 0 to 3
packets doesn't "spike" just because its baseline was near zero).

Scoring against a per-key rolling baseline, instead of one fixed packets/
second number for the whole network, is what lets this adapt to hosts with
very different normal traffic levels (a busy server vs. a quiet laptop)
without hand-tuning a threshold per host.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional

from scapy.all import IP, Packet

from ..alerting import Alert, Severity
from ..state import RollingRate
from .base import BaseDetector


def _default_key(pkt: Packet) -> Optional[str]:
    if pkt.haslayer(IP):
        return pkt[IP].src
    return None


class TrafficSpikeDetector(BaseDetector):
    name = "traffic_spike"

    def __init__(
        self,
        interval_seconds: float = 5.0,
        zscore_threshold: float = 3.5,
        min_packets: int = 20,
        ewma_alpha: float = 0.3,
        min_stddev: float = 1.0,
        key_fn: Callable[[Packet], Optional[str]] = _default_key,
    ):
        self.interval_seconds = interval_seconds
        self.zscore_threshold = zscore_threshold
        self.min_packets = min_packets
        # Floor applied to the baseline stddev (in packets/sec) before it's
        # used as the z-score denominator. Without this, a host with a
        # perfectly flat or very short history (stddev near 0) can never
        # trigger -- not because nothing anomalous happened, but purely
        # because dividing by ~0 is guarded against. The floor keeps a
        # genuine jump from a quiet/uniform baseline detectable instead of
        # silently unscoreable.
        self.min_stddev = min_stddev
        self.key_fn = key_fn

        self._lock = threading.Lock()
        self._counts: Dict[str, int] = defaultdict(int)
        self._window_start = time.time()
        self._rates = RollingRate(alpha=ewma_alpha)

    def process(self, pkt: Packet) -> Iterable[Alert]:
        key = self.key_fn(pkt)
        if key is None:
            return []

        alerts: List[Alert] = []
        now = time.time()
        with self._lock:
            self._counts[key] += 1
            elapsed = now - self._window_start
            if elapsed >= self.interval_seconds:
                alerts = self._flush(now)
        return alerts

    def _flush(self, now: float) -> List[Alert]:
        """Close out the current interval: score every key seen in it
        against its own EWMA baseline, update the baseline, and start a
        new interval. Must be called with self._lock held.
        """
        alerts: List[Alert] = []
        for key, count in self._counts.items():
            rate = count / self.interval_seconds
            mean, stddev = self._rates.update(key, rate)
            if count < self.min_packets:
                continue
            effective_stddev = max(stddev, self.min_stddev)
            zscore = (rate - mean) / effective_stddev
            if zscore >= self.zscore_threshold:
                severity = Severity.HIGH if zscore >= self.zscore_threshold * 1.5 else Severity.MEDIUM
                alerts.append(
                    Alert(
                        detector=self.name,
                        severity=severity,
                        message=(
                            f"Traffic spike from {key}: {rate:.1f} pkt/s vs "
                            f"baseline {mean:.1f} pkt/s (z={zscore:.1f})"
                        ),
                        source_ip=key,
                        details={
                            "rate": rate,
                            "baseline_mean": mean,
                            "baseline_stddev": stddev,
                            "effective_stddev": effective_stddev,
                            "zscore": zscore,
                            "interval_seconds": self.interval_seconds,
                        },
                    )
                )
        self._counts = defaultdict(int)
        self._window_start = now
        return alerts
