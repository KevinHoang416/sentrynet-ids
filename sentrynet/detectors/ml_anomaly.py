"""Experimental stretch detector: unsupervised anomaly scoring over simple
per-packet feature vectors using an Isolation Forest.

This is deliberately simple and is NOT a replacement for the rule-based
detectors above -- it's included to demonstrate where rule-based detection
tops out (things with no fixed signature) and how you'd start layering in
statistical/ML detection on top. It retrains periodically on a rolling
in-memory buffer of recent packets and is fully unsupervised, which means:

  * It needs a warm-up period ("warmup") on YOUR network's normal traffic
    before its baseline means anything. Enable it in a lab first.
  * Every alert is a low-confidence statistical outlier, not a labeled
    attack -- treat it as "worth a look", not "confirmed malicious".

Disabled by default in config.py. Requires scikit-learn and numpy; if
they're not installed, constructing this detector raises immediately with
a clear message rather than failing silently later.
"""
from __future__ import annotations

from collections import deque
from typing import Deque, Iterable, List, Optional

from scapy.all import IP, TCP, UDP, Packet

from ..alerting import Alert, Severity
from .base import BaseDetector

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class MLAnomalyDetector(BaseDetector):
    """Scores simple packet-level feature vectors (size, protocol, ports,
    TTL) against an Isolation Forest retrained periodically on a rolling
    buffer of recent traffic.
    """

    name = "ml_anomaly"

    def __init__(
        self,
        buffer_size: int = 2000,
        retrain_every: int = 200,
        contamination: float = 0.02,
        warmup: int = 500,
    ):
        if not SKLEARN_AVAILABLE:
            raise RuntimeError(
                "ml_anomaly is enabled but scikit-learn/numpy are not installed. "
                "Install them with 'pip install scikit-learn numpy', or set "
                "detectors.ml_anomaly.enabled: false in your config."
            )
        self.buffer_size = buffer_size
        self.retrain_every = retrain_every
        self.contamination = contamination
        self.warmup = warmup

        self._buffer: Deque[List[float]] = deque(maxlen=buffer_size)
        self._model: Optional["IsolationForest"] = None
        self._since_retrain = 0

    def _features(self, pkt: Packet) -> Optional[List[float]]:
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            proto, sport, dport = 6.0, float(pkt[TCP].sport), float(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto, sport, dport = 17.0, float(pkt[UDP].sport), float(pkt[UDP].dport)
        else:
            proto, sport, dport = 0.0, 0.0, 0.0
        return [float(len(pkt)), proto, sport, dport, float(ip.ttl)]

    def process(self, pkt: Packet) -> Iterable[Alert]:
        feats = self._features(pkt)
        if feats is None:
            return []

        self._buffer.append(feats)
        self._since_retrain += 1

        if len(self._buffer) < self.warmup:
            return []

        if self._model is None or self._since_retrain >= self.retrain_every:
            X = np.array(self._buffer)
            self._model = IsolationForest(contamination=self.contamination, random_state=0)
            self._model.fit(X)
            self._since_retrain = 0
            return []

        prediction = self._model.predict([feats])[0]
        if prediction != -1:
            return []

        score = self._model.decision_function([feats])[0]
        ip = pkt[IP]
        return [
            Alert(
                detector=self.name,
                severity=Severity.LOW,
                message=(
                    f"Statistical anomaly in flow {ip.src}->{ip.dst} "
                    f"(isolation score={score:.3f}); low-confidence unsupervised "
                    f"signal, investigate rather than act on directly"
                ),
                source_ip=ip.src,
                dest_ip=ip.dst,
                details={"isolation_score": float(score), "features": feats},
            )
        ]
