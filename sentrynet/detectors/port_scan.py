"""Port scan detection.

Tracks, per source IP, the set of distinct destination ports contacted
within a rolling time window -- a real scanner (or a compromised host doing
recon) looks like one source touching many ports on a target in a short
span, regardless of which scan technique it uses. On top of that, this
classifies the *technique* from the TCP flag combination on the probing
packets (SYN scan, FIN scan, NULL scan, XMAS scan), since the flag pattern
often fingerprints the tool being used against you, e.g. `nmap -sS` vs
`nmap -sN`.

Note: a lone SYN packet is indistinguishable from a normal connection
attempt -- that's true of real scan detection generally. The signal is in
the aggregate (many distinct ports, short window), which is exactly what
`port_threshold` and `window_seconds` gate on before anything is raised.
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, Optional

from scapy.all import IP, TCP, Packet

from ..alerting import Alert, Severity
from ..state import ExpiringSet
from .base import BaseDetector

# Standard TCP flag bits (masking off ECN/CWR/reserved bits).
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_MASK = 0x3F


def classify_scan(flags: int) -> Optional[str]:
    if flags == FLAG_SYN:
        return "SYN scan"
    if flags == 0:
        return "NULL scan"
    if flags == FLAG_FIN:
        return "FIN scan"
    if flags == (FLAG_FIN | FLAG_PSH | FLAG_URG):
        return "XMAS scan"
    return None


class PortScanDetector(BaseDetector):
    name = "port_scan"

    def __init__(
        self,
        window_seconds: float = 10.0,
        port_threshold: int = 15,
        cooldown_seconds: float = 30.0,
    ):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self.cooldown_seconds = cooldown_seconds
        self._ports_seen = ExpiringSet(window_seconds)
        self._last_alert: Dict[str, float] = {}

    def process(self, pkt: Packet) -> Iterable[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        src, dst, dport = ip_layer.src, ip_layer.dst, int(tcp_layer.dport)
        flags = int(tcp_layer.flags) & FLAG_MASK
        scan_type = classify_scan(flags)

        now = time.time()
        self._ports_seen.add(src, dport, now=now)
        distinct = self._ports_seen.distinct_count(src, now=now)

        if distinct < self.port_threshold:
            return []

        last = self._last_alert.get(src, 0.0)
        if now - last < self.cooldown_seconds:
            return []
        self._last_alert[src] = now

        label = scan_type or "port scan"
        severity = (
            Severity.HIGH if scan_type in ("SYN scan", "NULL scan", "XMAS scan") else Severity.MEDIUM
        )
        return [
            Alert(
                detector=self.name,
                severity=severity,
                message=(
                    f"{label} suspected: {src} touched {distinct} distinct ports "
                    f"on {dst} within {self.window_seconds:.0f}s"
                ),
                source_ip=src,
                dest_ip=dst,
                details={
                    "distinct_ports": distinct,
                    "window_seconds": self.window_seconds,
                    "flags": flags,
                    "scan_type": scan_type,
                },
            )
        ]
