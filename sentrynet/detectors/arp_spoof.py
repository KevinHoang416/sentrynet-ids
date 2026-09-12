"""ARP spoofing / cache poisoning detection.

Maintains an IP -> MAC table built from observed ARP replies and raises an
alert whenever an IP that already has a known MAC suddenly appears to
belong to a different MAC -- the core signature of ARP cache poisoning,
whether it's done with arpspoof, ettercap, or a hand-rolled scapy script.
A conflict on a configured gateway IP is treated as CRITICAL rather than
HIGH, since redirecting the gateway is the classic man-in-the-middle setup
move (it puts the attacker between the victim and the rest of the network).
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, Optional, Set

from scapy.all import ARP, Packet

from ..alerting import Alert, Severity
from ..state import MacTable
from .base import BaseDetector

ARP_OP_REPLY = 2
NULL_MAC = "00:00:00:00:00:00"


class ArpSpoofDetector(BaseDetector):
    name = "arp_spoof"

    def __init__(
        self,
        gateway_ips: Optional[Set[str]] = None,
        cooldown_seconds: float = 15.0,
    ):
        self.gateway_ips = gateway_ips or set()
        self.cooldown_seconds = cooldown_seconds
        self._table = MacTable()
        self._last_alert: Dict[str, float] = {}

    def process(self, pkt: Packet) -> Iterable[Alert]:
        if not pkt.haslayer(ARP):
            return []

        arp = pkt[ARP]
        # op 1 = who-has (request), 2 = is-at (reply). We only trust
        # is-at announcements to update the table -- this also naturally
        # catches gratuitous ARP, which is an unsolicited is-at where the
        # sender is announcing/re-announcing its own IP->MAC mapping.
        if arp.op != ARP_OP_REPLY:
            return []

        ip, mac = arp.psrc, arp.hwsrc
        if not ip or not mac or mac == NULL_MAC:
            return []

        now = time.time()
        conflict = self._table.observe(ip, mac, now=now)
        if conflict is None:
            return []

        last = self._last_alert.get(ip, 0.0)
        if now - last < self.cooldown_seconds:
            return []
        self._last_alert[ip] = now

        is_gateway = ip in self.gateway_ips
        severity = Severity.CRITICAL if is_gateway else Severity.HIGH
        gw_note = " -- this is a configured GATEWAY IP" if is_gateway else ""

        return [
            Alert(
                detector=self.name,
                severity=severity,
                message=(
                    f"Possible ARP spoofing: {ip} was at {conflict.mac}, "
                    f"now claimed by {mac}{gw_note}"
                ),
                source_ip=ip,
                details={
                    "old_mac": conflict.mac,
                    "new_mac": mac,
                    "is_gateway": is_gateway,
                    "old_binding_seen_count": conflict.seen_count,
                },
            )
        ]
