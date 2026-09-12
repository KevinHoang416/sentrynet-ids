"""Asset-visibility detector: flags the first time an IP address is seen
on the network, at INFO severity.

A new host showing up isn't a threat signal by itself -- that's completely
normal on any real network -- but knowing when a previously-unseen address
starts talking is exactly the kind of low-noise, informational fact a SOC
dashboard should still surface: "a new device joined" rather than "you're
being attacked". It's genuinely useful for asset visibility (spotting an
unexpected device on a segment you thought you knew), and it's the only
detector here that reports at INFO rather than something actionable.

Each address is reported once per scan: restarting a scan clears the
"seen" set, so a fresh run re-announces everyone. That's deliberate -- a
scan represents one observation window, not a permanent inventory, so
"new" means "new to this window", not "new ever".
"""
from __future__ import annotations

from typing import Iterable, Set

from scapy.all import ARP, IP, Packet

from ..alerting import Alert, Severity
from .base import BaseDetector


class NewHostDetector(BaseDetector):
    name = "new_host"

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def process(self, pkt: Packet) -> Iterable[Alert]:
        alerts = []
        for ip, via in self._addresses(pkt):
            if ip in self._seen:
                continue
            self._seen.add(ip)
            alerts.append(
                Alert(
                    detector=self.name,
                    severity=Severity.INFO,
                    message=f"New host observed on the network: {ip}",
                    source_ip=ip,
                    details={"first_seen_via": via},
                )
            )
        return alerts

    def _addresses(self, pkt: Packet) -> Iterable[tuple]:
        """Yields (ip, description) for every address a packet introduces.
        IP traffic reports both ends of the flow; ARP reports whichever of
        sender/target protocol addresses are real (a "who-has" request
        legitimately leaves the target's own address as 0.0.0.0, which
        isn't a host at all and must not be reported as one).
        """
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            proto = pkt.sprintf("%IP.proto%")
            yield ip_layer.src, f"{proto} traffic"
            yield ip_layer.dst, f"{proto} traffic"
        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.psrc and arp.psrc != "0.0.0.0":
                yield arp.psrc, "ARP"
            if arp.pdst and arp.pdst != "0.0.0.0":
                yield arp.pdst, "ARP"
