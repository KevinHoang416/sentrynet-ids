"""Base interface all detector modules implement."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from scapy.all import Packet

from ..alerting import Alert


class BaseDetector(ABC):
    """A detector consumes packets one at a time and may emit zero or more
    Alert objects per packet. Detectors keep their own rolling state and
    are called synchronously from the main processing loop, so `process`
    should never block for long -- there is no per-packet work here beyond
    dict/deque bookkeeping and arithmetic.
    """

    name: str = "base"

    @abstractmethod
    def process(self, pkt: Packet) -> Iterable[Alert]:
        """Inspect a packet and return any alerts it triggers."""
        raise NotImplementedError
