"""Packet capture sources: live Scapy sniffing and pcap replay.

Both sources are consumed the same way by cli.py, so detectors never know
(or care) whether traffic is live or replayed from a file -- that's what
lets you validate the whole detector pipeline against a recorded attack
without needing a live network in front of you.
"""
from __future__ import annotations

import queue
import time
from typing import Optional

from scapy.all import AsyncSniffer, Packet, PcapReader
from scapy.error import Scapy_Exception


class LiveCapture:
    """Sniffs live traffic on an interface in a background thread and pushes
    packets onto a bounded queue for the main loop to drain.

    Detection logic deliberately does NOT run inside the Scapy sniff
    callback -- that callback just enqueues the packet and returns
    immediately, so a slow detector can never cause the capture thread to
    fall behind and drop packets at the OS level.
    """

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = "", queue_size: int = 10000):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._queue: "queue.Queue[Packet]" = queue.Queue(maxsize=queue_size)
        self._sniffer: Optional[AsyncSniffer] = None
        self._dropped = 0

    def _on_packet(self, pkt: Packet) -> None:
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._dropped += 1

    def start(self) -> None:
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter or None,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is None:
            return
        try:
            self._sniffer.stop()
        except Scapy_Exception:
            # AsyncSniffer.stop() raises exactly this ("Not running ! (check
            # .running attr)") if called before its background thread has
            # flipped to "running" yet -- a startup race when stop() follows
            # start() almost immediately, e.g. a quick Start-then-Stop click
            # in the web UI -- or if it already stopped on its own. Both
            # mean "already not running", which is exactly the state stop()
            # is trying to reach, so this one is safe to swallow.
            #
            # Anything else -- PermissionError (no raw-socket access, e.g.
            # not running as root/admin), OSError (bad/unknown interface
            # name) -- is scapy re-raising the real reason the capture
            # thread never actually started, via its stored `.exception`.
            # That must propagate so ScanEngine surfaces it as a scan error
            # instead of the capture looking like it's silently running
            # forever with zero packets.
            pass

    def is_alive(self) -> bool:
        """False once the sniffer's background thread has exited on its own
        -- for example because opening the socket failed (no permission, or
        no such interface). Checking this lets a caller notice a dead-on-
        arrival capture quickly, rather than only finding out when stop()
        is eventually called (e.g. when a user clicks Stop) and re-raises
        whatever exception killed the thread.
        """
        if self._sniffer is None or self._sniffer.thread is None:
            return False
        return self._sniffer.thread.is_alive()

    def get(self, timeout: float = 1.0) -> Optional[Packet]:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def dropped_count(self) -> int:
        return self._dropped


class PcapReplay:
    """Replays a .pcap file through the same pipeline as LiveCapture.

    By default packets are yielded as fast as possible (good for automated
    tests / quick validation). Set realtime=True to pace playback according
    to the packets' original timestamps, which is what you want when
    demoing detectors reacting to a recorded attack.
    """

    def __init__(self, path: str, realtime: bool = False, speed: float = 1.0):
        self.path = path
        self.realtime = realtime
        self.speed = speed

    def __iter__(self):
        last_ts: Optional[float] = None
        with PcapReader(self.path) as reader:
            for pkt in reader:
                if self.realtime:
                    ts = float(pkt.time)
                    if last_ts is not None:
                        delay = (ts - last_ts) / self.speed
                        if delay > 0:
                            time.sleep(delay)
                    last_ts = ts
                yield pkt
