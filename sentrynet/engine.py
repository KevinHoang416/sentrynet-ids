"""Runtime engine that owns one capture/replay + detector run at a time,
and can be started and stopped on demand.

Originally the capture source (live interface or pcap file) was fixed at
process launch by CLI flags. Pulling that into its own class is what lets
the web dashboard offer real Start/Stop controls: `cli.py` still starts a
scan immediately when -i/--pcap is given (unchanged for scripted use), but
when none is given and the web dashboard is up, nothing runs until a
viewer picks a source and clicks Start.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .alerting import AlertManager
from .capture import LiveCapture, PcapReplay
from .detectors.base import BaseDetector


@dataclass
class ScanStatus:
    running: bool = False
    mode: Optional[str] = None  # "live" | "pcap"
    source: Optional[str] = None  # interface name, or pcap path
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    packet_count: int = 0
    dropped_count: int = 0


class ScanEngine:
    """Runs at most one scan at a time. `start()`/`stop()` are safe to call
    from any thread -- in particular, the web dashboard's HTTP handler
    thread calls them in response to POST /api/start and /api/stop while
    the scan itself runs on its own background thread.

    Status counters (`packet_count`, `dropped_count`) are updated from the
    scan thread and read from others without a lock -- they're for display
    only, so eventual consistency is fine, the same tradeoff already made
    for LiveCapture.dropped_count.
    """

    def __init__(
        self,
        detector_factory: Callable[[], List[BaseDetector]],
        alert_manager: AlertManager,
        on_packet: Optional[Callable[[], None]] = None,
    ):
        # A factory, not a fixed list: detectors carry rolling state
        # (ExpiringSet windows, EWMA baselines, MAC tables) that must not
        # leak between separate scan runs, so each start() builds fresh ones.
        self._detector_factory = detector_factory
        self.alert_manager = alert_manager
        self.on_packet = on_packet or (lambda: None)

        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._capture: Optional[LiveCapture] = None
        self._stop_flag = threading.Event()
        self.status = ScanStatus()

    def start(
        self,
        *,
        mode: str,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        pcap_path: Optional[str] = None,
        realtime_replay: bool = False,
    ) -> None:
        if mode not in ("live", "pcap"):
            raise ValueError(f"unknown mode {mode!r}; expected 'live' or 'pcap'")
        if mode == "pcap":
            if not pcap_path:
                raise ValueError("pcap_path is required for mode='pcap'")
            if not os.path.isfile(pcap_path):
                raise ValueError(f"pcap file not found: {pcap_path}")

        with self._lock:
            if self.status.running:
                raise RuntimeError("a scan is already running; stop it first")
            self._stop_flag.clear()
            detectors = self._detector_factory()
            self.status = ScanStatus(
                running=True,
                mode=mode,
                source=(interface or "default interface") if mode == "live" else pcap_path,
                started_at=time.time(),
            )
            self._thread = threading.Thread(
                target=self._run,
                args=(detectors, mode, interface, bpf_filter, pcap_path, realtime_replay),
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            was_running = self.status.running
            self._stop_flag.set()
            capture = self._capture
        if capture is not None:
            try:
                capture.stop()
            except Exception as exc:
                # A capture that never actually started (bad interface,
                # missing raw-socket permission) surfaces its real failure
                # right here, via scapy's stored exception. Record it the
                # same way a failure inside the scan thread itself would
                # be, rather than letting it raise out of stop() -- a Stop
                # click (or shutdown) right after a dead-on-arrival Start
                # should still report what went wrong, not crash the
                # caller (e.g. the web dashboard's /api/stop handler).
                self.status.error = str(exc)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        with self._lock:
            if was_running:
                self.status.running = False
                self.status.finished_at = time.time()
            self._thread = None
            self._capture = None

    def _run(
        self,
        detectors: List[BaseDetector],
        mode: str,
        interface: Optional[str],
        bpf_filter: str,
        pcap_path: Optional[str],
        realtime_replay: bool,
    ) -> None:
        try:
            if mode == "pcap":
                for pkt in PcapReplay(pcap_path, realtime=realtime_replay):
                    if self._stop_flag.is_set():
                        break
                    self._process(pkt, detectors)
                return

            capture = LiveCapture(iface=interface, bpf_filter=bpf_filter)
            with self._lock:
                self._capture = capture
            capture.start()

            # AsyncSniffer.start() returns immediately without waiting to
            # see whether the capture actually came up -- a permission
            # failure (not running as root/admin, the single most common
            # way someone runs into this) or an unknown interface name
            # kills its background thread almost instantly, but silently:
            # nothing raises here, and the packet queue would just sit
            # empty forever. Give it a brief moment, then check whether
            # that thread is still alive; if not, stop() re-raises scapy's
            # stored exception, which the except clause below turns into a
            # normal scan error instead of a scan that looks "running"
            # with zero packets and no explanation.
            time.sleep(0.2)
            if not capture.is_alive():
                capture.stop()
                return

            while not self._stop_flag.is_set():
                pkt = capture.get(timeout=1.0)
                if pkt is not None:
                    self._process(pkt, detectors)
                self.status.dropped_count = capture.dropped_count
            capture.stop()
            self.status.dropped_count = capture.dropped_count
        except Exception as exc:  # surface it to the UI instead of dying silently
            self.status.error = str(exc)
        finally:
            with self._lock:
                self.status.running = False
                self.status.finished_at = time.time()
                self._capture = None

    def _process(self, pkt, detectors: List[BaseDetector]) -> None:
        self.status.packet_count += 1
        self.on_packet()
        for detector in detectors:
            try:
                for alert in detector.process(pkt):
                    self.alert_manager.emit(alert)
            except Exception as exc:  # one bad packet must never kill the scan
                print(f"[{detector.name}] error processing packet: {exc}")
