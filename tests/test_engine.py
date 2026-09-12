import time

import pytest
from scapy.all import IP, TCP, wrpcap

from sentrynet.alerting import AlertManager
from sentrynet.engine import ScanEngine


def _wait_until(predicate, timeout=2.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_start_rejects_unknown_mode():
    engine = ScanEngine(detector_factory=lambda: [], alert_manager=AlertManager(console=False))
    with pytest.raises(ValueError, match="unknown mode"):
        engine.start(mode="carrier-pigeon")


def test_start_pcap_requires_a_path_that_exists():
    engine = ScanEngine(detector_factory=lambda: [], alert_manager=AlertManager(console=False))
    with pytest.raises(ValueError, match="pcap_path is required"):
        engine.start(mode="pcap")
    with pytest.raises(ValueError, match="not found"):
        engine.start(mode="pcap", pcap_path="does_not_exist.pcap")
    assert engine.status.running is False


def test_start_twice_without_stopping_raises(tmp_path):
    pcap_path = tmp_path / "many.pcap"
    wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)] * 500)

    engine = ScanEngine(detector_factory=lambda: [], alert_manager=AlertManager(console=False))
    engine.start(mode="pcap", pcap_path=str(pcap_path), realtime_replay=True)
    try:
        assert engine.status.running is True
        with pytest.raises(RuntimeError, match="already running"):
            engine.start(mode="pcap", pcap_path=str(pcap_path))
    finally:
        engine.stop()
    assert engine.status.running is False


def test_pcap_replay_processes_every_packet_and_settles_idle(tmp_path):
    pcap_path = tmp_path / "small.pcap"
    packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=p) for p in range(20)]
    wrpcap(str(pcap_path), packets)

    processed = []
    engine = ScanEngine(
        detector_factory=lambda: [],
        alert_manager=AlertManager(console=False),
        on_packet=lambda: processed.append(1),
    )
    engine.start(mode="pcap", pcap_path=str(pcap_path))
    assert _wait_until(lambda: not engine.status.running)

    assert len(processed) == 20
    assert engine.status.packet_count == 20
    assert engine.status.error is None
    assert engine.status.finished_at is not None


def test_stop_before_start_is_a_harmless_noop():
    engine = ScanEngine(detector_factory=lambda: [], alert_manager=AlertManager(console=False))
    engine.stop()  # must not raise
    assert engine.status.running is False


def test_live_capture_failure_surfaces_as_a_scan_error_not_a_silent_hang():
    # Regression test: without raw-socket permission (or with an unknown
    # interface name), scapy's AsyncSniffer thread dies almost instantly
    # but silently -- nothing raises from start(), and .running stays True
    # forever unless something calls .stop() to re-trigger scapy's stored
    # exception. Before this fix, engine.status.error was never populated
    # in that case: the dashboard would just show "Running" with zero
    # packets, indefinitely, with no explanation. An unknown interface
    # name is used here so this reproduces the same failure mode
    # regardless of whether the test runner happens to have raw-socket
    # privileges.
    engine = ScanEngine(detector_factory=lambda: [], alert_manager=AlertManager(console=False))
    engine.start(mode="live", interface="definitely-not-a-real-interface-xyz")

    assert _wait_until(lambda: not engine.status.running, timeout=3.0)
    assert engine.status.error is not None
    assert engine.status.error != ""


def test_rapid_start_then_stop_on_live_capture_does_not_raise():
    # Regression test: Scapy's AsyncSniffer.stop() raises if called before
    # its background thread has flipped its internal "running" flag, which
    # a web-UI user can trigger by clicking Start then Stop in quick
    # succession. Loopback is used so this doesn't need elevated
    # capture privileges to at least attempt starting a sniffer.
    engine = ScanEngine(detector_factory=lambda: [], alert_manager=AlertManager(console=False))
    for _ in range(5):
        try:
            engine.start(mode="live", interface="lo")
        except Exception:
            # Live capture may be unavailable/unprivileged in this
            # environment -- that's fine, we're only exercising stop()'s
            # robustness to a start that hasn't fully spun up yet.
            pass
        engine.stop()  # must never raise, regardless of the race above
        assert engine.status.running is False
