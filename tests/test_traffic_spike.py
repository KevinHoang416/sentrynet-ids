import time

from scapy.layers.inet import ICMP, IP

from sentrynet.detectors.traffic_spike import TrafficSpikeDetector


def make_pkt(src):
    return IP(src=src, dst="10.0.0.1") / ICMP()


def test_spike_detected_after_baseline():
    det = TrafficSpikeDetector(interval_seconds=0.05, zscore_threshold=2.0, min_packets=5, ewma_alpha=0.5)

    alerts = []
    # Establish a quiet baseline across several short intervals.
    for _ in range(6):
        for _ in range(5):
            alerts.extend(det.process(make_pkt("10.0.0.9")))
        time.sleep(0.06)

    # Blast far more packets than baseline within one interval.
    for _ in range(200):
        alerts.extend(det.process(make_pkt("10.0.0.9")))
    time.sleep(0.06)
    alerts.extend(det.process(make_pkt("10.0.0.9")))  # forces the flush of the spike interval

    assert any(a.detector == "traffic_spike" for a in alerts)


def test_quiet_steady_traffic_does_not_spike():
    det = TrafficSpikeDetector(interval_seconds=0.05, zscore_threshold=3.5, min_packets=5, ewma_alpha=0.3)

    alerts = []
    for _ in range(8):
        for _ in range(5):
            alerts.extend(det.process(make_pkt("10.0.0.9")))
        time.sleep(0.06)

    assert not alerts


def test_spike_fires_even_with_a_perfectly_flat_baseline():
    # A hand-fed, exact-count baseline has ~zero natural variance. Without
    # a stddev floor this could never fire (dividing by ~0 is guarded
    # against by skipping, not by treating the deviation as significant),
    # even though a jump from a rock-steady baseline is exactly the kind
    # of thing this detector exists to catch.
    det = TrafficSpikeDetector(
        interval_seconds=0.05, zscore_threshold=3.0, min_packets=5, ewma_alpha=0.5, min_stddev=0.5
    )

    alerts = []
    for _ in range(6):
        for _ in range(10):  # exactly 10 packets every interval, no jitter
            alerts.extend(det.process(make_pkt("10.0.0.9")))
        time.sleep(0.06)

    assert not alerts, "identical baseline intervals should not themselves alert"

    for _ in range(200):
        alerts.extend(det.process(make_pkt("10.0.0.9")))
    time.sleep(0.06)
    alerts.extend(det.process(make_pkt("10.0.0.9")))

    assert any(a.detector == "traffic_spike" for a in alerts), (
        "a large jump from a flat baseline should still fire once a stddev floor is applied"
    )


def test_low_volume_intervals_are_ignored():
    det = TrafficSpikeDetector(interval_seconds=0.05, zscore_threshold=1.0, min_packets=50, ewma_alpha=0.5)

    alerts = []
    for _ in range(6):
        alerts.extend(det.process(make_pkt("10.0.0.9")))  # 1 packet per interval, below min_packets
        time.sleep(0.06)

    assert not alerts
