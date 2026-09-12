from scapy.layers.inet import IP, TCP

from sentrynet.detectors.port_scan import PortScanDetector


def make_syn(src, dst, dport):
    return IP(src=src, dst=dst) / TCP(sport=12345, dport=dport, flags="S")


def test_syn_scan_triggers_alert():
    det = PortScanDetector(window_seconds=10, port_threshold=5, cooldown_seconds=0)
    alerts = []
    for port in range(1, 6):
        alerts.extend(det.process(make_syn("10.0.0.5", "10.0.0.1", port)))
    assert alerts, "expected an alert once the distinct-port threshold is crossed"
    assert alerts[-1].source_ip == "10.0.0.5"
    assert "SYN scan" in alerts[-1].message


def test_repeated_hits_on_one_port_do_not_trigger():
    det = PortScanDetector(window_seconds=10, port_threshold=15, cooldown_seconds=0)
    alerts = []
    for _ in range(50):
        alerts.extend(det.process(make_syn("10.0.0.5", "10.0.0.1", 443)))
    assert not alerts, "many packets to a single port is normal traffic, not a scan"


def test_cooldown_suppresses_repeat_alerts():
    det = PortScanDetector(window_seconds=10, port_threshold=3, cooldown_seconds=1000)
    alerts = []
    for port in range(1, 4):
        alerts.extend(det.process(make_syn("10.0.0.5", "10.0.0.1", port)))
    assert len(alerts) == 1
    for port in range(4, 7):
        alerts.extend(det.process(make_syn("10.0.0.5", "10.0.0.1", port)))
    assert len(alerts) == 1, "cooldown should suppress a second alert right after the first"


def test_null_scan_is_classified():
    det = PortScanDetector(window_seconds=10, port_threshold=3, cooldown_seconds=0)
    alerts = []
    for port in range(1, 4):
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=12345, dport=port, flags=0)
        alerts.extend(det.process(pkt))
    assert alerts
    assert "NULL scan" in alerts[-1].message
