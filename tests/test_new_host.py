from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP

from sentrynet.alerting import Severity
from sentrynet.detectors.new_host import NewHostDetector


def make_ip_packet(src, dst):
    return IP(src=src, dst=dst) / ICMP()


def test_first_sighting_of_each_ip_fires_one_info_alert_per_address():
    det = NewHostDetector()
    alerts = det.process(make_ip_packet("10.0.0.1", "10.0.0.2"))
    assert len(alerts) == 2
    assert {a.source_ip for a in alerts} == {"10.0.0.1", "10.0.0.2"}
    assert all(a.severity == Severity.INFO for a in alerts)


def test_repeat_traffic_between_known_hosts_does_not_re_alert():
    det = NewHostDetector()
    det.process(make_ip_packet("10.0.0.1", "10.0.0.2"))
    alerts = det.process(make_ip_packet("10.0.0.1", "10.0.0.2"))
    assert not alerts


def test_only_the_new_side_of_a_flow_re_alerts():
    det = NewHostDetector()
    det.process(make_ip_packet("10.0.0.1", "10.0.0.2"))
    alerts = det.process(make_ip_packet("10.0.0.1", "10.0.0.3"))
    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.3"


def test_arp_who_has_does_not_report_the_placeholder_target_address():
    det = NewHostDetector()
    # A "who-has" request leaves the target's protocol address as 0.0.0.0 --
    # that isn't a host at all and must not be reported as one.
    alerts = det.process(ARP(op=1, psrc="192.168.1.5", pdst="0.0.0.0"))
    assert len(alerts) == 1
    assert alerts[0].source_ip == "192.168.1.5"


def test_arp_reply_reports_both_sender_and_target():
    det = NewHostDetector()
    alerts = det.process(ARP(op=2, psrc="192.168.1.5", pdst="192.168.1.1"))
    assert {a.source_ip for a in alerts} == {"192.168.1.5", "192.168.1.1"}
