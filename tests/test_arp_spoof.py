from scapy.layers.l2 import ARP

from sentrynet.alerting import Severity
from sentrynet.detectors.arp_spoof import ArpSpoofDetector


def make_arp_reply(psrc, hwsrc):
    return ARP(op=2, psrc=psrc, hwsrc=hwsrc)


def test_first_binding_does_not_alert():
    det = ArpSpoofDetector()
    alerts = det.process(make_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
    assert not alerts


def test_repeated_same_mac_does_not_alert():
    det = ArpSpoofDetector()
    det.process(make_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
    alerts = det.process(make_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
    assert not alerts


def test_conflicting_mac_triggers_alert():
    det = ArpSpoofDetector(cooldown_seconds=0)
    det.process(make_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
    alerts = det.process(make_arp_reply("192.168.1.1", "bb:bb:bb:bb:bb:bb"))
    assert alerts
    assert alerts[0].details["old_mac"] == "aa:aa:aa:aa:aa:aa"
    assert alerts[0].details["new_mac"] == "bb:bb:bb:bb:bb:bb"
    assert alerts[0].severity == Severity.HIGH


def test_gateway_conflict_is_critical():
    det = ArpSpoofDetector(gateway_ips={"192.168.1.1"}, cooldown_seconds=0)
    det.process(make_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
    alerts = det.process(make_arp_reply("192.168.1.1", "bb:bb:bb:bb:bb:bb"))
    assert alerts[0].severity == Severity.CRITICAL


def test_arp_request_is_ignored():
    det = ArpSpoofDetector()
    alerts = det.process(ARP(op=1, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"))
    assert not alerts
