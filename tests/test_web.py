import json
import time
import urllib.error
import urllib.request

from sentrynet.alerting import Alert, AlertManager, Severity
from sentrynet.engine import ScanEngine
from sentrynet.web import WebDashboard


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _post(url, body):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _make_dashboard(alert_manager=None, detector_factory=None):
    alert_manager = alert_manager or AlertManager(console=False)
    engine = ScanEngine(detector_factory=detector_factory or (lambda: []), alert_manager=alert_manager)
    dashboard = WebDashboard(engine, detector_names=["port_scan", "arp_spoof"], port=0)
    return dashboard, engine


def test_web_dashboard_serves_index_and_state():
    alert_manager = AlertManager(console=False)
    alert_manager.emit(
        Alert(detector="port_scan", severity=Severity.HIGH, message="test alert", source_ip="10.0.0.5")
    )

    dashboard, engine = _make_dashboard(alert_manager=alert_manager)
    # port=0 asks the OS for a free port; read back what we actually bound to.
    dashboard.start()
    try:
        port = dashboard._server.server_address[1]
        base = f"http://127.0.0.1:{port}"

        engine.status.packet_count = 2

        status, body = _get(base + "/")
        assert status == 200
        assert b"Sentrynet" in body

        status, body = _get(base + "/api/state?limit=50")
        assert status == 200
        payload = json.loads(body)
        assert payload["packet_count"] == 2
        assert payload["detectors"] == ["port_scan", "arp_spoof"]
        assert len(payload["alerts"]) == 1
        assert payload["alerts"][0]["message"] == "test alert"
        assert payload["alerts"][0]["severity"] == "high"
        # No scan has been started yet -- the dashboard should report idle
        # rather than requiring a source at launch time.
        assert payload["scan"] == {"running": False, "mode": None, "source": None, "error": None}

        status, body = _get(base + "/api/nope")
        assert status == 404
    finally:
        dashboard.stop()


def test_web_dashboard_start_and_stop_a_pcap_scan(tmp_path):
    from scapy.all import IP, TCP, wrpcap

    pcap_path = tmp_path / "tiny.pcap"
    wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)])

    dashboard, engine = _make_dashboard()
    dashboard.start()
    try:
        port = dashboard._server.server_address[1]
        base = f"http://127.0.0.1:{port}"

        status, body = _post(base + "/api/start", {"mode": "pcap", "pcap_path": str(pcap_path)})
        assert status == 200
        assert json.loads(body)["ok"] is True

        # Give the background scan thread a moment to pick up the one packet
        # and, since a 1-packet pcap replay finishes almost instantly, to
        # settle back to idle on its own.
        for _ in range(20):
            if not engine.status.running:
                break
            time.sleep(0.05)

        status, body = _get(base + "/api/state")
        payload = json.loads(body)
        assert payload["scan"]["mode"] == "pcap"
        assert payload["scan"]["source"] == str(pcap_path)
        assert payload["packet_count"] >= 1

        # Stopping an already-finished scan should be a harmless no-op.
        status, body = _post(base + "/api/stop", {})
        assert status == 200
        assert json.loads(body)["ok"] is True
    finally:
        dashboard.stop()


def test_web_dashboard_start_rejects_bad_requests():
    dashboard, engine = _make_dashboard()
    dashboard.start()
    try:
        port = dashboard._server.server_address[1]
        base = f"http://127.0.0.1:{port}"

        # Unknown pcap path -- the engine validates before starting a thread.
        status, body = _post(base + "/api/start", {"mode": "pcap", "pcap_path": "does_not_exist.pcap"})
        assert status == 400
        payload = json.loads(body)
        assert payload["ok"] is False
        assert "not found" in payload["error"]
        assert engine.status.running is False

        # Unknown mode.
        status, body = _post(base + "/api/start", {"mode": "carrier-pigeon"})
        assert status == 400
        assert json.loads(body)["ok"] is False
    finally:
        dashboard.stop()


def test_web_dashboard_rejects_starting_a_second_scan_while_one_runs(tmp_path):
    from scapy.all import IP, TCP, wrpcap

    pcap_path = tmp_path / "one.pcap"
    wrpcap(str(pcap_path), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)] * 500)

    dashboard, engine = _make_dashboard()
    dashboard.start()
    try:
        port = dashboard._server.server_address[1]
        base = f"http://127.0.0.1:{port}"

        status, body = _post(base + "/api/start", {"mode": "pcap", "pcap_path": str(pcap_path), "realtime_replay": True})
        assert status == 200
        assert engine.status.running is True

        status, body = _post(base + "/api/start", {"mode": "pcap", "pcap_path": str(pcap_path)})
        assert status == 400
        payload = json.loads(body)
        assert payload["ok"] is False
        assert "already running" in payload["error"]

        status, body = _post(base + "/api/stop", {})
        assert status == 200
        assert engine.status.running is False
    finally:
        dashboard.stop()
