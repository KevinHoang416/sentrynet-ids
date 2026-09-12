"""CLI entrypoint: builds the detector set and a ScanEngine, optionally
starts the terminal and/or web dashboard, and either starts a scan right
away (when -i/--pcap was given, for scripted use) or leaves the engine
idle so a scan can be started from the web dashboard instead.
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from typing import Any, Dict, List, Optional

from .alerting import AlertManager
from .config import load_config
from .detectors.arp_spoof import ArpSpoofDetector
from .detectors.base import BaseDetector
from .detectors.new_host import NewHostDetector
from .detectors.port_scan import PortScanDetector
from .detectors.traffic_spike import TrafficSpikeDetector
from .engine import ScanEngine


def build_detectors(cfg: Dict[str, Any]) -> List[BaseDetector]:
    detectors: List[BaseDetector] = []
    d_cfg = cfg["detectors"]

    if d_cfg["port_scan"]["enabled"]:
        c = {k: v for k, v in d_cfg["port_scan"].items() if k != "enabled"}
        detectors.append(PortScanDetector(**c))

    if d_cfg["arp_spoof"]["enabled"]:
        c = {k: v for k, v in d_cfg["arp_spoof"].items() if k != "enabled"}
        detectors.append(ArpSpoofDetector(gateway_ips=set(cfg.get("gateway_ips") or []), **c))

    if d_cfg["traffic_spike"]["enabled"]:
        c = {k: v for k, v in d_cfg["traffic_spike"].items() if k != "enabled"}
        detectors.append(TrafficSpikeDetector(**c))

    if d_cfg["new_host"]["enabled"]:
        detectors.append(NewHostDetector())

    if d_cfg["ml_anomaly"]["enabled"]:
        from .detectors.ml_anomaly import MLAnomalyDetector

        c = {k: v for k, v in d_cfg["ml_anomaly"].items() if k != "enabled"}
        detectors.append(MLAnomalyDetector(**c))

    return detectors


def build_alert_manager(cfg: Dict[str, Any]) -> AlertManager:
    a_cfg = cfg["alerting"]
    syslog_address = None
    if a_cfg.get("syslog"):
        syslog_address = (a_cfg["syslog"]["host"], a_cfg["syslog"].get("port", 514))
    return AlertManager(
        console=a_cfg.get("console", True),
        json_path=a_cfg.get("json_path"),
        syslog_address=syslog_address,
    )


def run(cfg: Dict[str, Any], pcap_path: Optional[str] = None, realtime_replay: bool = False) -> None:
    alert_manager = build_alert_manager(cfg)
    engine = ScanEngine(detector_factory=lambda: build_detectors(cfg), alert_manager=alert_manager)

    dashboard = None
    if cfg.get("dashboard", {}).get("enabled"):
        from .dashboard import Dashboard

        dashboard = Dashboard(alert_manager)
        engine.on_packet = dashboard.note_packet

    detector_names = [d.name for d in build_detectors(cfg)]

    web = None
    if cfg.get("web", {}).get("enabled"):
        from .web import WebDashboard

        w_cfg = cfg.get("web", {})
        web = WebDashboard(
            engine,
            detector_names,
            host=w_cfg.get("host", "127.0.0.1"),
            port=w_cfg.get("port", 8787),
        )
        web.start()

        if w_cfg.get("open_browser", True):
            url = f"http://{web.host}:{web.port}/"
            threading.Timer(0.4, lambda: _open_browser_quietly(url)).start()

    print(f"Configured detectors: {detector_names}", file=sys.stderr)

    if pcap_path:
        engine.start(mode="pcap", pcap_path=pcap_path, realtime_replay=realtime_replay)
        print(f"Replaying {pcap_path} ...", file=sys.stderr)
    elif cfg.get("interface") or not web:
        # Either an interface was explicitly given, or there's no web UI to
        # start a scan from interactively -- preserve the old behavior of
        # starting a live capture immediately.
        engine.start(mode="live", interface=cfg.get("interface"), bpf_filter=cfg.get("bpf_filter", ""))
        iface_desc = cfg.get("interface") or "default interface"
        print(f"Live capture started on {iface_desc}. Press Ctrl+C to stop.", file=sys.stderr)
    else:
        print(f"No scan running yet -- start one from the dashboard at http://{web.host}:{web.port}/", file=sys.stderr)

    if dashboard or web:
        try:
            with dashboard if dashboard else _NoopCtx():
                while True:
                    time.sleep(0.5)
                    if dashboard:
                        dashboard.refresh()
        except KeyboardInterrupt:
            pass
        finally:
            engine.stop()
            if web:
                web.stop()
            if engine.status.dropped_count:
                print(f"Warning: dropped {engine.status.dropped_count} packets (queue full)", file=sys.stderr)
        return

    # No UI at all: block until this run finishes (pcap replay completes on
    # its own; live capture runs until Ctrl+C), matching plain-CLI scripted use.
    try:
        while engine.status.running:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        if engine.status.dropped_count:
            print(f"Warning: dropped {engine.status.dropped_count} packets (queue full)", file=sys.stderr)


def _open_browser_quietly(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass  # headless/server environment -- the URL is already printed


class _NoopCtx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="sentrynet",
        description="Custom Scapy-based network intrusion detector",
    )
    parser.add_argument("-c", "--config", help="Path to YAML config file", default=None)
    parser.add_argument("-i", "--interface", help="Network interface to sniff (overrides config)", default=None)
    parser.add_argument("--pcap", help="Replay a .pcap file instead of live capture", default=None)
    parser.add_argument(
        "--realtime-replay", action="store_true", help="Pace pcap replay to the packets' original timing"
    )
    parser.add_argument(
        "--dashboard", action="store_true", help="Enable the live Rich terminal dashboard (overrides config)"
    )
    parser.add_argument(
        "--web", action="store_true", help="Enable the local web dashboard (overrides config)"
    )
    parser.add_argument(
        "--web-port", type=int, default=None, help="Port for the web dashboard (default 8787)"
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Don't automatically open a browser tab for --web"
    )
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    if args.interface:
        cfg["interface"] = args.interface
    if args.dashboard:
        cfg.setdefault("dashboard", {})["enabled"] = True
    if args.web:
        cfg.setdefault("web", {})["enabled"] = True
    if args.web_port:
        cfg.setdefault("web", {})["port"] = args.web_port
    if args.no_browser:
        cfg.setdefault("web", {})["open_browser"] = False

    run(cfg, pcap_path=args.pcap, realtime_replay=args.realtime_replay)


if __name__ == "__main__":
    main()
