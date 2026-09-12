#!/usr/bin/env python3
"""Entrypoint for a free-tier public demo deployment (see the README's
"Deploy a free public demo" section). This is NOT what you run locally --
for that, use `run.py`, which starts idle and lets you pick live capture
or pcap replay yourself from the dashboard.

This script instead:

- binds the web dashboard to 0.0.0.0 on whatever port the host assigns
  via the $PORT environment variable, which Render (and most other free
  PaaS tiers) require -- they route external traffic to that port, not a
  fixed one.
- loops the bundled sample.pcap forever, so anyone who opens the link
  always finds it "running" with a fresh stream of alerts, instead of
  sitting idle waiting for a human to click Start. A brief pause between
  loops lets a visitor actually see it settle to idle and restart, which
  is also a live demonstration that the Start/Stop controls are real and
  not just for show -- clicking Stop just makes the next auto-restart
  arrive a few seconds early.
- sets SENTRYNET_DEMO_MODE, which makes the dashboard show a banner
  explaining itself and disables "Live interface": a hosted container has
  no raw-socket access and no real network worth sniffing anyway, so
  leaving that option enabled would just be a confusing error click away.
"""
from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("SENTRYNET_DEMO_MODE", "1")

from sentrynet.cli import build_alert_manager, build_detectors  # noqa: E402
from sentrynet.config import load_config  # noqa: E402
from sentrynet.engine import ScanEngine  # noqa: E402
from sentrynet.web import WebDashboard  # noqa: E402

PCAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.pcap")


def loop_pcap_forever(engine: ScanEngine) -> None:
    while True:
        try:
            engine.start(mode="pcap", pcap_path=PCAP_PATH, realtime_replay=True)
        except RuntimeError:
            # A scan is already running -- shouldn't happen since this is
            # the only thing ever calling start(), but a visitor's own
            # Start click racing this loop must never kill the watchdog.
            pass
        while engine.status.running:
            time.sleep(0.5)
        # Idle pause between loops (and after a visitor clicks Stop) so
        # the dashboard visibly settles before the next replay begins.
        time.sleep(4)


def main() -> None:
    cfg = load_config(None)
    alert_manager = build_alert_manager(cfg)
    engine = ScanEngine(detector_factory=lambda: build_detectors(cfg), alert_manager=alert_manager)
    detector_names = [d.name for d in build_detectors(cfg)]

    port = int(os.environ.get("PORT", "8787"))
    web = WebDashboard(engine, detector_names, host="0.0.0.0", port=port)
    web.start()

    watchdog = threading.Thread(target=loop_pcap_forever, args=(engine,), daemon=True)
    watchdog.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        web.stop()


if __name__ == "__main__":
    main()
