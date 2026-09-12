"""Optional live terminal dashboard, built on Rich.

Pure presentation layer over AlertManager's history buffer -- it doesn't
participate in detection at all, so it's safe to leave disabled (the
default) and turn on with --dashboard or dashboard.enabled: true in config.
"""
from __future__ import annotations

import time
from collections import Counter
from typing import Optional

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .alerting import AlertManager, Severity

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


class Dashboard:
    def __init__(self, alert_manager: AlertManager, refresh_per_second: float = 2.0):
        if not RICH_AVAILABLE:
            raise RuntimeError(
                "dashboard is enabled but 'rich' is not installed. Install it "
                "with 'pip install rich', or set dashboard.enabled: false in "
                "your config."
            )
        self.alert_manager = alert_manager
        self.refresh_per_second = refresh_per_second
        self._console = Console()
        self._packet_count = 0
        self._start_time = time.time()
        self._live: Optional["Live"] = None

    def note_packet(self) -> None:
        self._packet_count += 1

    def _render(self):
        alerts = self.alert_manager.recent(15)
        uptime = time.time() - self._start_time

        stats_table = Table(title="Session Stats", expand=True)
        stats_table.add_column("Metric")
        stats_table.add_column("Value")
        stats_table.add_row("Uptime", f"{uptime:.0f}s")
        stats_table.add_row("Packets processed", str(self._packet_count))
        counts = Counter(a.detector for a in alerts)
        stats_table.add_row("Alerts (last 15)", str(len(alerts)))
        for detector, count in counts.items():
            stats_table.add_row(f"  {detector}", str(count))

        alert_table = Table(title="Recent Alerts", expand=True)
        alert_table.add_column("Time", width=8)
        alert_table.add_column("Severity", width=10)
        alert_table.add_column("Detector", width=14)
        alert_table.add_column("Message")
        for a in reversed(alerts):
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            style = SEVERITY_STYLE.get(a.severity, "")
            alert_table.add_row(
                ts, f"[{style}]{a.severity.value.upper()}[/{style}]", a.detector, a.message
            )

        return Group(stats_table, alert_table)

    def __enter__(self):
        self._live = Live(self._render(), console=self._console, refresh_per_second=self.refresh_per_second)
        self._live.__enter__()
        return self

    def __exit__(self, *exc):
        if self._live:
            return self._live.__exit__(*exc)
        return False

    def refresh(self) -> None:
        if self._live:
            self._live.update(self._render())
