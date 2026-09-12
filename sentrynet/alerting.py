"""Alert data model and sinks (console, JSON-lines, syslog).

Detectors don't write alerts anywhere themselves -- they just return Alert
objects, and AlertManager fans each one out to whichever sinks are
configured. It also keeps a small in-memory ring buffer of recent alerts
for the dashboard to read.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    detector: str
    severity: Severity
    message: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


SEVERITY_COLOR = {
    Severity.INFO: "\033[37m",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m",
    Severity.CRITICAL: "\033[1;31m",
}
RESET = "\033[0m"


class AlertManager:
    """Fans out alerts to whichever sinks are configured: console, a
    JSON-lines file, and/or syslog.
    """

    def __init__(
        self,
        console: bool = True,
        json_path: Optional[str] = None,
        syslog_address: Optional[Tuple[str, int]] = None,
        history_size: int = 500,
    ):
        self.console = console
        self._json_path = json_path
        self._lock = threading.Lock()
        self._history: List[Alert] = []
        self._history_size = history_size

        self._syslog_logger: Optional[logging.Logger] = None
        if syslog_address:
            logger = logging.getLogger("sentrynet.syslog")
            logger.setLevel(logging.INFO)
            handler = logging.handlers.SysLogHandler(address=syslog_address)
            handler.setFormatter(logging.Formatter("sentrynet: %(message)s"))
            logger.addHandler(handler)
            self._syslog_logger = logger

    def emit(self, alert: Alert) -> None:
        with self._lock:
            self._history.append(alert)
            if len(self._history) > self._history_size:
                self._history.pop(0)

        if self.console:
            self._emit_console(alert)
        if self._json_path:
            self._emit_json(alert)
        if self._syslog_logger:
            self._syslog_logger.info(json.dumps(alert.to_dict()))

    def _emit_console(self, alert: Alert) -> None:
        color = SEVERITY_COLOR.get(alert.severity, "")
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        src = f" src={alert.source_ip}" if alert.source_ip else ""
        dst = f" dst={alert.dest_ip}" if alert.dest_ip else ""
        print(
            f"{color}[{ts}] [{alert.severity.value.upper():8}] "
            f"[{alert.detector}]{src}{dst} {alert.message}{RESET}",
            file=sys.stderr,
        )

    def _emit_json(self, alert: Alert) -> None:
        with open(self._json_path, "a") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    def recent(self, n: int = 20) -> List[Alert]:
        with self._lock:
            return list(self._history[-n:])
