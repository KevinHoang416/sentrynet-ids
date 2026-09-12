"""YAML-driven configuration for sentrynet, with sane built-in defaults so the
tool runs out of the box with `sentrynet` and no config file at all.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import yaml

DEFAULT_CONFIG: Dict[str, Any] = {
    "interface": None,
    "bpf_filter": "",
    "gateway_ips": [],
    "detectors": {
        "port_scan": {
            "enabled": True,
            "window_seconds": 10,
            "port_threshold": 15,
            "cooldown_seconds": 30,
        },
        "arp_spoof": {
            "enabled": True,
            "cooldown_seconds": 15,
        },
        "traffic_spike": {
            "enabled": True,
            "interval_seconds": 5,
            "zscore_threshold": 3.5,
            "min_packets": 20,
            "ewma_alpha": 0.3,
            "min_stddev": 1.0,
        },
        "ml_anomaly": {
            "enabled": False,
            "buffer_size": 2000,
            "retrain_every": 200,
            "contamination": 0.02,
            "warmup": 500,
        },
    },
    "alerting": {
        "console": True,
        "json_path": None,
        "syslog": None,  # e.g. {"host": "127.0.0.1", "port": 514}
    },
    "dashboard": {
        "enabled": False,
    },
    "web": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 8787,
        "open_browser": True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return _deep_merge(DEFAULT_CONFIG, {})
    with open(path) as f:
        user_config = yaml.safe_load(f) or {}
    return _deep_merge(DEFAULT_CONFIG, user_config)
