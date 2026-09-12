"""sentrynet: a small, from-scratch Scapy-based network intrusion detector.

Architecture (see README.md for the full write-up):

    capture.py      -- live Scapy sniffing / pcap replay, feeding a queue
    state.py        -- thread-safe, time-windowed state primitives shared
                        by detectors (distinct-value sets, EWMA rates, an
                        IP->MAC table)
    detectors/      -- one module per detection technique, each consuming
                        packets and emitting Alert objects
    alerting.py     -- Alert data model + console/JSON/syslog sinks
    dashboard.py    -- optional live Rich terminal dashboard
    config.py       -- YAML config loading with sane defaults
    cli.py          -- wires it all together, argparse entrypoint
"""

__version__ = "0.1.0"
