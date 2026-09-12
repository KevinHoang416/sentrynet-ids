#!/usr/bin/env python3
"""Convenience entrypoint so you can run this without installing the
package: `python run.py --pcap sample.pcap` or `sudo python run.py -i eth0`.
"""
from sentrynet.cli import main

if __name__ == "__main__":
    main()
