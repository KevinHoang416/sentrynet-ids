# Sentrynet

A small, from-scratch network intrusion detector built on Scapy. It sniffs
live traffic (or replays a `.pcap`) through independent detector modules
for port scans, ARP spoofing, and volumetric traffic spikes, and can
optionally layer an experimental unsupervised anomaly detector on top.

Built as a from-scratch alternative to deploying something like Wazuh:
every detection technique here is hand-written and explained below, rather
than being a pre-built rule pack.

> **Authorized use only.** Run this only against networks and traffic you
> own or have explicit written permission to test. Live packet sniffing
> and the ARP/scan testing tools mentioned in this README can disrupt a
> network if misused; keep testing to an isolated lab segment.

## Architecture

```
capture.py  --->  queue  --->  engine.py ScanEngine  --->  detectors/*.py  --->  alerting.py  --->  console / JSON / syslog
                                        |
                                        +-->  dashboard.py (optional, Rich terminal view)
                                        +-->  web.py (optional, browser dashboard; can start/stop the engine itself)
```

- **`engine.py`** -- `ScanEngine` owns one capture/replay + detector run at
  a time and can be started and stopped on demand from any thread. This is
  what lets the web dashboard offer real Start/Stop controls: run
  `sentrynet --web` with no interface or pcap given at all, and nothing
  actually runs until you pick a source and click Start in the browser.
  `cli.py` still starts a scan immediately when `-i`/`--pcap` is given, for
  scripted/unattended use.

- **`capture.py`** -- `LiveCapture` runs Scapy's `AsyncSniffer` in a
  background thread whose callback does nothing but push packets onto a
  bounded queue. Detection logic never runs inside that callback, so a
  slow detector can't cause the OS-level capture to drop packets.
  `PcapReplay` reads a `.pcap` file and yields packets through the exact
  same downstream path, which is what lets you validate every detector
  against a recorded attack without a live network in front of you.

- **`state.py`** -- three small, thread-safe primitives shared by the
  detectors: `ExpiringSet` (distinct values seen per key in a rolling
  window -- e.g. "distinct ports hit by this IP in 10s"), `RollingRate`
  (an EWMA mean/variance tracker used to z-score a new rate observation
  against a key's own recent history), and `MacTable` (an IP->MAC binding
  table that reports conflicts).

- **`detectors/`** -- one module per technique. Each implements
  `process(pkt) -> Iterable[Alert]` and keeps its own state; see below for
  what each one actually does.

- **`alerting.py`** -- an `Alert` dataclass (detector, severity, message,
  source/dest IP, structured `details`) and `AlertManager`, which fans
  every alert out to whichever sinks are configured: colored console
  output, a JSON-lines file, and/or syslog (so this can feed into
  whatever SIEM you already run).

- **`dashboard.py`** -- an optional live Rich terminal view of recent
  alerts and session stats. Purely a presentation layer; detectors and
  alerting work identically with or without it.

- **`web.py`** -- an optional local web dashboard: a stdlib-only
  (`http.server`) server exposing a live-polling HTML/JS page at
  `http://127.0.0.1:8787/`, which opens automatically in your browser as
  soon as it starts. Dark, SOC-style UI: a scan control bar (pick live
  interface or pcap replay, Start/Stop, live status), clickable severity
  tiles that filter the feed, expandable rows showing each alert's
  structured `details` as key/value pairs, a live packets/sec readout, a
  sparkline of alert volume over the last 3 minutes, and a top-talkers
  panel, all computed client-side from the same `/api/state` JSON. The
  control bar's Start/Stop buttons are the only way a request can affect
  the detection pipeline (via `POST /api/start` and `/api/stop`, which
  just call straight into `ScanEngine`) -- there's still no other path
  from the network into detection, and no authentication, so keep `host`
  at `127.0.0.1` unless you deliberately want it (and scan control)
  reachable from other machines you trust.

- **`config.py`** / **`cli.py`** -- YAML config with built-in defaults, and
  the `sentrynet` entrypoint that wires everything together.

## Detectors

**Port scan (`detectors/port_scan.py`)** -- tracks, per source IP, the set
of *distinct destination ports* touched within a rolling window
(`window_seconds`). Once that count crosses `port_threshold`, it alerts,
suppressing repeats for `cooldown_seconds`. It also classifies the
technique from the raw TCP flag combination on the packets:

| Flags | Classified as |
|---|---|
| `SYN` only | SYN scan (`nmap -sS`) |
| none set | NULL scan (`nmap -sN`) |
| `FIN` only | FIN scan (`nmap -sF`) |
| `FIN,PSH,URG` | XMAS scan (`nmap -sX`) |

A single SYN packet looks identical to a normal connection attempt --
that's inherent to scan detection, not a gap in this tool. The signal is
in the aggregate (many distinct ports, short window), which is exactly
what's gated on before anything fires.

**ARP spoofing (`detectors/arp_spoof.py`)** -- maintains an IP->MAC table
built only from ARP *replies* (`op=2`, which also covers gratuitous ARP,
since that's just an unsolicited reply). If an IP that already has a known
MAC suddenly shows up bound to a different MAC, that's flagged as possible
cache poisoning. Conflicts on an IP listed in `gateway_ips` are escalated
to `CRITICAL`, since hijacking the gateway is the classic
man-in-the-middle setup move.

**Traffic spike (`detectors/traffic_spike.py`)** -- buckets packet counts
per source IP into fixed intervals (`interval_seconds`). When an interval
closes, that key's rate is scored with a z-score against an EWMA baseline
built from its *own* history (`RollingRate`), rather than one fixed
packets/sec number for the whole network. `min_packets` prevents a host
going from 0 to 3 packets from "spiking" just because its baseline was
near zero, and `min_stddev` puts a floor under the baseline's standard
deviation so a very flat or brand-new baseline (near-zero variance) can
still register a genuine jump instead of being unscoreable by division
against ~0.

**New host (`detectors/new_host.py`, INFO severity)** -- flags the first
time an IP address is seen during a scan, whether from IP traffic or ARP.
It's not a threat signal by itself (new devices joining a network is
completely normal); it's asset visibility -- "a new device joined" rather
than "you're being attacked" -- and it's the only detector here that
reports at INFO. Each scan starts with a clean slate, so restarting one
re-announces every address as "new" again; that's deliberate, since a
scan is one observation window, not a permanent inventory.

**ML anomaly (`detectors/ml_anomaly.py`, off by default, experimental)** --
an Isolation Forest retrained periodically on a rolling buffer of simple
per-packet features (size, protocol, ports, TTL). Included to show where
rule-based detection tops out (things with no fixed signature), not as a
production-ready detector: it's fully unsupervised, needs a `warmup`
period on your own normal traffic before it means anything, and every
alert is a low-confidence statistical outlier rather than a labeled
attack. Requires `scikit-learn` and `numpy`.

## Install

```bash
pip install -r requirements.txt
```

Live capture needs raw-socket access, so run it as root (or grant the
Python interpreter `CAP_NET_RAW`/`CAP_NET_ADMIN` via `setcap` if you'd
rather not run as root). On macOS, use `sudo` and pass your actual
interface name (`en0` for Wi-Fi on most Macs -- check with `ifconfig` or
`networksetup -listallhardwareports` if unsure); Linux typically uses
names like `eth0` or `wlan0`.

## Usage

### Run it from VS Code

Open this folder in VS Code (install the recommended "Python" extension
if prompted), open the Run and Debug panel, pick **Sentrynet: Web
Dashboard** from the dropdown, and press the green Run button (or F5).
That's it -- no terminal, no manual `pip install`, and no flags needed:
every configuration automatically installs `requirements.txt` into
whichever Python interpreter VS Code has selected before it runs, so a
completely fresh clone works on the first try. If you have more than one
Python installed (conda, Homebrew, etc.), use "Python: Select
Interpreter" from the command palette first to pick the one you want
used. There's also a **Sentrynet: Web Dashboard + sample.pcap demo**
configuration that replays the bundled capture automatically so every
detector fires within about 30 seconds, and a **Sentrynet: Run tests**
one for the test suite. These live in `.vscode/launch.json` and
`.vscode/tasks.json` if you want to tweak them (add `-i` for a specific
interface, change the port, etc.).

Live packet capture still needs the raw-socket access described below
(root/admin) no matter how you launch it -- that's an OS thing, not a VS
Code thing. If you start the dashboard without elevated privileges and
click Start Scan on "Live interface", it'll now report a clear
permission error in the status bar instead of just sitting there; pcap
replay mode has no such requirement, which is why the demo config uses
it.

### Just run it

The simplest way to use Sentrynet: run it with no interface or pcap file
at all, and it opens the web dashboard in your browser with nothing
running yet -- pick "Live interface" or "Pcap file" in the control bar
and click **Start Scan** to begin, and **Stop Scan** whenever you're done.
No root needed just to look at the dashboard; live capture still needs
the raw-socket access described in Install below once you actually click
Start on a live interface.

```bash
python run.py --web
```

Pass `--no-browser` if you don't want it to open a tab automatically (for
example over SSH), and use `--web-port` to change the port.

### Scripted / unattended use

Giving `-i`/`--interface` or `--pcap` on the command line starts a scan
immediately, exactly as before -- useful for automation, cron jobs, or
just muscle memory:

A bundled `sample.pcap` is included so you can see every detector fire
without needing root, a live network, or an attack tool installed:

```bash
# Fast replay: fires the port_scan, arp_spoof, and new_host alerts immediately.
python run.py --pcap sample.pcap

# Realtime replay: also fires the traffic_spike alert.
# Needed because traffic_spike buckets by wall-clock time, so its 5-second
# windows only line up correctly when replay is paced to match -- this
# takes about a minute since that's how long the recording is.
python run.py --pcap sample.pcap --realtime-replay

# Same, with the browser dashboard at http://127.0.0.1:8787/ (opens
# automatically, and stays open after the file finishes so you can review
# results or start another scan at your own pace)
python run.py --pcap sample.pcap --realtime-replay --web

# Live capture on a specific interface, using the example config
sudo python run.py -i eth0 --config example_config.yaml

# Live capture with the terminal dashboard, or the browser dashboard
sudo python run.py -i eth0 --dashboard
sudo python run.py -i eth0 --web
```

With no `--config`, `sentrynet` runs with the built-in defaults in
`config.py` (`port_scan`, `arp_spoof`, `traffic_spike`, and `new_host` on;
`ml_anomaly` and both dashboards off). Copy `example_config.yaml` and
adjust thresholds, your gateway IP(s), and alerting sinks for your
environment.

The web dashboard (`--web`, or `web.enabled: true` in config) binds to
`127.0.0.1` by default and has no authentication, so only change `host`
if you deliberately want it (and its scan controls) reachable from other
machines on a network you trust. It can run alongside the terminal
dashboard, and it stays up after a pcap replay finishes or a live capture
is stopped, so you can review results or start another scan at your own
pace.

## Deploy a free public demo

Live packet capture needs raw-socket access and an actual network to
sniff, neither of which a free hosting container gives you -- so a
"hosted Sentrynet" only makes sense as a demo that loops the bundled
`sample.pcap` on a public link (e.g. for a resume or portfolio), not as
real monitoring. [Render's free tier](https://render.com) fits this well:
no credit card, 750 free instance-hours/month (enough to run all month),
though it spins down after 15 minutes with no traffic and takes about a
minute to wake back up on the next visit.

`render_demo.py` is a separate entrypoint built for exactly this -- it's
not what you run locally (`run.py` is). It binds to `0.0.0.0` on
whatever port Render assigns, loops `sample.pcap` forever so the
dashboard is never sitting idle, and sets `SENTRYNET_DEMO_MODE=1`, which
makes the page show a banner explaining itself and disables the "Live
interface" option (since it can't work there anyway). Clicking Stop on
the hosted demo just makes the next auto-restart arrive a few seconds
early -- the controls are real, not for show.

To deploy: push this repo to your own GitHub account, then in the Render
dashboard choose **New -> Blueprint**, point it at the repo, and click
**Apply** -- `render.yaml` in this repo configures the build/start
commands and free plan automatically. (Without the blueprint, the
equivalent manual setup is a Python web service with build command
`pip install -r requirements.txt`, start command `python render_demo.py`,
and an `SENTRYNET_DEMO_MODE=1` environment variable.)

`render_demo.py` also tunes a couple of things beyond the local defaults
purely so the demo shows every severity within one loop of the sample
capture: it lists `192.168.1.1` under `gateway_ips` (so the bundled
ARP-spoof traffic reads as a hijacked gateway, CRITICAL, rather than a
plain HIGH), and it turns `ml_anomaly` on with a much shorter
`warmup`/`retrain_every` than the (still off-by-default) local defaults,
so it produces a genuine LOW alert instead of needing hundreds of packets
to warm up. Neither change affects anyone running Sentrynet normally --
they're only set inside `render_demo.py`, not in `config.py`.

## Testing it against real attack traffic

Do this only in an isolated lab (a couple of VMs on a host-only/NAT
network segment you control), never on a shared or production network.

**Port scan:**
```bash
# On the target/monitoring box:
sudo python run.py -i eth0

# From another host in the lab:
nmap -sS -p 1-100 <target-ip>       # SYN scan
nmap -sN -p 1-100 <target-ip>       # NULL scan
nmap -sX -p 1-100 <target-ip>       # XMAS scan
```
You should see a `port_scan` alert naming the correct scan type within
`window_seconds` of the scan starting.

**ARP spoofing:**
```bash
# From an attacker VM, spoof the gateway's IP to your own MAC:
sudo arpspoof -i eth0 -t <victim-ip> <gateway-ip>
```
You should see an `arp_spoof` alert (CRITICAL if you listed that IP under
`gateway_ips`) as soon as the forged ARP reply is sent.

**Traffic spike:**
```bash
# On the target, run an iperf3 server; from the attacker, saturate it:
iperf3 -s                              # on target
iperf3 -c <target-ip> -u -b 500M -t 20 # from attacker, or use hping3 --flood
```
Watch for a `traffic_spike` alert once the burst clearly exceeds the
baseline established by normal traffic before it.

For a repeatable demo that doesn't need live attack traffic each time,
capture one of the above sessions with `tcpdump -w attack.pcap` and replay
it later with `python run.py --pcap attack.pcap`.

## Running the unit tests

The detector unit tests build crafted Scapy packets directly, the engine
tests exercise `ScanEngine`'s start/stop lifecycle (bad input, double
starts, a rapid start/stop race) against small pcaps written to a temp
directory, and the web dashboard tests spin up a real (ephemeral-port)
instance of it and hit its endpoints -- including `/api/start` and
`/api/stop` -- over HTTP. None of it needs root, a live network, or the
bundled pcap file:

```bash
pytest tests/ -v
```

## Extending it

Each detector is independent and implements one method
(`BaseDetector.process`), so adding a new technique is a matter of
dropping a new file in `detectors/`, wiring it into
`cli.build_detectors`, and adding its defaults to `config.py`. The
`state.py` primitives (`ExpiringSet`, `RollingRate`, `MacTable`) cover most
of what a new rolling-window or baseline-based detector would need.
