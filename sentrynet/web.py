"""Optional local web dashboard.

Serves a small static HTML/JS page plus a JSON polling endpoint over
AlertManager's alert history and the ScanEngine's live status. Built
entirely on the standard library (`http.server`) so turning it on costs
no extra dependency beyond what sentrynet already requires. The heavier
lifting (severity filtering, relative timestamps, the sparkline, top
talkers, expandable detail panels) all happens client-side in
INDEX_HTML's script against the same /api/state payload -- the backend
just reports raw facts.

The dashboard also exposes two control endpoints, POST /api/start and
POST /api/stop, so a scan can be started and stopped from the page
itself instead of only at process launch via CLI flags. Both just call
straight through to the ScanEngine, which validates its own arguments;
the HTTP layer adds no privilege beyond what the engine already allows.
It binds to 127.0.0.1 by default -- change `host` deliberately if you
want it reachable from other machines, and never expose it on an
untrusted network, since it has no authentication and anyone who can
reach it can start or stop scans.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

from .engine import ScanEngine

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentrynet live dashboard</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    --bg: oklch(16% 0.006 260);
    --panel: oklch(19.5% 0.007 260);
    --panel-2: oklch(23% 0.008 260);
    --border: oklch(28% 0.009 260);
    --text: oklch(93% 0.004 260);
    --text-dim: oklch(64% 0.008 260);
    --text-dimmer: oklch(46% 0.008 260);
    --brand: oklch(78% 0.16 155);
    --info: oklch(70% 0.02 250);
    --low: oklch(75% 0.12 210);
    --medium: oklch(80% 0.15 85);
    --high: oklch(68% 0.19 35);
    --critical: oklch(64% 0.22 15);

    background: var(--bg);
    color: var(--text);
    font-family: 'IBM Plex Sans', system-ui, sans-serif;
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }
  a { color: var(--brand); }
  a:hover { color: oklch(85% 0.16 155); }
  .mono { font-family: 'IBM Plex Mono', ui-monospace, monospace; }
  .dim { color: var(--text-dim); }
  .dimmer { color: var(--text-dimmer); }

  /* Topbar */
  .topbar {
    display: flex; align-items: center; gap: 24px; padding: 0 24px; height: 68px; flex-shrink: 0;
    border-bottom: 1px solid var(--border); background: var(--panel); flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand-name { font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: 16px; letter-spacing: 0.02em; }
  @keyframes pulseRing { 0% { transform: scale(0.5); opacity: 0.55; } 100% { transform: scale(2.1); opacity: 0; } }
  .vdiv { width: 1px; height: 28px; background: var(--border); }
  .metrics { display: flex; align-items: center; gap: 30px; flex-wrap: wrap; }
  .metric { display: flex; flex-direction: column; gap: 3px; }
  .metric-label { font-size: 10.5px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-dimmer); }
  .metric-value { font-family: 'IBM Plex Mono', monospace; font-size: 15px; font-weight: 600; }
  .metric-value.ok { color: var(--brand); }
  .metric-value.warn { color: var(--medium); }
  .topbar-right { margin-left: auto; }
  .addr-tag {
    font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--text-dimmer);
    padding: 5px 10px; border: 1px solid var(--border); border-radius: 6px;
  }

  /* Scan control bar */
  .controlbar {
    display: flex; align-items: center; gap: 16px; padding: 12px 24px; flex-shrink: 0;
    border-bottom: 1px solid var(--border); background: var(--panel); flex-wrap: wrap;
  }
  .scan-status { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
  .status-dot { position: relative; width: 8px; height: 8px; border-radius: 50%; background: var(--text-dimmer); }
  .status-dot.status-live { background: var(--brand); }
  .status-dot.status-live::after {
    content: ''; position: absolute; inset: -6px; border-radius: 50%;
    border: 1px solid var(--brand); animation: pulseRing 1.8s ease-out infinite; opacity: 0;
  }
  .status-text { font-family: 'IBM Plex Mono', monospace; font-size: 12px; font-weight: 600; color: var(--text-dim); white-space: nowrap; }
  .status-text.status-live-text { color: var(--brand); }
  .scan-form { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .ctl-select, .ctl-input {
    background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
    border-radius: 6px; padding: 6px 10px; font-family: 'IBM Plex Sans', sans-serif; font-size: 12.5px;
  }
  .ctl-input { min-width: 210px; }
  .realtime-label { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-dim); cursor: pointer; }
  .btn {
    font-family: 'IBM Plex Sans', sans-serif; font-size: 12.5px; font-weight: 600; padding: 7px 14px;
    border-radius: 6px; border: 1px solid transparent; cursor: pointer;
  }
  .btn-start { background: var(--brand); color: oklch(16% 0.006 260); }
  .btn-start:hover { background: oklch(85% 0.16 155); }
  .btn-start:disabled { opacity: 0.5; cursor: default; }
  .btn-stop { background: transparent; border-color: var(--critical); color: var(--critical); }
  .btn-stop:hover { background: color-mix(in oklch, var(--critical) 14%, transparent); }
  .scan-error { font-size: 12px; color: var(--critical); }

  /* Severity filter tiles */
  .filters { display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 12px; padding: 16px 24px; flex-shrink: 0; }
  .tile {
    display: flex; flex-direction: column; gap: 8px; padding: 12px 15px; border-radius: 10px;
    background: var(--panel); border: 1px solid var(--border); cursor: pointer; text-align: left;
    font: inherit; color: inherit; transition: opacity 0.15s ease;
  }
  .tile-head { display: flex; align-items: center; gap: 7px; }
  .tile-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .tile-label { font-size: 11px; letter-spacing: 0.07em; text-transform: uppercase; color: var(--text-dim); }
  .tile-count { font-family: 'IBM Plex Mono', monospace; font-size: 23px; font-weight: 600; }
  .tile.tile-on { background: var(--tile-tint); border-color: var(--tile-border); }
  .tile.tile-on .tile-count, .tile.tile-on .tile-label { color: var(--tile-fg); }
  .tile.tile-off { opacity: 0.45; }
  .tile.tile-off .tile-count { color: var(--text-dimmer); }

  /* Layout */
  .content { display: flex; gap: 18px; padding: 0 24px 24px 24px; flex: 1; min-height: 0; }
  .col-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .col-side { width: 300px; flex-shrink: 0; display: flex; flex-direction: column; gap: 18px; }
  @media (max-width: 900px) {
    .content { flex-direction: column; }
    .col-side { width: 100%; flex-direction: row; }
    .col-side > .panel { flex: 1; }
  }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  .panel-header { display: flex; align-items: baseline; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid var(--border); gap: 12px; }
  .panel-title { font-size: 13px; font-weight: 600; white-space: nowrap; }
  .panel-sub { font-size: 11px; color: var(--text-dimmer); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .feed-panel { flex: 1; display: flex; flex-direction: column; min-height: 240px; }
  .feed-scroll { overflow: auto; flex: 1; }

  .row-grid {
    display: grid;
    grid-template-columns: 78px 100px 116px 116px 116px 1fr 20px;
    gap: 12px; align-items: center; padding: 11px 20px; min-width: 640px;
  }
  .row-head { padding: 9px 20px; min-width: 640px; }
  .row-head .col-h { font-size: 10.5px; letter-spacing: 0.07em; text-transform: uppercase; color: var(--text-dimmer); }

  .alert-row { border-bottom: 1px solid var(--border); cursor: pointer; }
  .alert-row:last-child { border-bottom: none; }
  .alert-row:hover .row-grid { background: var(--panel-2); }
  .alert-row.expanded .row-grid { align-items: start; }

  .badge {
    display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 5px;
    font-family: 'IBM Plex Mono', monospace; font-size: 10.5px; font-weight: 600; letter-spacing: 0.02em;
    width: fit-content;
  }
  .chip {
    display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 5px;
    background: var(--panel-2); font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--text-dim);
    width: fit-content; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ip { font-family: 'IBM Plex Mono', monospace; font-size: 12px; }
  .msg { font-size: 12.5px; line-height: 1.4; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .msg.wrap { white-space: normal; }
  .time-cell { font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--text-dim); white-space: nowrap; }
  .chev { transition: transform 0.15s ease; margin-top: 2px; }
  .alert-row.expanded .chev { transform: rotate(90deg); }

  .detail-panel {
    margin: 0 20px 14px 20px; padding: 13px 15px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; font-family: 'IBM Plex Mono', monospace; font-size: 11.5px;
    display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px;
  }
  .dk { color: var(--text-dimmer); }
  .dv { color: var(--text-dim); word-break: break-all; }

  .feed-msg { padding: 40px 20px; text-align: center; color: var(--text-dimmer); font-size: 12.5px; }

  .empty-wrap {
    flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 12px; padding: 32px; text-align: center; min-height: 240px;
  }
  .empty-title { font-size: 15px; font-weight: 600; }
  .empty-sub { font-size: 12.5px; color: var(--text-dim); max-width: 420px; line-height: 1.6; }
  .empty-chips { display: flex; gap: 8px; margin-top: 2px; flex-wrap: wrap; justify-content: center; }

  .spark { display: flex; align-items: flex-end; gap: 3px; height: 68px; padding: 16px 20px 6px 20px; }
  .spark-bar { flex: 1; background: oklch(78% 0.16 155 / 0.28); border-radius: 2px 2px 0 0; min-height: 2px; transition: height 0.3s ease; }
  .spark-bar.peak { background: var(--brand); }
  .spark-bar.flat { background: var(--panel-2); }
  .spark-axis { display: flex; justify-content: space-between; padding: 0 20px 14px 20px; font-size: 10.5px; color: var(--text-dimmer); }

  .talker-row { display: flex; align-items: center; gap: 10px; padding: 10px 20px; }
  .talker-ip { font-family: 'IBM Plex Mono', monospace; font-size: 12px; width: 104px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .talker-bar-track { flex: 1; height: 6px; border-radius: 3px; background: var(--panel-2); overflow: hidden; }
  .talker-bar-fill { height: 100%; background: var(--text-dimmer); border-radius: 3px; transition: width 0.3s ease; }
  .talker-count { font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--text-dim); width: 18px; text-align: right; flex-shrink: 0; }
  .talker-empty { padding: 26px 20px; text-align: center; font-size: 12px; color: var(--text-dimmer); }
</style>
</head>
<body>

  <div class="topbar">
    <div class="brand">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
        <path d="M12 2C6.48 2 2 6.48 2 12" stroke="oklch(78% 0.16 155)" stroke-width="2" stroke-linecap="round"/>
        <path d="M12 6.2C8.8 6.2 6.2 8.8 6.2 12" stroke="oklch(78% 0.16 155)" stroke-width="2" stroke-linecap="round" opacity="0.55"/>
        <circle cx="12" cy="12" r="2.1" fill="oklch(78% 0.16 155)"/>
      </svg>
      <span class="brand-name">Sentrynet</span>
    </div>
    <div class="vdiv"></div>
    <div class="metrics">
      <div class="metric"><span class="metric-label">Uptime</span><span class="metric-value mono" id="m-uptime">--</span></div>
      <div class="metric"><span class="metric-label">Packets</span><span class="metric-value mono" id="m-packets">--</span></div>
      <div class="metric"><span class="metric-label">Dropped</span><span class="metric-value mono ok" id="m-dropped">0</span></div>
      <div class="metric"><span class="metric-label">Detectors</span><span class="metric-value mono" id="m-detectors">--</span></div>
    </div>
    <div class="topbar-right"><span class="addr-tag" id="m-addr">--</span></div>
  </div>

  <div class="controlbar" id="controlbar">
    <div class="scan-status">
      <span class="status-dot" id="status-dot"></span>
      <span class="status-text" id="status-text">Idle</span>
    </div>
    <div class="scan-form" id="scan-form">
      <select id="scan-mode" class="ctl-select">
        <option value="live">Live interface</option>
        <option value="pcap">Pcap file</option>
      </select>
      <input id="scan-source" class="ctl-input" type="text" placeholder="Interface (blank = default)">
      <label class="realtime-label" id="realtime-label" style="display:none;">
        <input type="checkbox" id="scan-realtime"> Realtime replay
      </label>
      <button class="btn btn-start" id="start-btn">Start Scan</button>
    </div>
    <button class="btn btn-stop" id="stop-btn" style="display:none;">Stop Scan</button>
    <span class="scan-error" id="scan-error"></span>
  </div>

  <div class="filters" id="filters"></div>

  <div class="content">
    <div class="col-main">
      <div class="panel feed-panel">
        <div class="panel-header">
          <span class="panel-title">Alert Feed</span>
          <span class="panel-sub" id="feed-sub">-- alerts</span>
        </div>
        <div class="feed-scroll" id="feed-scroll"></div>
      </div>
    </div>

    <div class="col-side">
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Alert Volume</span><span class="panel-sub">last 3 min</span></div>
        <div class="spark" id="spark"></div>
        <div class="spark-axis"><span>-3m</span><span>-2m</span><span>-1m</span><span>now</span></div>
      </div>
      <div class="panel" style="flex:1;">
        <div class="panel-header"><span class="panel-title">Top Talkers</span><span class="panel-sub">by alert count</span></div>
        <div id="talkers"></div>
      </div>
    </div>
  </div>

<script>
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const activeSev = new Set(SEVERITIES);
const expanded = new Set();
let lastPacketCount = null;
let lastPollTime = null;
let rateDisplay = null;

document.getElementById("m-addr").textContent = location.host;

const modeSelect = document.getElementById("scan-mode");
const sourceInput = document.getElementById("scan-source");
const realtimeLabel = document.getElementById("realtime-label");
const realtimeCheckbox = document.getElementById("scan-realtime");
const startBtn = document.getElementById("start-btn");
const stopBtn = document.getElementById("stop-btn");
const scanForm = document.getElementById("scan-form");
const scanError = document.getElementById("scan-error");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");

function updateModeUI() {
  if (modeSelect.value === "pcap") {
    sourceInput.placeholder = "Path to .pcap file";
    realtimeLabel.style.display = "flex";
  } else {
    sourceInput.placeholder = "Interface (blank = default)";
    realtimeLabel.style.display = "none";
  }
}
modeSelect.addEventListener("change", updateModeUI);
updateModeUI();

async function startScan() {
  scanError.textContent = "";
  const mode = modeSelect.value;
  const body = { mode };
  if (mode === "pcap") {
    body.pcap_path = sourceInput.value.trim();
    body.realtime_replay = realtimeCheckbox.checked;
  } else {
    body.interface = sourceInput.value.trim() || null;
  }
  startBtn.disabled = true;
  try {
    const res = await fetch("/api/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!data.ok) scanError.textContent = data.error || "Failed to start scan";
  } catch (e) {
    scanError.textContent = "Failed to reach the dashboard server.";
  } finally {
    startBtn.disabled = false;
  }
}

async function stopScan() {
  stopBtn.disabled = true;
  try {
    await fetch("/api/stop", { method: "POST" });
  } catch (e) {
    // Server likely stopped or is busy tearing down -- the next poll will
    // reflect whatever the real state turns out to be.
  } finally {
    stopBtn.disabled = false;
  }
}

startBtn.addEventListener("click", startScan);
stopBtn.addEventListener("click", stopScan);

function renderScan(scan) {
  scan = scan || {};
  if (scan.running) {
    statusDot.className = "status-dot status-live";
    statusText.className = "status-text status-live-text";
    const src = scan.source ? ` · ${esc(scan.source)}` : "";
    statusText.textContent = `Running (${scan.mode})${src}`;
    scanForm.style.display = "none";
    stopBtn.style.display = "";
    scanError.textContent = "";
  } else {
    statusDot.className = "status-dot";
    statusText.className = "status-text";
    statusText.textContent = "Idle";
    scanForm.style.display = "flex";
    stopBtn.style.display = "none";
    if (scan.error) scanError.textContent = scan.error;
  }
}

function esc(s) {
  const map = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"};
  return String(s).replace(/[&<>"']/g, c => map[c]);
}

function fmtDuration(totalSeconds) {
  const s = Math.max(0, Math.round(totalSeconds));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function fmtRelative(ts) {
  const diff = Math.max(0, Date.now() / 1000 - ts);
  if (diff < 2) return "just now";
  return fmtDuration(diff) + " ago";
}

function fmtInt(n) {
  return Number(n).toLocaleString();
}

function severityColorVar(sev) {
  return `var(--${sev})`;
}

function renderFilters(counts) {
  const box = document.getElementById("filters");
  box.innerHTML = "";
  for (const sev of SEVERITIES) {
    const on = activeSev.has(sev);
    const btn = document.createElement("button");
    btn.className = "tile " + (on ? "tile-on" : "tile-off");
    btn.style.setProperty("--tile-tint", `color-mix(in oklch, ${severityColorVar(sev)} 14%, var(--panel))`);
    btn.style.setProperty("--tile-border", `color-mix(in oklch, ${severityColorVar(sev)} 40%, var(--border))`);
    btn.style.setProperty("--tile-fg", severityColorVar(sev));
    btn.innerHTML = `
      <div class="tile-head"><span class="tile-dot" style="background:${severityColorVar(sev)}"></span><span class="tile-label">${sev}</span></div>
      <span class="tile-count">${counts[sev] || 0}</span>
    `;
    btn.addEventListener("click", () => {
      if (activeSev.has(sev)) activeSev.delete(sev); else activeSev.add(sev);
      renderAll(lastState);
    });
    box.appendChild(btn);
  }
}

function renderFeed(allAlerts) {
  const scroll = document.getElementById("feed-scroll");
  const sub = document.getElementById("feed-sub");
  const visible = allAlerts.filter(a => activeSev.has(a.severity));
  const excludedCount = allAlerts.length - visible.length;
  sub.textContent = `${visible.length} alert${visible.length === 1 ? "" : "s"}` +
    (excludedCount > 0 ? ` (${excludedCount} filtered)` : "");

  if (allAlerts.length === 0) {
    scroll.innerHTML = `
      <div class="empty-wrap">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none">
          <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" stroke="oklch(55% 0.01 260)" stroke-width="1.5" stroke-linejoin="round"/>
          <path d="M9 12l2 2 4-4" stroke="oklch(55% 0.01 260)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div class="empty-title">All quiet</div>
        <div class="empty-sub">No alerts yet. Detectors are watching live traffic and will show up here the moment something crosses a threshold.</div>
        <div class="empty-chips" id="empty-detectors"></div>
      </div>`;
    const chips = document.getElementById("empty-detectors");
    if (chips) {
      chips.innerHTML = (lastState.detectors || []).map(d => `<span class="chip">${esc(d)}</span>`).join("");
    }
    return;
  }

  if (visible.length === 0) {
    scroll.innerHTML = `<div class="feed-msg">No alerts match the current filter.</div>`;
    return;
  }

  const head = `
    <div class="row-head row-grid dim">
      <span class="col-h">Time</span><span class="col-h">Severity</span><span class="col-h">Detector</span>
      <span class="col-h">Source</span><span class="col-h">Dest</span><span class="col-h">Message</span><span></span>
    </div>`;

  const rowsHtml = visible.map((a, i) => {
    const key = `${a.timestamp}-${i}`;
    const isOpen = expanded.has(key);
    let detailHtml = "";
    if (isOpen && a.details && Object.keys(a.details).length > 0) {
      const pairs = Object.entries(a.details).map(([k, v]) =>
        `<span class="dk">${esc(k)}</span><span class="dv">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span>`
      ).join("");
      detailHtml = `<div class="detail-panel">${pairs}</div>`;
    }
    return `
      <div class="alert-row ${isOpen ? "expanded" : ""}" data-key="${esc(key)}">
        <div class="row-grid">
          <span class="time-cell">${fmtRelative(a.timestamp)}</span>
          <span class="badge" style="background: color-mix(in oklch, ${severityColorVar(a.severity)} 16%, transparent); color:${severityColorVar(a.severity)};">${a.severity.toUpperCase()}</span>
          <span class="chip">${esc(a.detector)}</span>
          <span class="ip">${esc(a.source_ip || "—")}</span>
          <span class="ip dimmer">${esc(a.dest_ip || "—")}</span>
          <span class="msg ${isOpen ? "wrap" : ""}">${esc(a.message)}</span>
          <svg class="chev" width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M9 6l6 6-6 6" stroke="oklch(55% 0.01 260)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        ${detailHtml}
      </div>`;
  }).join("");

  scroll.innerHTML = head + rowsHtml;

  scroll.querySelectorAll(".alert-row").forEach(row => {
    row.addEventListener("click", () => {
      const key = row.dataset.key;
      if (expanded.has(key)) expanded.delete(key); else expanded.add(key);
      renderFeed(lastState.alerts || []);
    });
  });
}

function renderSpark(allAlerts) {
  const box = document.getElementById("spark");
  const BUCKETS = 18, SPAN = 180; // 18 x 10s buckets = last 3 minutes
  const now = Date.now() / 1000;
  const counts = new Array(BUCKETS).fill(0);
  for (const a of allAlerts) {
    const age = now - a.timestamp;
    if (age < 0 || age > SPAN) continue;
    const idx = BUCKETS - 1 - Math.floor(age / (SPAN / BUCKETS));
    if (idx >= 0 && idx < BUCKETS) counts[idx]++;
  }
  const max = Math.max(...counts, 1);
  const allZero = counts.every(c => c === 0);
  box.innerHTML = counts.map(c => {
    const pct = allZero ? 4 : Math.max(4, Math.round((c / max) * 100));
    const cls = allZero ? "flat" : (c === max && c > 0 ? "peak" : "");
    return `<div class="spark-bar ${cls}" style="height:${pct}%"></div>`;
  }).join("");
}

function renderTalkers(allAlerts) {
  const box = document.getElementById("talkers");
  const counts = {};
  for (const a of allAlerts) {
    if (!a.source_ip) continue;
    counts[a.source_ip] = (counts[a.source_ip] || 0) + 1;
  }
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (top.length === 0) {
    box.innerHTML = `<div class="talker-empty">No alerts recorded yet</div>`;
    return;
  }
  const max = top[0][1];
  box.innerHTML = top.map(([ip, count]) => `
    <div class="talker-row">
      <span class="talker-ip">${esc(ip)}</span>
      <div class="talker-bar-track"><div class="talker-bar-fill" style="width:${Math.max(6, Math.round((count / max) * 100))}%"></div></div>
      <span class="talker-count">${count}</span>
    </div>`).join("");
}

let lastState = { alerts: [], detectors: [] };

function renderAll(state) {
  lastState = state;
  const alerts = state.alerts || [];

  document.getElementById("m-uptime").textContent = fmtDuration(state.uptime_seconds);
  document.getElementById("m-packets").textContent = fmtInt(state.packet_count) + (rateDisplay !== null ? ` · ${rateDisplay}/s` : "");
  const droppedEl = document.getElementById("m-dropped");
  droppedEl.textContent = fmtInt(state.dropped_count);
  droppedEl.className = "metric-value mono " + (state.dropped_count > 0 ? "warn" : "ok");
  document.getElementById("m-detectors").textContent = `${(state.detectors || []).length}`;

  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const a of alerts) { if (counts[a.severity] !== undefined) counts[a.severity]++; }
  renderFilters(counts);
  renderFeed(alerts);
  renderSpark(alerts);
  renderTalkers(alerts);
  renderScan(state.scan);
}

async function poll() {
  try {
    const res = await fetch("/api/state?limit=300");
    const state = await res.json();
    const now = performance.now();
    if (lastPacketCount !== null && lastPollTime !== null) {
      const dt = (now - lastPollTime) / 1000;
      if (dt > 0.05) rateDisplay = Math.max(0, Math.round((state.packet_count - lastPacketCount) / dt));
    }
    lastPacketCount = state.packet_count;
    lastPollTime = now;
    renderAll(state);
  } catch (e) {
    // server likely stopped -- fail quietly, next tick retries
  }
}

poll();
setInterval(poll, 1000);
</script>
</body>
</html>
"""


class WebDashboard:
    """Starts a background HTTP server exposing the live dashboard.

    Wraps a ScanEngine rather than owning capture/detection state itself:
    the dashboard just reports `engine.status` and the alert history, and
    forwards POST /api/start and /api/stop straight through to the engine.
    That's what lets a scan be started and stopped from the page itself,
    including the initial "just run it and go" case where no -i/--pcap was
    given at all -- the engine sits idle until a viewer picks a source.
    """

    def __init__(
        self,
        engine: ScanEngine,
        detector_names: List[str],
        host: str = "127.0.0.1",
        port: int = 8787,
    ):
        self.engine = engine
        self.alert_manager = engine.alert_manager
        self.detector_names = detector_names
        self.host = host
        self.port = port

        # Dashboard/server uptime -- distinct from the scan's own
        # started_at, which may be None (idle) or reset on every new scan.
        self._start_time = time.time()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def _state_payload(self, limit: int) -> dict:
        alerts = self.alert_manager.recent(limit)
        status = self.engine.status
        return {
            "uptime_seconds": time.time() - self._start_time,
            "packet_count": status.packet_count,
            "dropped_count": status.dropped_count,
            "detectors": self.detector_names,
            "alerts": [a.to_dict() for a in reversed(alerts)],
            "scan": {
                "running": status.running,
                "mode": status.mode,
                "source": status.source,
                "error": status.error,
            },
        }

    def _make_handler(self):
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: A002 - quiet by design
                pass

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _send_json(self, status: int, payload: dict) -> None:
                self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

            def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                parsed = urlparse(self.path)
                if parsed.path in ("/", "/index.html"):
                    self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
                elif parsed.path == "/api/state":
                    qs = parse_qs(parsed.query)
                    try:
                        limit = int(qs.get("limit", ["200"])[0])
                    except ValueError:
                        limit = 200
                    payload = dashboard._state_payload(limit)
                    self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                parsed = urlparse(self.path)
                if parsed.path not in ("/api/start", "/api/stop"):
                    self._send(404, b"not found", "text/plain")
                    return

                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._send_json(400, {"ok": False, "error": "malformed JSON request body"})
                    return

                if parsed.path == "/api/stop":
                    dashboard.engine.stop()
                    self._send_json(200, {"ok": True})
                    return

                # /api/start
                try:
                    dashboard.engine.start(
                        mode=body.get("mode", "live"),
                        interface=(body.get("interface") or None),
                        bpf_filter=body.get("bpf_filter") or "",
                        pcap_path=(body.get("pcap_path") or None),
                        realtime_replay=bool(body.get("realtime_replay", False)),
                    )
                    self._send_json(200, {"ok": True})
                except (ValueError, RuntimeError) as exc:
                    self._send_json(400, {"ok": False, "error": str(exc)})

        return Handler

    def start(self) -> None:
        handler = self._make_handler()
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        print(f"Web dashboard running at http://{self.host}:{self.port}/", file=sys.stderr)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
