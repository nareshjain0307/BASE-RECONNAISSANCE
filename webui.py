#!/usr/bin/env python3
"""
webui.py — Local web interface for BASE-RECONNAISSANCE
===================================================
Runs the recon pipeline from a browser: pick a target, choose which tools to
run (or all of them), watch live progress, then read the report in its own page
and export it as PDF, JSON or CSV.

Uses only the Python standard library, like the rest of the project.

Usage:
    python webui.py                     # http://127.0.0.1:8000
    python webui.py --port 9000
    python webui.py --host 0.0.0.0      # expose on LAN (read the warning below)

The server binds to 127.0.0.1 by default because it launches scanners. Binding
to 0.0.0.0 makes anyone who can reach the port able to scan arbitrary hosts from
your machine — only do that on a trusted, isolated network.
"""

import argparse
import copy
import html
import json
import logging
import re
import shutil
import sys
import threading
import traceback
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))

from recon import run_scan, banner, BOLD, CYAN, GREEN, YELLOW, RED, RESET
from modules.report import generate_html, generate_json, generate_csv

# ── Scan registry ────────────────────────────────────────────────────────────
# scan_id -> record. Guarded by SCANS_LOCK because the HTTP server is threaded.
SCANS: dict = {}
SCANS_LOCK = threading.Lock()

OUTPUT_ROOT = Path("output")

# Tools offered in the UI, with the description shown next to each checkbox.
TOOL_CHOICES = [
    ("whatweb",    "WhatWeb",    "Web technology fingerprinting (HTTP/S ports)"),
    ("gobuster", "Gobuster", "Directory/file discovery (HTTP/S ports)"),
    ("nikto",      "Nikto",      "Web vulnerability scan (HTTP/S ports)"),
    ("smbclient",  "smbclient",  "List SMB shares (ports 139/445)"),
    ("enum4linux", "enum4linux", "Deep SMB/RPC user, group and policy enum"),
    ("searchsploit", "Searchsploit", "Match detected services against ExploitDB"),
]

# nmap is not selectable: run_scan always runs it first because every other
# module depends on the open-port list it produces. It is still shown in the UI
# so its presence and status are visible rather than looking absent.
ALWAYS_RUN = [
    ("nmap", "nmap (port scan)",
     "Service/version detection — always runs first, all other tools use its results"),
]

# Binary required by each selectable tool, used for the availability strip.
TOOL_BINARY = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "nikto": "nikto",
    "gobuster": "gobuster",
    "smbclient": "smbclient",
    "enum4linux": "enum4linux-ng",   # preferred, falls back to enum4linux
    "searchsploit": "searchsploit",
}


def tool_available(key: str) -> bool:
    """True if the binary a tool needs is on PATH."""
    binary = TOOL_BINARY.get(key)
    if not binary:
        return True
    if key == "enum4linux":
        return (shutil.which("enum4linux-ng") is not None
                or shutil.which("enum4linux") is not None)
    return shutil.which(binary) is not None

# Targets are passed to nmap/whatweb/nikto as a bare argv element. A value
# beginning with "-" would be parsed by those tools as an option (e.g. an NSE
# script), so the character set is restricted to hostnames, IPv4/IPv6 literals
# and CIDR notation.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._\-:\[\]/%]+$")
_MAX_TARGET_LEN = 255


class ScanError(Exception):
    """A user-facing problem with a scan request."""


def validate_target(target: str) -> str:
    """Validate and normalise a scan target, or raise ScanError."""
    if target is None:
        raise ScanError("No target provided.")
    target = target.strip()
    if not target:
        raise ScanError("Target cannot be empty.")
    # Strip URL schemes that users commonly paste (http://host, https://host/path)
    for scheme in ("https://", "http://"):
        if target.lower().startswith(scheme):
            target = target[len(scheme):]
            break
    # Strip trailing path components (e.g. /login, /index.html)
    target = target.split("/")[0]
    # Strip trailing port if present after scheme strip (e.g. host:8080)
    # but keep IPv6 brackets intact
    target = target.strip()
    if not target:
        raise ScanError("Target cannot be empty after stripping URL scheme.")
    if len(target) > _MAX_TARGET_LEN:
        raise ScanError(f"Target is too long (max {_MAX_TARGET_LEN} characters).")
    if target.startswith("-"):
        raise ScanError("Target cannot start with '-'.")
    if not _TARGET_RE.match(target):
        raise ScanError(
            "Target contains invalid characters. Use a hostname, IPv4/IPv6 "
            "address or CIDR range (letters, digits, dots, dashes, colons)."
        )
    return target


def scan_record(scan_id: str) -> dict:
    with SCANS_LOCK:
        rec = SCANS.get(scan_id)
    if rec is None:
        raise ScanError(f"Unknown scan '{scan_id}'.")
    return rec


def disk_record(scan_id: str) -> dict:
    """
    Rebuild a completed record from a scan directory on disk.

    The in-memory registry is lost when the server restarts, but the scan
    artefacts remain, so /scan/<id> stays useful instead of erroring out.
    """
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", scan_id):
        raise ScanError("Invalid scan id.")
    base = OUTPUT_ROOT / scan_id
    state_file = base / "state.json"
    if not state_file.is_file():
        raise ScanError(f"No scan '{scan_id}' on this server.")

    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"Could not read saved scan state: {exc}")

    reports = {}
    for kind in ("html", "json", "csv"):
        matches = sorted(base.glob(f"report_*.{kind}"))
        if matches:
            reports[kind] = matches[-1].name

    meta = state.get("meta", {})
    return {
        "id": scan_id,
        "target": state.get("target", scan_id),
        "profile": meta.get("profile", "quick"),
        "parallel": meta.get("parallel", 4),
        "selected": meta.get("selected", "all"),
        "demo": bool(meta.get("demo")),
        "status": scan_outcome(state)[0],
        "started": meta.get("timestamp"),
        "finished": None,
        "events": [],
        "from_disk": True,
        "state": state,
        "scan_dir": str(base),
        "reports": reports,
        "summary": _summarise(state),
        "error": scan_outcome(state)[1],
    }


def find_record(scan_id: str) -> dict:
    """In-memory record if the scan is live, otherwise the one on disk."""
    with SCANS_LOCK:
        rec = SCANS.get(scan_id)
        if rec is not None:
            return copy.deepcopy(rec)
    return disk_record(scan_id)


# ── The scan job ─────────────────────────────────────────────────────────────

def start_scan(target: str, profile: str, parallel: int, selected: list,
               demo: bool, wordlist=None) -> str:
    """
    Kick off a scan in a background thread and return its id immediately.

    Args:
        target:    Validated target string.
        profile:   'quick' or 'full'.
        parallel:  Thread pool size.
        selected:  Optional module names to run (empty list means all).
        demo:      Use embedded demo data instead of scanning.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id = f"{timestamp}_{uuid.uuid4().hex[:6]}"
    scan_dir = OUTPUT_ROOT / scan_id
    raw_dir = scan_dir / "raw"
    scan_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    record = {
        "id": scan_id,
        "target": target,
        "profile": profile,
        "parallel": parallel,
        "selected": selected,
        "demo": demo,
        "wordlist": wordlist,
        "status": "running",
        "started": datetime.now().isoformat(timespec="seconds"),
        "finished": None,
        "events": [],
        "scan_dir": str(scan_dir),
        "reports": {},
        "error": None,
    }
    with SCANS_LOCK:
        SCANS[scan_id] = record

    thread = threading.Thread(target=_run_job, args=(scan_id, scan_dir, raw_dir),
                              daemon=True, name=f"scan-{scan_id}")
    thread.start()
    return scan_id


def _run_job(scan_id: str, scan_dir: Path, raw_dir: Path) -> None:
    """Body of a background scan. Never raises; records failures on the record."""
    with SCANS_LOCK:
        rec = SCANS[scan_id]

    def on_event(event):
        with SCANS_LOCK:
            result = event.get('result')
            if result is not None:
                rec.setdefault('results', {})[event['name']] = copy.deepcopy(result)
                rec['revision'] = rec.get('revision', 0) + 1
            stamped = {**{k: v for k, v in event.items() if k != 'result'},
                       "at": datetime.now().strftime("%H:%M:%S")}
            # Update existing event for the same task name instead of
            # duplicating (e.g. running -> ok transitions).
            if event.get("type") == "task" and event.get("name"):
                for i, existing in enumerate(rec["events"]):
                    if (existing.get("type") == "task"
                            and existing.get("name") == event["name"]):
                        rec["events"][i] = stamped
                        return
            rec["events"].append(stamped)

    # Each scan gets its own log file; the console handler is silenced so the
    # server's terminal is not flooded by parallel scans.
    log_file = scan_dir / "recon.log"
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"))
    root = logging.getLogger()
    prev_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)

    try:
        target = rec["target"]
        profile = rec["profile"]
        demo = rec["demo"]
        selected = rec["selected"]

        if demo:
            target = "demo-target"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        state = {
            "target": target,
            "timestamp": timestamp,
            "meta": {
                "profile": profile,
                "timestamp": timestamp,
                "demo": demo,
                "parallel": rec["parallel"],
                "selected": rec["selected"],
                "wordlist": rec.get("wordlist"),
                "source": "webui",
            },
        }

        # quiet=True suppresses console output; no need to hijack sys.stdout
        # which is process-global and unsafe across threads.
        scan_data = run_scan(
            target, profile, scan_dir, raw_dir,
            parallel=rec["parallel"],
            verbose=False,
            demo=demo,
            state=state,
            selected=selected,
            on_event=on_event,
            quiet=True,
        )

        # ── Reports ───────────────────────────────────────────────────────
        html_path = scan_dir / f"report_{scan_id}.html"
        json_path = scan_dir / f"report_{scan_id}.json"
        csv_path = scan_dir / f"report_{scan_id}.csv"

        generate_html(scan_data, html_path, raw_dir)
        generate_json(scan_data, json_path)
        generate_csv(scan_data, csv_path)

        rec["reports"] = {
            "html": html_path.name,
            "json": json_path.name,
            "csv": csv_path.name,
        }
        rec["results"] = {name: copy.deepcopy(scan_data[name]) for name in TOOL_BINARY if name in scan_data}
        rec['revision'] = rec.get('revision', 0) + 1
        rec["summary"] = _summarise(scan_data)
        rec["status"], rec["error"] = scan_outcome(scan_data)

    except Exception as exc:
        rec["status"] = "error"
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["traceback"] = traceback.format_exc()
    finally:
        rec["finished"] = datetime.now().isoformat(timespec="seconds")
        root.removeHandler(handler)
        handler.close()
        root.setLevel(prev_level)


# _QuietStdout removed: it was process-global and thread-unsafe.
# The scan runner now relies on quiet=True passed to run_scan() instead.


def scan_outcome(state):
    if state.get('nmap', {}).get('error'):
        return 'error', 'Port discovery failed: ' + str(state['nmap']['error'])
    failures = [f"{name}: {result.get('error', 'Failed')}" for name, result in state.items()
                if isinstance(result, dict) and result.get('status') == 'error']
    return ('done_with_errors', '; '.join(failures)) if failures else ('done', None)


def _summarise(scan_data: dict) -> dict:
    """Small summary object the UI shows next to a finished scan."""
    nmap = scan_data.get("nmap", {})
    vuln = scan_data.get("searchsploit", {})
    return {
        "open_ports": len(nmap.get("open_ports", [])),
        "hostname": nmap.get("hostname", ""),
        "os_guess": nmap.get("os_guess", ""),
        "exploits": vuln.get("total_exploits", 0),
    }


# ── Scans already on disk ────────────────────────────────────────────────────

def list_disk_scans() -> list:
    """Scans present in output/, so the UI survives a server restart."""
    out = []
    if not OUTPUT_ROOT.exists():
        return out
    for d in sorted(OUTPUT_ROOT.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        reports = {}
        for kind in ("html", "json", "csv"):
            matches = sorted(d.glob(f"report_*.{kind}"))
            if matches:
                reports[kind] = matches[-1].name
        out.append({
            "id": d.name,
            "target": d.name,
            "html": reports.get("html"),
            "json": reports.get("json"),
            "csv": reports.get("csv"),
        })
    return out


# ── HTML escaping helper for the small server-rendered pages ────────────────

def esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_message(title: str, message: str) -> bytes:
    """Small HTML page used for friendly errors on browser-facing routes."""
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>{PAGE_CSS}</style></head><body><div class="wrap">
<header><h1>🛡 BASE-RECONNAISSANCE</h1><a class="btn sec" href="/">← New scan</a></header>
<div class="card"><h2>{esc(title)}</h2><p class="muted">{esc(message)}</p></div>
</div></body></html>"""
    return page.encode("utf-8")


def _scan_row(s: dict) -> str:
    """One row in the 'previous scans' table."""
    sid = esc(s["id"])
    report = (f'<a href="/report/{sid}">report</a>' if s.get("html")
              else '<span class="muted">no report</span>')
    links = " ".join(
        '<a href="/download/{sid}/{k}">{up}</a>'.format(sid=sid, k=k, up=k.upper())
        for k in ("html", "json", "csv") if s.get(k)
    )
    return f'<tr><td class="mono">{sid}</td><td>{report}</td><td>{links}</td></tr>'


# ══════════════════════════════════════════════════════════════════════════
#  Frontend
# ══════════════════════════════════════════════════════════════════════════

PAGE_CSS = """
:root{--bg:#ffffff;--surface:#ffffff;--border:#dce3ed;--text:#172b45;--muted:#5b6b80;
--accent:#2459d3;--green:#167344;--yellow:#936000;--red:#c52c3a;--orange:#b74712;--purple:#7040b0}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
font-size:14px;line-height:1.6;padding:0 1rem 4rem}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:900px;margin:0 auto}
header{display:flex;align-items:center;gap:.8rem;padding:1.2rem 0;border-bottom:1px solid var(--border);margin-bottom:1.6rem}
header h1{font-size:1.3rem;color:var(--accent);flex:1}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.4rem;margin-bottom:1.2rem}
h2{font-size:1.05rem;margin-bottom:1rem}
label{display:block;margin-bottom:.35rem;color:var(--muted);font-size:.82rem;text-transform:uppercase;letter-spacing:.05em}
input[type=text],input[type=number],select{width:100%;background:var(--bg);color:var(--text);
border:1px solid var(--border);border-radius:6px;padding:.6rem .7rem;font-size:.95rem;font-family:inherit}
input:focus,select:focus{outline:none;border-color:var(--accent)}
.grid{display:grid;grid-template-columns:2fr 1fr 1fr;gap:1rem}
.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:.7rem}
.tool{display:flex;gap:.6rem;align-items:flex-start;background:var(--bg);border:1px solid var(--border);
border-radius:8px;padding:.7rem .8rem;cursor:pointer}
.tool:hover{border-color:var(--accent)}
.tool input{margin-top:.25rem;accent-color:var(--accent)}
.tool .name{font-weight:600;display:block}
.tool .desc{color:var(--muted);font-size:.78rem}
.tool.locked{cursor:default;background:#f4f7fb;border-style:dashed}
.tool.locked:hover{border-color:var(--border)}
.tool.locked .box{width:15px;height:15px;margin-top:.22rem;border:1px solid var(--muted);
border-radius:3px;background:var(--surface);flex:none}
.tool.off{opacity:.55}
.tool.off .name{text-decoration:line-through}
.avail{margin-left:auto;align-self:center;font-size:.7rem;font-weight:600;padding:.15rem .5rem;
border-radius:99px;border:1px solid currentColor;white-space:nowrap;flex:none}
.avail.yes{color:var(--green)}
.avail.no{color:var(--red)}
.btn{display:inline-flex;align-items:center;gap:.4rem;background:var(--accent);color:#ffffff;border:none;
border-radius:6px;padding:.65rem 1.2rem;font-size:.9rem;font-weight:600;cursor:pointer;font-family:inherit}
.btn:hover{filter:brightness(1.1)}
.btn.sec{background:var(--surface);color:var(--text);border:1px solid var(--border)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;margin-top:1.1rem}
.warn{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.4);border-radius:8px;
padding:.7rem .9rem;font-size:.83rem;color:#a32232;margin-top:1.1rem}
.err{background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.5);border-radius:8px;
padding:.8rem 1rem;color:#a32232;margin:1rem 0;white-space:pre-wrap;font-family:monospace;font-size:.82rem}
.status{display:flex;align-items:center;gap:.6rem;padding:.5rem 0;border-bottom:1px solid var(--border)}
.status:last-child{border-bottom:none}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}
.dot.run{background:var(--yellow);animation:pulse 1s infinite}
.dot.ok{background:var(--green)}
.dot.err{background:var(--red)}
.dot.skip{background:var(--muted)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.sname{font-weight:600;min-width:150px}
.sdetail{color:var(--muted);font-size:.84rem}
.stamp{color:var(--muted);font-size:.75rem;margin-left:auto}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;
padding:.5rem .6rem;border-bottom:1px solid var(--border)}
td{padding:.5rem .6rem;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:.15rem .55rem;border-radius:99px;font-size:.72rem;
font-weight:600;border:1px solid currentColor}
.b-green{color:var(--green)}.b-red{color:var(--red)}.b-yellow{color:var(--yellow)}.b-muted{color:var(--muted)}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem}
/* Light workspace */
:root{color-scheme:light}
body{font-family:Inter,'Segoe UI',system-ui,sans-serif;line-height:1.65}
.wrap{max-width:1120px}
header{padding:1.6rem 0;margin-bottom:2rem;flex-wrap:wrap}
header h1{color:var(--text);font-size:1.1rem;letter-spacing:-.03em;overflow-wrap:anywhere}
header .badge{background:#eef4ff;color:var(--accent);border-color:#d7e4ff}
.hero{margin:0 0 2rem;max-width:740px}
.eyebrow{color:var(--accent);font-size:.72rem;letter-spacing:.15em;font-weight:750;text-transform:uppercase;margin-bottom:.6rem}
.hero h2{font-size:clamp(1.9rem,4vw,2.7rem);line-height:1.15;letter-spacing:-.045em;margin-bottom:.8rem}
.hero p{color:var(--muted);font-size:1rem;max-width:600px}
.workflow{display:flex;gap:.65rem;flex-wrap:wrap;margin-top:1.2rem}
.workflow span{font-size:.78rem;color:var(--muted);background:#f4f7fb;padding:.35rem .8rem;border-radius:30px}
.card{border-radius:16px;padding:1.6rem;box-shadow:0 5px 24px rgba(23,43,69,.045);margin-bottom:1.5rem}
h2{font-size:1.12rem;letter-spacing:-.02em}
label{font-weight:600;font-size:.75rem}
input[type=text],input[type=number],select{min-height:46px;border-radius:9px;background:#fbfcfe}
input:focus,select:focus{box-shadow:0 0 0 3px #2459d31a}
:focus-visible{outline:3px solid #2459d3;outline-offset:3px}
.tool{border-radius:11px;min-height:84px;transition:border-color .15s,background .15s;text-transform:none;letter-spacing:normal}
.tool:has(input:checked:not(:disabled)){border-color:#b8cef7;background:#f5f8ff}
.tool .name{font-size:.9rem;color:var(--text)}
.tool .desc{font-weight:400;line-height:1.5;display:block;margin-top:.18rem}
.tool.locked{border-style:solid}
.btn{border-radius:9px;min-height:42px;transition:background .15s,box-shadow .15s}
.btn:hover{filter:brightness(.96);text-decoration:none;box-shadow:0 3px 10px #172b4510}
#go{padding:.8rem 1.6rem;box-shadow:0 4px 12px #2459d330}
.warn{background:#fff9ed;border-color:#eddbad;color:#765419}
.err{background:#fff1f2;border-color:#f0bec4;color:#a32232}
.dot.err{padding:0;margin:0;border:0;background:var(--red)}
th{background:#f5f7fb;padding:.8rem}
td{padding:.8rem;overflow-wrap:anywhere}
tr:hover td{background:#fafbfe}
.status{flex-wrap:wrap;gap:.6rem;padding:.8rem 0}
.sdetail{overflow-wrap:anywhere}
.card{overflow-x:auto}
@media(max-width:640px){body{padding:0 .8rem 2rem}.card{padding:1rem}.grid{grid-template-columns:1fr}.tools{grid-template-columns:1fr}header{gap:.5rem}.stamp{margin-left:0}.hero{margin-bottom:1.5rem}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}

"""

INDEX_JS = """
function toolBoxes(){return Array.from(document.querySelectorAll('input[name=tools]')).filter(b=>!b.disabled);}
function setAll(on){ toolBoxes().forEach(b=>b.checked=on); updateCount(); }
function updateCount(){
  const boxes=toolBoxes();
  const n=boxes.filter(b=>b.checked).length;
  document.getElementById('selcount').textContent =
    n===0?'none':(n===boxes.length?'all':n+' selected');
}
document.querySelectorAll('input[name=tools]').forEach(b=>b.addEventListener('change',updateCount));

document.getElementById('go').addEventListener('click', async function(){
  const target = document.getElementById('target').value.trim();
  const demo   = document.getElementById('demo').checked;
  const ack    = document.getElementById('ack').checked;
  const tools  = Array.from(document.querySelectorAll('input[name=tools]:checked')).map(b=>b.value);
  const errBox = document.getElementById('err'); errBox.style.display='none';

  if(!target && !demo){ showErr('Enter a target IP address or hostname.'); return; }
  if(!demo && !ack){ showErr('Confirm you are authorised to test this target.'); return; }


  const btn=this; btn.disabled=true; btn.textContent='Starting…';
  try{
    const r = await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target:target,profile:document.getElementById('profile').value,
        parallel:parseInt(document.getElementById('parallel').value,10)||4,
        tools:tools,demo:demo,wordlist:document.getElementById("wordlist").value.trim()})});
    const j = await r.json();
    if(!r.ok) throw new Error(j.error||'Request failed');
    location.href = '/scan/'+j.id;
  }catch(e){ showErr(e.message); btn.disabled=false; btn.textContent='▶ Start scan'; }
});
function showErr(m){ const b=document.getElementById('err'); b.textContent=m; b.style.display='block';
  document.getElementById('go').disabled=false; document.getElementById('go').textContent='▶ Start scan'; }
"""


def render_index(scans: list) -> bytes:
    boxes = "".join(
        f"""<label class="tool{' off' if not tool_available(key) else ''}">
<input type="checkbox" name="tools" value="{esc(key)}" checked{' disabled' if not tool_available(key) else ''}>
<span><span class="name">{esc(label)}</span>
<span class="desc">{esc(desc)}</span></span>
{"<span class='avail no'>not installed</span>" if not tool_available(key) else ""}</label>"""
        for key, label, desc in TOOL_CHOICES
    )
    locked = "".join(
        f"""<div class="tool locked">
<span class="box"></span>
<span><span class="name">{esc(label)}</span>
<span class="desc">{esc(desc)}</span></span>
<span class="avail {'yes' if tool_available(key) else 'no'}">
{'always runs' if tool_available(key) else 'not installed'}</span></div>"""
        for key, label, desc in ALWAYS_RUN
    )
    rows = "".join(_scan_row(s) for s in scans) or \
        '<tr><td colspan="3" class="muted">No scans yet.</td></tr>'

    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BASE-RECONNAISSANCE</title><style>{PAGE_CSS}</style></head><body><div class="wrap">
<header><h1>🛡 BASE-RECONNAISSANCE</h1><span class="badge b-muted">Recon workspace</span></header>

<section class="hero">
  <div class="eyebrow">Discover · Assess · Understand</div>
  <h2>A clearer view of your attack surface.</h2>
  <p>Bring service discovery, web checks, and security findings together in one focused workspace.</p>
  <div class="workflow"><span>01 &nbsp; Choose a target</span><span>02 &nbsp; Select your tools</span><span>03 &nbsp; Review findings</span></div>
</section>
<div class="card">
  <h2>Configure your scan</h2>
  <div class="grid">
    <div><label for="target">Target (IP or hostname)</label>
      <input type="text" id="target" placeholder="192.168.1.10" autocomplete="off"></div>
    <div><label for="profile">Profile</label><select id="profile">
      <option value="quick">quick — top 100</option><option value="full">full — 1-65535</option></select></div>
    <div><label for="parallel">Parallel</label>
      <input type="number" id="parallel" value="4" min="1" max="16"></div>
  </div>

  <div style="margin-top:1rem"><label for="wordlist">Gobuster wordlist (optional server path)</label><input type="text" id="wordlist" placeholder="Default: dirb/common.txt or SecLists common.txt"></div>
  <h2 style="margin-top:1.4rem">Tools <span class="muted" id="selcount" style="font-size:.8rem"></span></h2>
  <div class="tools">{locked}</div>
  <div class="tools" style="margin-top:.7rem">{boxes}</div>
  <div class="row">
    <button class="btn sec" onclick="setAll(true)">Select all</button>
    <button class="btn sec" onclick="setAll(false)">Clear</button>
  </div>

  <div class="warn">⚠ Only scan systems you own or have explicit written permission to
  test. Scanning without authorisation may be unlawful.</div>
  <label style="display:flex;gap:.6rem;align-items:center;text-transform:none;letter-spacing:0;
font-size:.9rem;color:var(--text);margin-top:.8rem">
    <input type="checkbox" id="ack"> I am authorised to test this target</label>
  <label style="display:flex;gap:.6rem;align-items:center;text-transform:none;letter-spacing:0;
font-size:.9rem;color:var(--text);margin-top:.5rem">
    <input type="checkbox" id="demo"> Demo mode (embedded Metasploitable 2 data, no live target)</label>

  <div class="row"><button class="btn" id="go">▶ Start scan</button></div>
  <div class="err" id="err" style="display:none"></div>
</div>

<div class="card">
  <h2>Previous scans</h2>
  <table><thead><tr><th>Scan</th><th>Report</th><th>Download</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>
</div>
<script>
{INDEX_JS}
updateCount();
</script></body></html>"""
    return page.encode("utf-8")


STATUS_JS = """
let last = '';
let revision = -1;
async function poll(){
  try{
    const r = await fetch('/api/scan/' + SID);
    const j = await r.json();
    if(j.events && JSON.stringify(j.events) !== last){
      last = JSON.stringify(j.events);
      document.getElementById('log').innerHTML = j.events.map(e=>{
        let cls = e.type==='task' ? (e.status==='ok'?'ok':(e.status==='error'?'err':(e.status==='skipped'?'skip':'run'))) : 'run';
        let label = e.type==='phase' ? e.label : e.name;
        let detail = e.detail || '';
        return `<div class="status"><span class="dot ${cls}"></span>
          <span class="sname">${esc(label)}</span>
          <span class="sdetail">${esc(detail)}</span>
          <span class="stamp">${esc(e.at||'')}</span></div>`;
      }).join('');
    }
    if(j.tools){
      const labels={ok:'Completed',running:'Running',waiting:'Waiting',error:'Failed',skipped:'Skipped'};
      const classes={ok:'ok',running:'run',error:'err'};
      document.getElementById('tools-live').innerHTML=j.tools.map(row=>`<div class="status"><span class="dot ${classes[row.status]||'skip'}"></span><span class="sname">${esc(row.name)}</span><span>${esc(labels[row.status]||row.status)}</span><span class="sdetail">${esc(row.detail)}</span></div>`).join('');
    }
    if(j.revision !== revision && j.results_html !== undefined){
      const container=document.getElementById('results-live');
      const open={};container.querySelectorAll('details[data-tool]').forEach(d=>open[d.dataset.tool]=d.open);
      container.innerHTML=j.results_html;
      container.querySelectorAll('details[data-tool]').forEach(d=>{if(d.dataset.tool in open)d.open=open[d.dataset.tool];});
      revision=j.revision;
    }
    if (j.status) {
        document.getElementById('state').textContent = j.status;
        if(['done','done_with_errors','error'].includes(j.status)){
          clearInterval(t);
          document.getElementById('state').textContent = j.status;
          if(j.error){ document.getElementById('fail').style.display='block';
                       document.getElementById('fail').textContent = j.error; }
          location.reload();
        }
    }
  }catch(e){
      console.error(e);
  }
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
let t=setInterval(poll,1000); poll();
"""


def render_findings(results):
    """Escaped completed-tool findings, usable in initial HTML and poll replies."""
    cards = []
    def table(rows):
        return '<table><tbody>' + ''.join('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table>'
    def lines(values):
        return '<ul>' + ''.join(f'<li>{esc(v)}</li>' for v in values) + '</ul>'
    for name in TOOL_BINARY:
        result = results.get(name)
        if result is None:
            continue
        status = result.get('status', 'error' if result.get('error') else 'ok')
        label = {'ok': 'Completed', 'error': 'Failed / partial results', 'skipped': 'Skipped'}.get(status, status)
        body = f"<p class='muted'>{esc(result['error'])}</p>" if result.get('error') else ''
        if name == 'nmap':
            body += table([(f"{p['port']}/{p.get('protocol', 'tcp')}", p.get('service', ''), p.get('product', ''), p.get('version', '')) for p in result.get('open_ports', [])])
        elif name == 'whatweb':
            for finding in result.get('findings', []):
                body += f"<h3>{esc(finding.get('url', ''))}</h3>" + table([(t.get('name', ''), t.get('version', ''), t.get('detail', '')) for t in finding.get('technologies', [])])
        elif name in ('gobuster', 'nikto'):
            for finding in result.get('findings', []):
                body += f"<h3>{esc(finding.get('url') or 'Port ' + str(finding.get('port', '')))}</h3>"
                body += lines(finding.get('paths', finding.get('vulnerabilities', [])))
                body += lines(finding.get('warnings', []))
                if finding.get('error'):
                    body += f"<p class='muted'>{esc(finding['error'])}</p>"
        elif name == 'smbclient':
            body += table([(s.get('name', ''), s.get('type', ''), s.get('comment', '')) for s in result.get('shares', [])])
        elif name == 'enum4linux':
            body += f"<p>Workgroup: {esc(result.get('workgroup', ''))}</p>"
            body += table([(u.get('username', ''), u.get('uid', ''), u.get('comment', '')) for u in result.get('users', [])])
            body += lines(result.get('groups', [])) + table(result.get('password_policy', {}).items())
        elif name == 'searchsploit':
            body += f"<p>{esc(result.get('total_exploits', 0))} version matches; {esc(result.get('total_unverified', 0))} unverified leads.</p>"
            for row in result.get('results', []):
                body += f"<h3>Port {esc(row.get('port'))}: {esc(row.get('service', ''))}</h3>"
                body += lines([f"EDB-{e.get('id')}: {e.get('title')} — {e.get('match_reason', '')}" for e in row.get('exploits', [])])
                if row.get('unverified'):
                    body += '<details><summary>Unverified leads — excluded from matched count</summary>' + lines([e.get('title', '') for e in row['unverified']]) + '</details>'
                if row.get('error'):
                    body += f"<p>{esc(row['error'])}</p>"
        if not body:
            body = '<p class="muted">No findings returned.</p>'
        cards.append(f'<details class="card finding" data-tool="{esc(name)}" open><summary><strong>{esc(name)}</strong> — {esc(label)}</summary>{body}</details>')
    return ''.join(cards) or '<p class="muted">Results will appear here as each tool finishes.</p>'


def tool_statuses(rec):
    events = {e.get('name'): e for e in rec.get('events', []) if e.get('type') == 'task'}
    results = rec.get('results', rec.get('state', {}))
    selected = rec.get('selected', 'all')
    rows = []
    for name in TOOL_BINARY:
        event = events.get(name, {})
        result = results.get(name, {})
        default = 'waiting' if name == 'nmap' or selected == 'all' or name in selected else 'skipped'
        rows.append({'name': name, 'status': event.get('status') or result.get('status') or default,
                     'detail': event.get('detail') or result.get('error') or ''})
    return rows


def render_tools(rows):
    labels = {'ok': 'Completed', 'running': 'Running', 'waiting': 'Waiting', 'error': 'Failed', 'skipped': 'Skipped'}
    classes = {'ok': 'ok', 'running': 'run', 'error': 'err'}
    return ''.join(f"<div class='status'><span class='dot {classes.get(row['status'], 'skip')}'></span><span class='sname'>{esc(row['name'])}</span><span>{esc(labels.get(row['status'], row['status']))}</span><span class='sdetail'>{esc(row['detail'])}</span></div>" for row in rows)


def render_status(scan_id: str) -> bytes:
    rec = find_record(scan_id)

    if rec.get("from_disk"):
        # Events live in memory only, so show the module outcomes recorded in
        # state.json instead of an empty progress list.
        rows = []
        labels = {"nmap": "Nmap", "whatweb": "WhatWeb", "nikto": "Nikto", "smbclient": "smbclient",
                  "enum4linux": "enum4linux", "gobuster": "Gobuster", "searchsploit": "Searchsploit"}
        for key, label in labels.items():
            mod = (rec.get("state") or {}).get(key) or {}
            if mod.get("error"):
                rows.append(f'<div class="status"><span class="dot muted"></span>'
                            f'<span class="sname">{esc(label)}</span>'
                            f'<span class="sdetail">{esc(mod["error"])}</span></div>')
            else:
                rows.append(f'<div class="status"><span class="dot ok"></span>'
                            f'<span class="sname">{esc(label)}</span>'
                            f'<span class="sdetail">completed</span></div>')
        events = ('<div class="muted" style="padding:.4rem 0;font-size:.82rem">'
                  'Live progress is only available while the scan runs. Showing the '
                  'saved results for this scan.</div>' + "".join(rows))
    else:
        events = "".join(
            f"""<div class="status"><span class="dot {'ok' if e.get('status')=='ok' else ('err' if e.get('status')=='error' else ('skip' if e.get('status')=='skipped' else 'run'))}"></span>
<span class="sname">{esc(e.get('label') or e.get('name',''))}</span>
<span class="sdetail">{esc(e.get('detail',''))}</span>
<span class="stamp">{esc(e.get('at',''))}</span></div>"""
            for e in rec["events"]
        ) or '<div class="muted" style="padding:.5rem 0">Waiting for nmap…</div>'

    # Always render the fail container with id="fail" so STATUS_JS can
    # reference it. Show it only when the scan has already errored;
    # the JS will unhide it if an error arrives while polling.
    fail_msg = esc(rec.get("error", "")) if rec.get('error') else ""
    fail_display = "" if rec.get('error') else ' style="display:none"'
    fail = f'<div class="err" id="fail"{fail_display}>{fail_msg}</div>'

    results = rec.get('results', rec.get('state', {}))
    live_block = '<div class="card"><h2>Tool status</h2><div id="tools-live">' + render_tools(tool_statuses(rec)) + '</div></div>'
    live_block += '<h2>Results so far</h2><p class="muted">Completed tools appear below while other tools continue. Failed tools may have partial findings.</p><div id="results-live">' + render_findings(results) + '</div>'
    done_block = ""
    if rec["status"] in ('done', 'done_with_errors', 'error') and rec.get("reports"):
        s = rec.get("summary", {})
        done_block = f"""
<div class="card">
  <h2>{'Scan complete' if rec['status'] == 'done' else 'Scan finished with issues'}</h2>
  <div class="row" style="margin-top:0">
    <a class="btn" href="/report/{esc(scan_id)}" target="_blank">📄 Open report in new page</a>
    <a class="btn sec" href="/print/{esc(scan_id)}" target="_blank">🖨 Save as PDF</a>
    <a class="btn sec" href="/download/{esc(scan_id)}/json">⬇ JSON</a>
    <a class="btn sec" href="/download/{esc(scan_id)}/csv">⬇ CSV</a>
    <a class="btn sec" href="/download/{esc(scan_id)}/html">⬇ HTML</a>
  </div>
  <table style="margin-top:1.2rem">
    <tr><th>Open ports</th><th>Version matches</th><th>Hostname</th></tr>
    <tr><td><span class="badge b-green">{s.get('open_ports',0)}</span></td>
        <td><span class="badge {'b-red' if s.get('exploits') else 'b-green'}">{s.get('exploits',0)}</span></td>
        <td class="mono">{esc(s.get('hostname') or 'N/A')}</td></tr>
  </table>
</div>"""

    # Only poll while a live scan is actually in progress.
    script = ""
    if not rec.get("from_disk") and rec["status"] == "running":
        script = f"<script>const SID = {json.dumps(scan_id)};\n" \
                 + STATUS_JS.replace("{SID}", '" + SID + "') + "</script>"

    title_word = "Scan" if rec["status"] == "running" else "Scan result"
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_word} {esc(scan_id)}</title><style>{PAGE_CSS}</style></head><body><div class="wrap">
<header><h1>🛡 {esc(title_word)} — {esc(rec['target'])}</h1>
<span class="badge b-yellow" id="state">{esc(rec['status'])}</span>
<a class="btn sec" href="/">← New scan</a></header>

<div class="card">
  <h2>Progress</h2>
  <div id="log">{events}</div>
</div>
{fail}
{live_block}
{done_block}
</div>
{script}
</body></html>"""
    return page.encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════
#  HTTP layer
# ══════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    server_version = "BASE-RECONNAISSANCE"
    protocol_version = "HTTP/1.1"

    # ── helpers ─────────────────────────────────────────────────────────
    def _send(self, code: int, body: bytes, ctype: str, extra: dict = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src data:; form-action 'none'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, code: int, message: str):
        self._send(code, json.dumps({"error": message}).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _notfound(self):
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s  %s\n" % (self.log_date_time_string(), fmt % args))

    # ── routing ─────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path in ("/", "/index.html"):
                return self._send(200, render_index(list_disk_scans()),
                                  "text/html; charset=utf-8")
            if path.startswith("/scan/"):
                sid = path.split("/")[2]
                try:
                    body = render_status(sid)
                except ScanError as exc:
                    body = render_message("Scan not found", str(exc))
                return self._send(200, body, "text/html; charset=utf-8")
            if path.startswith("/api/scan/"):
                sid = path.split("/")[3]
                try:
                    rec = find_record(sid)
                except ScanError as exc:
                    return self._json({"error": str(exc)}, 404)
                return self._json({
                    "id": rec["id"], "status": rec["status"], "target": rec["target"],
                    "error": rec["error"], "events": rec["events"],
                    "summary": rec.get("summary"),
                    "tools": tool_statuses(rec),
                    "revision": rec.get('revision', 0),
                    "results_html": render_findings(rec.get('results', rec.get('state', {}))),
                })
            if path.startswith("/api/scans"):
                return self._json({"scans": list_disk_scans()})
            if path.startswith("/report/") or path.startswith("/print/"):
                return self._serve_report(path)
            if path.startswith("/download/"):
                return self._serve_download(path)
            if path.startswith("/raw/"):
                return self._serve_raw(path)
            return self._notfound()
        except ScanError as exc:
            return self._error(404, str(exc))
        except Exception as exc:
            traceback.print_exc()
            return self._error(500, f"{type(exc).__name__}: {exc}")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/scan":
            return self._notfound()
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64 * 1024:
                return self._error(413, "Request body too large.")
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._error(400, "Invalid JSON body.")

        try:
            demo = bool(payload.get("demo"))
            target = payload.get("target") or ""
            if not demo:
                target = validate_target(target)
            else:
                target = target.strip()[:64] or "demo-target"

            profile = payload.get("profile") or "quick"
            if profile not in ("quick", "full"):
                return self._error(400, "Profile must be 'quick' or 'full'.")

            try:
                parallel = int(payload.get("parallel") or 4)
            except (TypeError, ValueError):
                parallel = 4
            parallel = max(1, min(16, parallel))

            tools = payload.get("tools") or []
            if not isinstance(tools, list):
                return self._error(400, "'tools' must be a list.")
            valid = {k for k, _, _ in TOOL_CHOICES}
            tools = [t for t in tools if t in valid]
            if "tools" not in payload:
                tools = sorted(valid)
            wordlist = payload.get("wordlist")
            if wordlist is not None and not isinstance(wordlist, str):
                return self._error(400, "wordlist must be a path string.")

            scan_id = start_scan(target, profile, parallel, tools, demo, wordlist or None)
            return self._json({"id": scan_id}, 201)
        except ScanError as exc:
            return self._error(400, str(exc))
        except Exception as exc:
            traceback.print_exc()
            return self._error(500, f"{type(exc).__name__}: {exc}")

    # ── file serving (path-traversal safe) ──────────────────────────────
    def _scan_file(self, scan_id: str, kind: str) -> Path:
        """Resolve output/<scan_id>/<file> and refuse anything outside it."""
        if not re.match(r"^[A-Za-z0-9._-]{1,64}$", scan_id):
            raise ScanError("Invalid scan id.")
        base = (OUTPUT_ROOT / scan_id).resolve()
        try:
            base.relative_to(OUTPUT_ROOT.resolve())
        except ValueError:
            raise ScanError("Invalid scan path.")
        if not base.is_dir():
            raise ScanError("No such scan on disk.")

        if kind == "html":
            matches = sorted(base.glob("report_*.html"))
        else:
            matches = sorted(base.glob(f"report_*.{kind}"))
        if not matches:
            raise ScanError(f"No {kind} report for this scan.")
        return matches[-1].resolve()

    def _serve_report(self, path: str):
        parts = path.strip("/").split("/")      # report|print / <id>
        if len(parts) != 2:
            return self._notfound()
        scan_id = parts[1]
        # Works for live scans and for scans discovered on disk.
        try:
            rec = scan_record(scan_id)
        except ScanError:
            rec = None

        try:
            f = self._scan_file(scan_id, "html")
        except ScanError as exc:
            return self._send(404, f"<h1>404</h1><p>{esc(exc)}</p>",
                              "text/html; charset=utf-8")

        body = f.read_bytes()
        if rec and rec["status"] == "running":
            body = self._inject_running_banner(body, rec)
        if parts[0] == "print":
            body = self._inject_print_button(body, scan_id)
        return self._send(200, body, "text/html; charset=utf-8")

    def _serve_download(self, path: str):
        parts = path.strip("/").split("/")      # download / <id> / <kind>
        if len(parts) != 3 or parts[2] not in ("html", "json", "csv"):
            return self._notfound()
        scan_id, kind = parts[1], parts[2]
        try:
            f = self._scan_file(scan_id, kind)
        except ScanError as exc:
            return self._error(404, str(exc))
        ctype = {"json": "application/json", "csv": "text/csv"}.get(kind, "text/html")
        return self._send(200, f.read_bytes(), ctype + "; charset=utf-8", {
            "Content-Disposition": f'attachment; filename="{f.name}"'
        })

    def _serve_raw(self, path: str):
        parts = path.strip("/").split("/")      # raw / <id> / <filename>
        if len(parts) != 3:
            return self._notfound()
        scan_id, name = parts[1], parts[2]
        if not re.match(r"^[A-Za-z0-9._-]{1,64}$", scan_id):
            return self._error(400, "Invalid scan id.")
        # Reject any name containing separators — blocks ../ traversal.
        safe = Path(name).name
        if safe != name or safe in ("", ".", ".."):
            return self._error(400, "Invalid filename.")

        base = (OUTPUT_ROOT / scan_id / "raw").resolve()
        try:
            base.relative_to(OUTPUT_ROOT.resolve())
        except ValueError:
            return self._error(400, "Invalid path.")
        target = base / safe
        if not target.is_file():
            return self._error(404, "No such file.")
        return self._send(200, target.read_bytes(),
                          "application/octet-stream", {
                              "Content-Disposition": f'attachment; filename="{safe}"'
                          })

    # ── report page enhancements ────────────────────────────────────────
    def _inject_running_banner(self, body: bytes, rec: dict) -> bytes:
        banner = (
            b'<div style="position:sticky;top:0;z-index:999;background:#936000;color:#ffffff;'
            b'padding:.6rem 1rem;font-weight:600;text-align:center;font-family:sans-serif">'
            b'Scan still running &mdash; '
            b'<a style="color:#ffffff;text-decoration:underline" href="/scan/'
            + rec["id"].encode() + b'">back to live progress</a></div>'
        )
        html_text = body.decode("utf-8", "replace")
        if "<body>" in html_text:
            return html_text.replace("<body>", "<body>" + banner.decode(), 1).encode()
        return body

    def _inject_print_button(self, body: bytes, scan_id: str) -> bytes:
        bar = (
            '<style>@media print{.no-print{display:none!important}}</style>'
            '<div class="no-print" style="position:sticky;top:0;z-index:999;background:#ffffff;color:#172b45;'
            'padding:.7rem 1rem;font-family:system-ui,sans-serif;font-size:.9rem;'
            'border-bottom:1px solid #dce3ed;display:flex;gap:.7rem;align-items:center">'
            '<button onclick="window.print()" style="background:#2459d3;color:#ffffff;border:none;'
            'border-radius:6px;padding:.5rem 1rem;font-weight:600;cursor:pointer;font-size:.85rem">'
            'Save as PDF</button>'
            '<span style="color:#5b6b80">In the print dialog choose '
            '&ldquo;Save as PDF&rdquo; as the destination.</span>'
            '<a href="/report/' + html.escape(scan_id) + '" '
            'style="margin-left:auto;color:#2459d3">Back to interactive report</a></div>'
        )
        html_text = body.decode("utf-8", "replace")
        if "<body>" in html_text:
            return html_text.replace("<body>", "<body>" + bar, 1).encode()
        return body


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="webui.py",
        description="BASE-RECONNAISSANCE web interface (local only by default).",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address. Default 127.0.0.1 (localhost only).")
    parser.add_argument("--port", type=int, default=8000, help="Port. Default 8000.")
    args = parser.parse_args()

    # Route recon.py's prints away from the server console.
    sys.stdout = sys.stderr

    banner()
    missing = [t for t in ("nmap", "whatweb", "nikto", "smbclient", "gobuster", "searchsploit")
               if shutil.which(t) is None]
    if missing:
        print(f"{YELLOW}  Note: missing tools -> {', '.join(missing)}")
        print(f"{YELLOW}  Affected sections will report 'not installed'."
              f" Demo mode still works.{RESET}\n")

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"  {GREEN}Web UI:{RESET} {BOLD}http://{args.host}:{args.port}{RESET}\n")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"  {RED}⚠  Bound to {args.host} — anyone who can reach this port can")
        print(f"     start scans from your machine. Use a trusted network only.{RESET}\n")
    print(f"  {CYAN}Ctrl-C to stop{RESET}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Shutting down.{RESET}")
        srv.shutdown()


if __name__ == "__main__":
    main()
