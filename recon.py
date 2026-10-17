#!/usr/bin/env python3
"""
recon.py — BASE-RECONNAISSANCE
============================
Automated initial reconnaissance for authorized penetration testing.

Usage:
  python recon.py --target 192.168.1.10 --profile quick
  python recon.py --target 192.168.1.10 --profile full --parallel 4 --output my_scan
  python recon.py --demo
  python recon.py --resume output/last_scan/

Author:  BASE-RECONNAISSANCE
License: MIT (for authorized testing only)
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

# ── Optional tqdm (graceful fallback) ────────────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ── Color codes (ANSI) ────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"

# ── Local modules ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from modules.scanner import run_nmap
from modules.web     import run_whatweb, run_nikto
from modules.smb     import run_smbclient, run_enum4linux
from modules.vuln    import run_searchsploit
from modules.pipeline import Tool, execute
from modules.content import run_gobuster
from modules.web import _is_http_port, assessment_ports
from modules.report  import generate_html, generate_json, generate_csv


# ─────────────────────────── Logging setup ───────────────────────────────────

def setup_logging(verbose: bool, debug: bool, log_file: Path) -> None:
    """Configure root logger with colored console output and file handler."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)

    fmt_file    = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
    fmt_console = "%(message)s"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # capture everything at root

    # File handler — always DEBUG
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt_file))
    root.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(fmt_console))
    root.addHandler(ch)


logger = logging.getLogger("recon")


# ─────────────────────────── CLI ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.py",
        description=(
            "BASE-RECONNAISSANCE — automated initial reconnaissance tool.\n"
            "For authorized penetration testing only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py --target 192.168.1.10 --profile quick
  python recon.py --target 192.168.1.10 --profile full --parallel 6 --output pentest_acme
  python recon.py --demo
  python recon.py --resume output/20240101_120000/
        """,
    )

    # Target / scan options
    tgt = p.add_argument_group("Target")
    tgt.add_argument("--target", "-t", metavar="IP/DOMAIN",
                     help="Target IP address or domain name.")
    tgt.add_argument("--profile", choices=["quick", "full"], default="quick",
                     help="Scan profile: 'quick' (top 100 ports) or 'full' (1–65535). Default: quick.")

    # Execution options
    exe = p.add_argument_group("Execution")
    exe.add_argument("--parallel", type=int, default=4, metavar="N",
                     help="Thread pool size for parallel scans. Default: 4.")
    exe.add_argument("--output", "-o", metavar="NAME",
                     help="Output directory name (under output/). Auto-generated if omitted.")

    exe.add_argument("--tools", nargs="+", choices=OPTIONAL_MODULES, help="Tools to run (default: all).")
    exe.add_argument("--wordlist", help="Gobuster wordlist path.")

    # Modes
    mode = p.add_argument_group("Special modes")
    mode.add_argument("--demo", action="store_true",
                      help="Run with embedded demo data (no live target needed).")
    mode.add_argument("--resume", metavar="DIR",
                      help="Resume a previous scan from its output directory.")

    # Verbosity
    verb = p.add_argument_group("Output")
    verb.add_argument("--verbose", "-v", action="store_true",
                      help="Show informational messages.")
    verb.add_argument("--debug",   "-d", action="store_true",
                      help="Show debug messages (very noisy).")

    return p


# ─────────────────────────── Directory helpers ───────────────────────────────

def make_output_dirs(base: str, timestamp: str) -> tuple:
    """
    Create and return (scan_dir, raw_dir).
    scan_dir: output/<name>/
    raw_dir:  output/<name>/raw/
    """
    scan_dir = Path("output") / (base or timestamp)
    raw_dir  = scan_dir / "raw"
    scan_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir, raw_dir


def save_state(state: dict, scan_dir: Path) -> None:
    """Persist scan state to disk for --resume."""
    state_file = scan_dir / "state.json"
    temporary = state_file.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    temporary.replace(state_file)


def load_state(resume_dir: str) -> tuple:
    """Load saved state from a previous run. Returns (state, scan_dir)."""
    scan_dir   = Path(resume_dir)
    state_file = scan_dir / "state.json"
    if not state_file.exists():
        raise FileNotFoundError(f"No state.json found in {resume_dir}. Cannot resume.")
    state = json.loads(state_file.read_text(encoding="utf-8"))
    return state, scan_dir


# ─────────────────────────── Progress helpers ────────────────────────────────

class ProgressTracker:
    """Simple progress tracker; uses tqdm if available, else plain print."""

    def __init__(self, total: int, desc: str = "Scanning"):
        self._total   = total
        self._current = 0
        self._bar     = None
        if HAS_TQDM:
            self._bar = tqdm(total=total, desc=desc, unit="task",
                             bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                             colour="cyan")

    def advance(self, label: str = "") -> None:
        self._current += 1
        if self._bar:
            self._bar.set_postfix_str(label, refresh=True)
            self._bar.update(1)
        else:
            pct = int(self._current / self._total * 100)
            print(f"  [{pct:3d}%] {label}", flush=True)

    def close(self) -> None:
        if self._bar:
            self._bar.close()


# ─────────────────────────── Print helpers ───────────────────────────────────

def banner() -> None:
    print(f"""
{CYAN}{BOLD}  ╔════════════════════════════════════════════════════════════╗
  ║                    BASE-RECONNAISSANCE                     ║
  ╚════════════════════════════════════════════════════════════╝{RESET}
{YELLOW}  Automated Initial Reconnaissance — For Authorized Use Only{RESET}
""")


def print_section(title: str, icon: str = "►") -> None:
    width = 70
    line  = "─" * width
    print(f"\n{CYAN}{line}{RESET}")
    print(f"{CYAN}{icon} {BOLD}{title}{RESET}")
    print(f"{CYAN}{line}{RESET}")


def print_summary(scan_data: dict, scan_dir: Path, elapsed: float) -> None:
    """Print a colored summary table to the console."""
    nmap   = scan_data.get("nmap", {})
    vuln   = scan_data.get("searchsploit", {})
    ports  = nmap.get("open_ports", [])
    total_exploits = vuln.get("total_exploits", 0)

    failed = nmap.get('error')
    print_section("SCAN INCOMPLETE" if failed else "SCAN SUMMARY", "⚠" if failed else "✅")
    if failed:
        print(f"  Discovery failed: {failed}")
    print(f"  {BOLD}Target:{RESET}         {CYAN}{scan_data.get('target')}{RESET}")
    print(f"  {BOLD}Hostname:{RESET}       {scan_data.get('nmap', {}).get('hostname') or 'N/A'}")
    print(f"  {BOLD}OS Guess:{RESET}       {scan_data.get('nmap', {}).get('os_guess') or 'N/A'}")
    print(f"  {BOLD}Open Ports:{RESET}     {GREEN}{len(ports)}{RESET}")
    print(f"  {BOLD}Version Matches:{RESET} {RED if total_exploits else GREEN}{total_exploits}{RESET}")
    print(f"  {BOLD}Elapsed:{RESET}        {elapsed:.1f}s")
    print(f"  {BOLD}Output Dir:{RESET}     {scan_dir}")
    print()

    if ports:
        print(f"  {BOLD}{'PORT':<12}{'SERVICE':<18}{'PRODUCT':<28}{'VERSION'}{RESET}")
        for p in ports:
            port_str = f"{p['port']}/{p['protocol']}"
            matches = [
                r for r in vuln.get("results", []) if r.get("port") == p["port"]
            ]
            indicator = ""
            for r in matches:
                count = r.get("exploit_count", len(r.get("exploits", [])))
                if not count:
                    continue
                colour = RED if r.get("confidence") == "version" else YELLOW
                noun = "exploit" if count == 1 else "exploits"
                if r.get("truncated"):
                    shown = len(r.get("exploits", []))
                    indicator += (f" {colour}[{count} {noun}, top {shown}]"
                                  f"{RESET}")
                else:
                    indicator += f" {colour}[{count} {noun}]{RESET}"
            print(f"  {YELLOW}{port_str:<12}{RESET}{p['service']:<18}{p['product']:<28}"
                  f"{GRAY}{p['version']}{RESET}{indicator}")

    print()
    print(f"  {BOLD}Reports:{RESET}")
    for fname in sorted(scan_dir.glob("*")):
        if fname.suffix in (".html", ".json", ".csv"):
            print(f"    📄 {fname}")


# ─────────────────────────── Scan orchestrator ───────────────────────────────

# Optional modules that can be selected or deselected by the caller. "nmap" is
# not listed because it is the gate every other module depends on.
OPTIONAL_MODULES = ("whatweb", "nikto", "smbclient", "enum4linux", "gobuster", "searchsploit")


def run_scan(target: str, profile: str, scan_dir: Path, raw_dir: Path,
             parallel: int, verbose: bool, demo: bool,
             state: dict, selected: Optional[Iterable[str]] = None,
             on_event=None, quiet: bool = False) -> dict:
    """
    Orchestrate all scan modules.

    Runs discovery, enumeration, and assessment in dependency order.
    Applicable tools within each stage run concurrently. Failed outcomes retry
    on resume; refreshed stages invalidate downstream checkpoints.

    Args:
        state:      Optionally pre-filled dict from --resume (will skip
                    completed steps).
        selected:   Optional iterable of optional module names to run. None
                    means run all of them. Deselected modules are recorded in
                    state with a "not selected" error so they still appear in
                    the report.
        on_event:   Optional callable receiving a dict per progress event, used
                    by the web UI. Events: {"type": "phase"|"task"|"done", ...}
        quiet:      Suppress console output (used by the web UI).

    Returns:
        Fully populated scan_data dict.
    """
    def emit(**event):
        if not quiet:
            if event.get('type') == 'phase':
                print_section(event.get('label', event.get('name', '')), '►')
            elif event.get('type') == 'task' and event.get('status') != 'running':
                name = event['name']
                detail = _module_detail(name, state.get(name, {})) or event.get('detail', '')
                print(f"  [{event.get('status')}] {name}: {detail}", flush=True)
        if on_event is not None:
            try:
                on_event(event)
            except Exception:
                pass  # a broken UI callback must never abort a scan

    if parallel < 1:
        raise ValueError("parallel must be at least 1")
    wanted = set(OPTIONAL_MODULES if selected is None else selected)
    unknown = wanted - set(OPTIONAL_MODULES)
    if unknown:
        raise ValueError(f"Unknown tools: {', '.join(sorted(unknown))}")
    ports = lambda s: s.get('nmap', {}).get('open_ports', [])
    http = lambda s: any(_is_http_port(p) for p in ports(s))
    smb = lambda s: any(p['port'] in {139, 445} for p in ports(s))
    def wrapper(fn):
        return lambda s: fn(target, ports(s), raw_dir, verbose=verbose, demo=demo)
    tools = [
        Tool('nmap', 'discovery', lambda s: True,
             lambda s: run_nmap(target, profile, raw_dir, verbose=verbose, demo=demo)),
        Tool('whatweb', 'fingerprinting', http, wrapper(run_whatweb)),
        Tool('smbclient', 'enumeration', smb, wrapper(run_smbclient)),
        Tool('enum4linux', 'enumeration', smb, wrapper(run_enum4linux)),
        Tool('gobuster', 'enumeration', http,
             lambda s: run_gobuster(target, ports(s), raw_dir, verbose=verbose,
                                    demo=demo, wordlist=state.get('meta', {}).get('wordlist'))),
        Tool('nikto', 'assessment', http, wrapper(run_nikto)),
        Tool('searchsploit', 'assessment', lambda s: bool(ports(s)),
             lambda s: run_searchsploit(assessment_ports(s), raw_dir, verbose=verbose, demo=demo)),
    ]
    # Revalidate old Searchsploit checkpoints with the new matching policy.
    if state.get('meta', {}).get('matching_policy') != 3:
        state.pop('searchsploit', None)
    state.setdefault('meta', {})['matching_policy'] = 3
    result = execute(tools, state, wanted | {'nmap'}, parallel,
                     lambda s: save_state(s, scan_dir), emit)
    emit(type='done', name='scan')
    return result


def _module_detail(name: str, result: dict) -> str:
    """One-line human summary of a module result, for the UI."""
    if not isinstance(result, dict):
        return ""
    if result.get("error"):
        return str(result["error"])
    if name == "whatweb":
        n = sum(len(f.get("technologies", [])) for f in result.get("findings", []))
        return f"{n} technologies across {len(result.get('urls_scanned', []))} URL(s)"
    if name == "nikto":
        n = sum(len(f.get("vulnerabilities", [])) for f in result.get("findings", []))
        return f"{n} findings on {len(result.get('scanned', []))} port(s)"
    if name == "smbclient":
        return f"{len(result.get('shares', []))} shares"
    if name == "enum4linux":
        return f"{len(result.get('users', []))} users, {len(result.get('groups', []))} groups"
    if name == "searchsploit":
        return f"{result.get('total_exploits', 0)} exploit matches"
    return ""


# ─────────────────────────── Entry point ─────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Validate: must have --target or --demo or --resume
    if not args.target and not args.demo and not args.resume:
        parser.error("Provide --target <IP/domain>, --demo, or --resume <dir>.")

    if args.parallel < 1:
        parser.error("--parallel must be at least 1")
    banner()

    # ── Timestamps and paths ──────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target    = args.target or "demo-target"

    # ── Resume mode ───────────────────────────────────────────────────────
    if args.resume:
        print(f"{YELLOW}[RESUME] Loading state from {args.resume}{RESET}")
        try:
            state, scan_dir = load_state(args.resume)
        except FileNotFoundError as e:
            print(f"{RED}ERROR: {e}{RESET}")
            sys.exit(1)
        raw_dir = scan_dir / "raw"
        raw_dir.mkdir(exist_ok=True)
        target  = state.get("target", target)
        profile = state.get("meta", {}).get("profile", args.profile)
        print(f"{GREEN}[RESUME] Resuming scan of {target} (profile: {profile}){RESET}")
    else:
        state    = {}
        scan_dir, raw_dir = make_output_dirs(args.output or timestamp, timestamp)
        profile  = args.profile

    if args.resume:
        args.demo = bool(state.get('meta', {}).get('demo', args.demo))

    # ── Logging ───────────────────────────────────────────────────────────
    log_file = scan_dir / "recon.log"
    setup_logging(args.verbose, args.debug, log_file)
    logger.info("BASE-RECONNAISSANCE starting. Target=%s Profile=%s Demo=%s",
                target, profile, args.demo)

    # ── Metadata ──────────────────────────────────────────────────────────
    if "meta" not in state:
        state["meta"] = {
            "profile":   profile,
            "timestamp": timestamp,
            "demo":      args.demo,
            "parallel":  args.parallel,
        }
    state["meta"]["wordlist"] = args.wordlist or state["meta"].get("wordlist")
    if args.tools is not None:
        state["meta"]["selected"] = args.tools
    state["target"]    = target
    state["timestamp"] = timestamp

    print(f"\n  {BOLD}Target  :{RESET} {CYAN}{target}{RESET}")
    print(f"  {BOLD}Profile :{RESET} {profile}")
    print(f"  {BOLD}Workers :{RESET} {args.parallel}")
    print(f"  {BOLD}Output  :{RESET} {scan_dir}")
    print(f"  {BOLD}Demo    :{RESET} {args.demo}")
    if not args.demo:
        print(f"\n  {YELLOW}⚠  Only run against systems you are authorised to test.{RESET}")
    print()

    # ── Run scan ──────────────────────────────────────────────────────────
    t_start   = time.monotonic()
    scan_data = run_scan(
        target, profile, scan_dir, raw_dir,
        parallel=args.parallel,
        verbose=args.verbose,
        demo=args.demo,
        state=state,
        selected=args.tools if args.tools is not None else (
            state.get("meta", {}).get("selected")
            if isinstance(state.get("meta", {}).get("selected"), list) else None
        ),
    )
    elapsed = time.monotonic() - t_start

    # ── Generate reports ──────────────────────────────────────────────────
    print_section("Phase 5 — Report Generation", "📝")

    html_path = scan_dir / f"report_{timestamp}.html"
    json_path = scan_dir / f"report_{timestamp}.json"
    csv_path  = scan_dir / f"report_{timestamp}.csv"

    generate_html(scan_data, html_path, raw_dir)
    generate_json(scan_data, json_path)
    generate_csv(scan_data, csv_path)

    print(f"  {GREEN}✓{RESET} HTML : {html_path}")
    print(f"  {GREEN}✓{RESET} JSON : {json_path}")
    print(f"  {GREEN}✓{RESET} CSV  : {csv_path}")

    # ── Summary ───────────────────────────────────────────────────────────
    print_summary(scan_data, scan_dir, elapsed)
    logger.info("Scan finished in %.1fs. Reports in %s", elapsed, scan_dir)
    if scan_data.get('nmap', {}).get('error'):
        sys.exit(1)
    if any(scan_data.get(name, {}).get('status') == 'error' for name in OPTIONAL_MODULES):
        sys.exit(2)


if __name__ == "__main__":
    main()
