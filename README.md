# BASE-RECONNAISSANCE 🛡

**Automated initial reconnaissance for authorized penetration testing on Kali Linux.**

> ⚠️ **Legal notice**: This tool is intended exclusively for authorized security assessments.
> Unauthorized scanning of systems you do not own or have explicit written permission to test
> is illegal. The author accepts no liability for misuse.

---

## Features

| Feature | Details |
|---|---|
| **Port scanning** | nmap with `-Pn` flag and XML parsing (quick: top 100 / full: 1–65535) |
| **Web tech detection** | WhatWeb against all open HTTP/HTTPS ports (detects by service name + port) |
| **Content discovery** | Gobuster directory/file enumeration with a configurable wordlist |
| **Web vuln scan** | Nikto against all open HTTP/HTTPS ports |
| **SMB enumeration** | smbclient (share list) + enum4linux / enum4linux-ng |
| **Exploit search** | Searchsploit product candidates filtered against detected versions; ambiguous leads kept separately |
| **Parallel execution** | Ordered discovery → fingerprinting → enumeration → assessment stages; parallel workers within each stage |
| **Service-aware detection** | Tools are dispatched based on nmap service names, not just port numbers |
| **Progress** | Stage and per-tool outcomes (CLI) / live event polling (Web UI) |
| **Resume** | Atomic checkpoints; successful tasks reused, failures retried, refreshed stages invalidate downstream results |
| **Demo mode** | `--demo` uses embedded Metasploitable 2 data — no live target needed |
| **Reports** | HTML (collapsible, light theme), JSON, CSV |
| **Raw output** | All tool outputs saved in `output/<run>/raw/` |
| **Web UI** | Browser-based interface — run scans, watch live progress, export reports |

---

## Installation

### Prerequisites (Kali Linux — most are pre-installed)

```bash
sudo apt update
sudo apt install -y nmap whatweb nikto smbclient enum4linux exploitdb gobuster dirb
```

> **enum4linux-ng** (preferred over enum4linux):
> ```bash
> sudo apt install -y enum4linux-ng
> ```

### Python setup

```bash
# Clone the project
git clone https://github.com/nareshjain0307/BASE-RECONNAISSANCE.git
cd BASE-RECONNAISSANCE

# Install Python deps (only tqdm is required beyond stdlib)
pip install -r requirements.txt
```

---

## Usage

### CLI — Quick start

```bash
# Fast scan — top 100 ports
python recon.py --target 192.168.1.10

# Full scan — all 65535 ports, 6 parallel workers
python recon.py --target 192.168.1.10 --profile full --parallel 6

# Named output directory
python recon.py --target 192.168.1.10 --output acme_pentest

# Verbose (see info messages)
python recon.py --target 192.168.1.10 --verbose

# Debug (very noisy — shows every subprocess line)
python recon.py --target 192.168.1.10 --debug

# Demo mode — no live target needed, uses embedded Metasploitable 2 data
python recon.py --demo

# Run only selected optional tools (Nmap always runs)
python recon.py --target 192.168.1.10 --tools whatweb gobuster searchsploit --wordlist /usr/share/wordlists/dirb/common.txt

# Resume an interrupted scan
python recon.py --resume output/20240610_143000/
```

### CLI options

```
usage: recon.py [-h] [--target IP/DOMAIN] [--profile {quick,full}]
                [--parallel N] [--output NAME]
                [--demo] [--resume DIR]
                [--verbose] [--debug]

Target:
  --target, -t    Target IP address or domain name
  --profile       quick (top 100 ports) | full (all 65535)  [default: quick]

Execution:
  --parallel N    Thread pool size  [default: 4]
  --output NAME   Output directory name (under output/)
  --tools NAMES   Optional tool names to run (default: all)
  --wordlist PATH Gobuster wordlist (defaults to installed dirb/SecLists common.txt)

Special modes:
  --demo          Run with embedded demo data (Metasploitable 2)
  --resume DIR    Resume from a previous scan directory

Output:
  --verbose, -v   Show informational messages
  --debug,   -d   Show debug messages
```

---

## Web UI

A browser-based interface for running scans, watching live progress, and exporting
reports. Built entirely with the Python standard library — no extra dependencies needed.

### Starting the Web UI

```bash
# Default — localhost only on port 8000
python webui.py

# Custom port
python webui.py --port 9000

# Expose on LAN (⚠ read the security warning below)
python webui.py --host 0.0.0.0
```

Then open **http://127.0.0.1:8000** in your browser.

### What you can do

- **Enter a target** — IP address, hostname, or CIDR range
  - URL formats like `http://192.168.1.10/path` are automatically cleaned to just the host
- **Pick a scan profile** — quick (top 100 ports) or full (all 65535 ports)
- **Set parallel workers** — 1 to 16 concurrent tool threads
- **Select individual tools** — or run all at once:
  - ✅ **nmap** — always runs first (all other tools depend on its port list)
  - ☑ **WhatWeb** — web technology fingerprinting
  - ☑ **Gobuster** — directory/file enumeration
  - ☑ **Nikto** — web vulnerability scanning
  - ☑ **smbclient** — SMB share enumeration
  - ☑ **enum4linux** — deep SMB/RPC user, group, and policy enumeration
  - ☑ **Searchsploit** — match detected services against ExploitDB
- **Demo mode** — tick the checkbox to scan embedded Metasploitable 2 data without a live target
- **Watch live progress** — per-tool status updates in real time while the scan runs
- **View the report** — full HTML report with collapsible sections, right in the browser
- **Export results** — download as PDF (via browser print), JSON, CSV, or standalone HTML
- **Download raw output** — every tool's raw output file (nmap XML, nikto txt, etc.)
- **Previous scans** — browse and revisit reports from past scans (persisted to disk)

### Web UI options

```
usage: webui.py [-h] [--host HOST] [--port PORT]

  --host HOST     Bind address  [default: 127.0.0.1]
  --port PORT     Port number   [default: 8000]
```

> **⚠ Security warning:** The server binds to `127.0.0.1` by default. Using
> `--host 0.0.0.0` exposes the scanner to your entire network — anyone who can
> reach the port can start scans from your machine. Only use this on a trusted,
> isolated network.

---

## How tool dispatch works

BASE-RECONNAISSANCE uses an ordered pipeline:

1. **Discovery:** Nmap detects open TCP ports, products, versions and TLS tunnels.
2. **Fingerprinting:** WhatWeb identifies web technologies and versions.
3. **Enumeration:** Gobuster, smbclient and enum4linux run concurrently when their services are present.
4. **Assessment:** Nikto and Searchsploit run after enumeration; missing Nmap server versions can use unambiguous WhatWeb fingerprints, with the source recorded.
5. **Reporting:** HTML, JSON and CSV capture findings and per-tool outcomes.

All tools run by default in the CLI. `--tools` selects a subset; Nmap remains mandatory.
In the Web UI, clearing optional tools runs Nmap alone. Missing tools, timeouts and
process failures appear as errors, rather than clean results. CLI exit codes are 0 for success, 1 for failed discovery, and 2 for secondary-tool errors. A discovery failure
blocks later stages. `--parallel` controls concurrent tools; Gobuster uses four HTTP
workers internally. Each endpoint has a bounded tool timeout; Nmap has a 30-minute limit.

Gobuster uses `--wordlist` when supplied, otherwise checks the installed dirb or
SecLists common wordlist. The Web UI accepts the corresponding server-side path.
HTTPS on nonstandard ports uses Nmap's service name or TLS tunnel metadata.
Gobuster retries certificate-verification failures without TLS validation and wildcard
precheck failures with the observed response length excluded. These recovery options
are recorded as warnings in JSON and HTML; excluding a length can omit valid paths
of that size. Retries are limited to three attempts per endpoint.

### Searchsploit matching policy

Searchsploit's default fuzzy version search can return entries for other releases.
The tool now queries product titles and independently checks each candidate against
the actual detected version. It supports exact versions, explicit comparison bounds,
numeric ranges and explicit version lists. OpenSSH `p` revisions and
prerelease boundaries are preserved. Apache 2.4.49 entries are excluded for Apache
2.4.68; an explicit range containing 2.4.68 can still match.

Unknown versions, broad `x` wildcards, titles without versions, abbreviated patch versions and unsupported
expressions are **unverified leads**, excluded from the matched count. JSON keeps
match reasons, rejected counts and unverified totals. Up to 100 entries per category
and port are retained in the report. The headline counts entries per port, so the
same entry on two ports is counted twice.

A title/version match is a candidate for manual assessment, not a confirmed
vulnerability: distribution backports, configuration and exploit prerequisites are
not inferred. Complex title syntax can remain unverified. No exploits are executed.

Resume reuses successful checkpoints and retries failed or newly selected tools.
Rerunning an upstream stage invalidates downstream results. Older Searchsploit
checkpoints are recomputed under this policy; existing exported reports are unchanged
until the scan is resumed and new reports are generated.

---

## Output structure

```
output/
└── 20240610_143022/           # timestamped run directory
    ├── raw/
    │   ├── nmap.xml
    │   ├── nmap_stdout.txt
    │   ├── whatweb_80.json
    │   ├── nikto_80.txt
    │   ├── smbclient.txt
    │   ├── enum4linux.txt
    │   └── searchsploit_*.json
    ├── report_20240610_143022.html    ← open in browser
    ├── report_20240610_143022.json    ← machine-parseable
    ├── report_20240610_143022.csv     ← spreadsheet summary
    ├── state.json                     ← resume checkpoint
    └── recon.log                      ← full debug log
```

---

## Project structure

```
BASE-RECONNAISSANCE/
├── recon.py              # Main entry point — CLI, orchestration, reporting
├── webui.py              # Local web interface (stdlib HTTP server)
├── modules/
│   ├── __init__.py
│   ├── scanner.py        # nmap wrapper + XML parser
│   ├── web.py            # WhatWeb + Nikto wrappers
│   ├── smb.py            # smbclient + enum4linux wrappers
│   ├── vuln.py           # Searchsploit candidates and affected-version filtering
│   ├── content.py        # Gobuster content discovery
│   ├── pipeline.py       # Stage execution and checkpoint reuse
│   └── report.py         # HTML / JSON / CSV report generation
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Demo mode

Run without any live target:

```bash
# CLI
python recon.py --demo

# Web UI — tick the "Demo mode" checkbox in the browser
python webui.py
```

This uses a pre-baked Metasploitable 2 nmap XML and synthetic tool outputs to
generate full reports immediately — useful for testing the tool itself or
demonstrating it in a classroom setting.

---

## Extending the tool

Each module follows the same contract:

```python
def run_<module>(target, open_ports, output_dir, verbose, demo) -> dict:
    """Returns structured data dict. Never raises — returns error key on failure."""
```

To add another scanner, implement its wrapper in `modules/`, then register a
`Tool(name, stage, applicable, run)` in `recon.py`. Add the name to
`OPTIONAL_MODULES`, the Web UI tool choices/binary map, and report generation.
The pipeline handles parallel execution, checkpoint writes and failure outcomes.

### Live scan results

The scan page refreshes every second. Each tool’s findings appear as soon as that
tool finishes, while the remaining tools continue. All tools show their current
status: Waiting, Running, Completed, Skipped or Failed. Failed tools can display
partial findings; report downloads become available when the pipeline ends.

### Local verification

```bash
python -m unittest discover -s tests -v
python recon.py --demo
```

The tests cover version filtering, stage dependencies, retries, failure blocking,
Gobuster invocation, TLS endpoint construction, report output and the Web UI demo job.
They use fixtures and mocks; they do not scan live targets.

---

## Tested on

- Kali Linux 2024.x (rolling)
- Python 3.11+
- nmap 7.94+, nikto 2.1.6, whatweb 0.5.5, smbclient 4.x, enum4linux 0.9.x

---

## License

MIT — see individual tool licenses for nmap, nikto, etc.
