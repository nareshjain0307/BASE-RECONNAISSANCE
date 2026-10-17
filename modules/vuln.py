"""
vuln.py — Searchsploit wrapper for BASE-RECONNAISSANCE.

Queries the local ExploitDB (via searchsploit) for each detected service version
and collects matching exploit IDs, titles, and file paths.
"""

import subprocess
import shutil
import logging
import json
import re
from pathlib import Path

logger = logging.getLogger("recon.vuln")


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# nmap appends the daemon name to the product ("Apache httpd", "Samba smbd",
# "OpenSSH sshd"). ExploitDB titles never contain those tokens, so keeping them
# guarantees a zero-hit query.
_DAEMON_TOKENS = {
    "httpd", "smbd", "sshd", "telnetd", "ftpd", "rlogind",
    "ftps", "http", "https",
}

# Products that reduce to a bare OS/vendor word. searchsploit's fuzzy matching
# turns these into thousands of unrelated hits ("Linux" -> 3000+ shellcodes), so
# a product-only query is only trusted when the product names real software.
_UNINFORMATIVE_PRODUCTS = {
    "linux", "unix", "bsd", "freebsd", "openbsd", "netbsd", "windows",
    "microsoft", "microsoft windows", "unknown", "apple", "macos", "osx",
}

# Cap the exploit list kept per port. A too-broad query can legitimately match
# thousands of unrelated entries, which would flood the report and inflate the
# headline counter; the true total is preserved in "exploit_count".
_MAX_EXPLOITS_PER_PORT = 100


def _normalise_product(product: str) -> str:
    """
    Clean an nmap product string into something ExploitDB titles resemble.

      "Apache httpd (Ubuntu)"  -> "Apache"
      "Samba smbd"             -> "Samba"
      "VMware ESXi httpd"      -> "VMware ESXi"
    """
    # Drop parenthesised qualifiers such as "(Ubuntu)" or "(x86_64)".
    cleaned = re.sub(r"\s*\([^)]+\)", " ", product)
    tokens = [
        t for t in cleaned.split()
        if t.lower().strip(",") not in _DAEMON_TOKENS
    ]
    return " ".join(tokens).strip() or product.strip()


def run_searchsploit(open_ports: list, output_dir: Path,
                     verbose: bool = False, demo: bool = False) -> dict:
    """
    Run searchsploit for each open port's service/version.

    Candidate titles are collected per product and classified against the
    detected version. Only supported exact versions and explicit ranges count
    as matches. Broad wildcards and ambiguous entries remain unverified leads.

    Args:
        open_ports:  List of parsed port dicts from scanner.
        output_dir:  Directory for raw output.
        verbose:     Log each query result.
        demo:        Return synthetic results without running searchsploit.

    Returns:
        dict: {results: [{port, service, query, queries_tried,
                          exploits: [{id, title, path, type}]}],
               total_exploits, error}
    """
    result = {"results": [], "total_exploits": 0, "total_unverified": 0, "error": None}

    if demo:
        logger.info("[DEMO] Returning synthetic searchsploit data.")
        result["results"] = [
            {
                "port": 21,
                "service": "ftp / vsftpd 2.3.4",
                "query": "vsftpd 2.3.4",
                "exploits": [
                    {
                        "id": "17491",
                        "title": "vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)",
                        "path": "/usr/share/exploitdb/exploits/unix/remote/17491.rb",
                        "type": "remote",
                    }
                ],
            },
            {
                "port": 22,
                "service": "ssh / OpenSSH 4.7p1",
                "query": "OpenSSH 4.7",
                "exploits": [
                    {
                        "id": "45233",
                        "title": "OpenSSH < 6.6 SFTP (x64) - Command Execution",
                        "path": "/usr/share/exploitdb/exploits/linux/remote/45233.py",
                        "type": "remote",
                    },
                    {
                        "id": "1902",
                        "title": "OpenSSH 2.x/3.x/4.x - Username Enumeration",
                        "path": "/usr/share/exploitdb/exploits/linux/remote/1902.pl",
                        "type": "remote",
                    },
                ],
            },
            {
                "port": 445,
                "service": "netbios-ssn / Samba 3.0.20",
                "query": "Samba 3.0.20",
                "exploits": [
                    {
                        "id": "16320",
                        "title": "Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)",
                        "path": "/usr/share/exploitdb/exploits/unix/remote/16320.rb",
                        "type": "remote",
                    }
                ],
            },
        ]
        for row in result["results"]:
            port = next((p for p in open_ports if p['port'] == row['port']), {})
            product = _normalise_product(port.get('product', ''))
            matched, unverified = [], []
            for entry in row['exploits']:
                verdict, reason = match_title(entry['title'], product, port.get('version', ''))
                item = {**entry, 'match_status': verdict, 'match_reason': reason}
                if verdict == 'matched':
                    matched.append(item)
                elif verdict == 'unverified':
                    unverified.append(item)
            row.update(exploits=matched, unverified=unverified,
                       unverified_count=len(unverified), exploit_count=len(matched),
                       confidence='version' if matched else 'none')
        result["total_exploits"] = sum(len(r['exploits']) for r in result['results'])
        result['total_unverified'] = sum(r['unverified_count'] for r in result['results'])
        return result

    if not _tool_available("searchsploit"):
        logger.warning("searchsploit not found — skipping vuln search.")
        result["error"] = "searchsploit not installed."
        return result

    cache = {}
    for port in open_ports:
        product = _normalise_product(port.get("product", ""))
        version = port.get("version", "")
        row = {"port": port.get("port"), "service": f"{product} {version}".strip(),
               "query": product, "queries_tried": [], "confidence": "none",
               "exploit_count": 0, "truncated": False, "exploits": [],
               "unverified": [], "unverified_count": 0, "rejected_count": 0, "detected_version": version, "fingerprint_source": port.get("fingerprint_source", "nmap")}
        # A product query collects range titles too. Every candidate is then
        # checked against the actual detected version, never a shortened query.
        if product and product.lower() not in _UNINFORMATIVE_PRODUCTS:
            row["queries_tried"] = [product]
            if product.lower() not in cache:
                try:
                    cache[product.lower()] = _run_single_query(product, output_dir, verbose)
                except Exception as exc:
                    row['error'] = str(exc)
                    result['error'] = 'Searchsploit failed for one or more products; see per-port results.'
                    result['results'].append(row)
                    continue
            for entry in cache[product.lower()]:
                verdict, reason = match_title(entry["title"], product, version)
                item = {**entry, "match_reason": reason, "match_status": verdict}
                if verdict == "matched":
                    row["exploits"].append(item)
                elif verdict == "unverified":
                    row["unverified"].append(item)
                else:
                    row["rejected_count"] += 1
        row["exploit_count"] = len(row["exploits"])
        row["confidence"] = "version" if row["exploits"] else "none"
        row["truncated"] = len(row["exploits"]) > _MAX_EXPLOITS_PER_PORT
        row["exploits"] = row["exploits"][:_MAX_EXPLOITS_PER_PORT]
        row["unverified_count"] = len(row["unverified"])
        row["unverified"] = row["unverified"][:_MAX_EXPLOITS_PER_PORT]
        result["results"].append(row)
    result["total_exploits"] = sum(r["exploit_count"] for r in result["results"])
    result["total_unverified"] = sum(r["unverified_count"] for r in result["results"])
    return result


def _run_single_query(query: str, output_dir: Path, verbose: bool) -> list:
    """
    Execute a single searchsploit query and parse JSON output.

    Returns:
        List of exploit dicts: {id, title, path, type}
    """
    cmd = ["searchsploit", "--json", "--disable-colour", "--title", *query.split()]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"searchsploit exited {proc.returncode}")
        raw_text = proc.stdout.strip()
        if not raw_text:
            raise ValueError("Searchsploit returned no JSON output")

        # Save raw output
        safe_name = re.sub(r"[^\w\s-]", "", query).strip().replace(" ", "_")
        raw_file = output_dir / f"searchsploit_{safe_name}.json"
        raw_file.write_text(raw_text, encoding="utf-8")

        if verbose:
            logger.debug("[searchsploit] %s", raw_text[:1000])

        return _parse_searchsploit_json(raw_text, query)

    except subprocess.TimeoutExpired:
        logger.warning("searchsploit timed out for query: %s", query)
        raise RuntimeError(f"searchsploit timed out: {query}")
    except Exception as exc:
        logger.error("searchsploit error: %s", exc)
        raise


def _parse_searchsploit_json(raw: str, query: str) -> list:
    """
    Parse searchsploit --json output and filter out unrelated products.

    Expected structure:
        {"RESULTS_EXPLOIT": [{EDB-ID, Title, Path, Type, ...}], ...}
    """
    exploits = []
    if not raw:
        return exploits

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: sometimes searchsploit prefixes output with color codes
        cleaned = re.sub(r"\x1b\[[0-9;]*m", "", raw)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            raise ValueError("Invalid searchsploit JSON output")

    # Filter out common cross-pollination terms in ExploitDB that ruin broad searches
    toxic_keywords = {
        "apache": ["tomcat", "openmeetings", "cxf", "xerces", "shiro", "struts", "shoutbox", "activemq", "camel", "couchdb", "solr"],
        "microsoft": ["windows", "office", "exchange", "sql", "iis", "sharepoint"],
        "linux": ["kernel"],
    }

    query_lower = query.lower()
    forbidden = []
    for base, toxics in toxic_keywords.items():
        # If the base word is in the query, exclude any of its sub-projects that ARE NOT in the query.
        if base in query_lower:
            for toxic in toxics:
                if toxic not in query_lower:
                    forbidden.append(toxic)

    for entry in data.get("RESULTS_EXPLOIT", []):
        title = entry.get("Title", "")
        title_lower = title.lower()

        if any(f in title_lower for f in forbidden):
            continue

        exploits.append({
            "id":    entry.get("EDB-ID", ""),
            "title": title,
            "path":  entry.get("Path", ""),
            "type":  entry.get("Type", ""),
        })

    return exploits


_VERSION = r"\d+(?:\.(?:\d+|[xX*]))*(?:p\d+|rc\d+|beta\d*|alpha\d*)?"

def _version_key(value):
    m = re.fullmatch(r"(\d+(?:\.\d+)*)(p\d+|rc\d+|beta\d*|alpha\d*)?", value, re.I)
    if not m:
        return None
    nums = tuple(int(x) for x in m[1].split('.'))
    nums = nums + (0,) * max(0, 6 - len(nums))
    suffix = (m[2] or '').lower()
    rank = -3 if suffix.startswith('alpha') else -2 if suffix.startswith('beta') else -1 if suffix.startswith('rc') else 1 if suffix.startswith('p') else 0
    number = re.search(r"\d+", suffix)
    return nums, rank, int(number[0]) if number else 0


def match_title(title, product, detected):
    """Conservative title applicability, not proof that a host is vulnerable.

    Unknown syntax, missing versions and ambiguous banners are retained as
    unverified leads and never contribute to the matched count.
    """
    header = re.split(r'\s+-\s+(?!\d)', title, maxsplit=1)[0].strip()
    identity = re.match(r"^" + re.escape(product) + r"(?=\s|/|$)", header, re.I)
    if not identity:
        return "rejected", "Different product"
    spec = header[identity.end():].strip()
    # Product-family ambiguity (Apache Tomcat versus Apache HTTP Server).
    if spec and not re.match(r"[\d<>=v]", spec, re.I):
        return "unverified", "Product or version expression is ambiguous"
    m = re.match(r"^(" + _VERSION + r")(?=$|[\s-])", detected or '', re.I)
    if not m or re.search(r"\s(?:-|<|to)\s|[xX*]", detected or ''):
        return "unverified", "Detected version is missing or ambiguous"
    actual = _version_key(m[1])
    if actual is None:
        return "unverified", "Detected version is incomplete"
    spec = re.sub(r"^v(?=\d)", '', spec, flags=re.I)
    # Ignore platform qualifiers following a clear version expression.
    spec = re.split(r"\s+(?:\(|SFTP\b|SSH\b|HTTP\b)", spec, maxsplit=1, flags=re.I)[0].strip()
    interval = re.fullmatch(r"(" + _VERSION + r")\s*(<=|<|to|-)\s*(" + _VERSION + r")", spec, re.I)
    if interval:
        lo, op, hi = interval.groups()
        lower, upper = _version_key(lo), _version_key(hi)
        if lower is None or upper is None:
            return "unverified", "Ambiguous range boundary"
        ok = lower <= actual and (actual < upper if op == '<' else actual <= upper)
        return ("matched" if ok else "rejected"), f"Affected range: {spec}"
    bound = re.fullmatch(r"(<=|>=|<|>)\s*(" + _VERSION + r")", spec, re.I)
    if bound:
        op, v = bound.groups(); key = _version_key(v)
        if key is None:
            return "unverified", "Ambiguous range boundary"
        ok = {'<': actual < key, '<=': actual <= key, '>': actual > key, '>=': actual >= key}[op]
        return ("matched" if ok else "rejected"), f"Affected bound: {spec}"
    versions = re.split(r"\s*[/,]\s*", spec)
    if not spec or not all(re.fullmatch(_VERSION, v, re.I) for v in versions):
        return "unverified", "No supported affected-version expression"
    unknown = False
    for v in versions:
        if re.search(r"[xX*]", v):
            prefix = re.split(r"[xX*]", v, maxsplit=1)[0].rstrip('.')
            if m[1] == prefix or m[1].startswith(prefix + '.'):
                unknown = True
                continue
        elif _version_key(v) == actual:
            return "matched", f"Exact affected version: {v}"
        elif len(v.split('.')) < len(m[1].split('.')) and m[1].startswith(v + '.'):
            unknown = True
    return ("unverified", "Title specifies a broad family or omits the patch version") if unknown else ("rejected", "Different affected version")
