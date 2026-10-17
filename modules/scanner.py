"""
scanner.py — Nmap wrapper for BASE-RECONNAISSANCE.

Runs nmap, parses XML output, and returns structured scan results.
Supports 'quick' (top 100 ports) and 'full' (1–65535) profiles.
"""

import subprocess
import shutil
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

logger = logging.getLogger("recon.scanner")

# ─────────────────────────── demo XML ────────────────────────────────────────
DEMO_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -oX - 192.168.1.10" start="1700000000"
         version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="100" services="top100"/>
<host starttime="1700000000" endtime="1700000060">
  <status state="up" reason="echo-reply"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <hostnames><hostname name="metasploitable" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="21">
      <state state="open" reason="syn-ack"/>
      <service name="ftp" product="vsftpd" version="2.3.4" method="probed"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1" method="probed"/>
    </port>
    <port protocol="tcp" portid="23">
      <state state="open" reason="syn-ack"/>
      <service name="telnet" product="Linux telnetd" method="probed"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.2.8" method="probed"/>
    </port>
    <port protocol="tcp" portid="139">
      <state state="open" reason="syn-ack"/>
      <service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X" method="probed"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="ssl/http" product="Apache httpd" version="2.2.8" method="probed"/>
    </port>
    <port protocol="tcp" portid="445">
      <state state="open" reason="syn-ack"/>
      <service name="netbios-ssn" product="Samba smbd" version="3.0.20-Debian" method="probed"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="open" reason="syn-ack"/>
      <service name="mysql" product="MySQL" version="5.0.51a-3ubuntu5" method="probed"/>
    </port>
    <port protocol="tcp" portid="5432">
      <state state="open" reason="syn-ack"/>
      <service name="postgresql" product="PostgreSQL DB" version="8.3.0 - 8.3.7" method="probed"/>
    </port>
    <port protocol="tcp" portid="8180">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache Tomcat/Coyote JSP engine" version="1.1" method="probed"/>
    </port>
  </ports>
  <os><osmatch name="Linux 2.6.9 - 2.6.33" accuracy="95"/></os>
  <times srtt="1200" rttvar="300" to="100000"/>
</host>
<runstats>
  <finished time="1700000060" timestr="Mon Nov  6 00:01:00 2023" elapsed="60"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""
# ─────────────────────────────────────────────────────────────────────────────


def _check_nmap() -> bool:
    """Return True if nmap is available on PATH."""
    return shutil.which("nmap") is not None


def build_nmap_command(target: str, profile: str, xml_output: Path,
                       extra_args: Optional[list] = None) -> list:
    """
    Construct the nmap command list.

    Args:
        target:      IP address or hostname.
        profile:     'quick' → top 100 ports; 'full' → all 65535 ports.
        xml_output:  Path where nmap writes its XML file.
        extra_args:  Additional nmap flags to append.

    Returns:
        List of strings suitable for subprocess.
    """
    cmd = ["nmap", "-Pn", "-sV", "-sC", "--open", "-oX", str(xml_output)]

    if profile == "full":
        cmd += ["-p-", "-T4"]
    else:
        # 'quick' — top 100 ports, aggressive timing
        cmd += ["--top-ports", "100", "-T4"]

    if extra_args:
        cmd += extra_args

    cmd.append(target)
    return cmd


def run_nmap(target: str, profile: str, output_dir: Path,
             verbose: bool = False, demo: bool = False) -> dict:
    """
    Execute nmap and return parsed results.

    Args:
        target:      Scan target (IP / hostname).
        profile:     'quick' or 'full'.
        output_dir:  Directory to store raw nmap output.
        verbose:     Log nmap stdout in real time if True.
        demo:        Use embedded demo XML instead of running nmap.

    Returns:
        dict with keys: target, hostname, os_guess, open_ports, raw_xml_path
        open_ports is a list of dicts: {port, protocol, service, product, version, state}
    """
    xml_path = output_dir / "nmap.xml"

    if demo:
        logger.info("[DEMO] Using embedded demo nmap XML — no live scan performed.")
        xml_path.write_text(DEMO_NMAP_XML, encoding="utf-8")
        return _parse_nmap_xml(xml_path, target)

    if not _check_nmap():
        logger.warning("nmap not found. Skipping port scan.")
        return {"target": target, "hostname": "", "os_guess": "",
                "open_ports": [], "raw_xml_path": None, "error": "nmap not found"}

    cmd = build_nmap_command(target, profile, xml_path)
    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        output = proc.stdout + proc.stderr
        (output_dir / 'nmap_stdout.txt').write_text(output, encoding='utf-8')
        if verbose:
            logger.debug('[nmap] %s', output)
        if proc.returncode:
            return {'target': target, 'hostname': '', 'os_guess': '', 'open_ports': [],
                    'raw_xml_path': str(xml_path),
                    'error': proc.stderr.strip() or f'nmap exited {proc.returncode}'}

    except FileNotFoundError:
        logger.error("nmap binary not found.")
        return {"target": target, "hostname": "", "os_guess": "",
                "open_ports": [], "raw_xml_path": None, "error": "nmap not found"}
    except Exception as exc:
        logger.error("nmap error: %s", exc)
        return {"target": target, "hostname": "", "os_guess": "",
                "open_ports": [], "raw_xml_path": None, "error": str(exc)}

    result = _parse_nmap_xml(xml_path, target)
    wrapped = [p for p in result['open_ports'] if p['service'] == 'tcpwrapped']
    if wrapped:
        _retry_wrapped_services(result, wrapped, target, output_dir)
    return result


def _retry_wrapped_services(result: dict, wrapped: list, target: str,
                            output_dir: Path) -> None:
    """Retry only wrapped ports, preserving discovery when identification fails."""
    retry_xml = output_dir / 'nmap_service_retry.xml'
    cmd = ['nmap', '-Pn', '-sV', '--version-all', '-T3', '--max-parallelism', '1',
           '-p', ','.join(str(p['port']) for p in wrapped), '-oX', str(retry_xml), target]
    logger.info('Retrying service detection on %d tcpwrapped ports: %s',
                len(wrapped), ' '.join(cmd))
    result['service_retry_xml_path'] = str(retry_xml)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        (output_dir / 'nmap_service_retry_stdout.txt').write_text(
            proc.stdout + proc.stderr, encoding='utf-8')
        if proc.returncode:
            result['service_detection_warning'] = 'Service retry failed; original discovery retained.'
            return
        retry = _parse_nmap_xml(retry_xml, target)
        if retry['error']:
            result['service_detection_warning'] = retry['error']
            return
        identified = {(p['protocol'], p['port']): p for p in retry['open_ports']
                      if p['service'] not in ('tcpwrapped', 'unknown', '')
                      and p['service_method'] == 'probed'}
        for port in wrapped:
            recovered = identified.get((port['protocol'], port['port']))
            if recovered:
                port.update(recovered)
                port['fingerprint_source'] = 'nmap_service_retry'
    except (OSError, subprocess.TimeoutExpired) as exc:
        result['service_detection_warning'] = f'Service retry failed: {exc}'
        return
    remaining = [str(p['port']) for p in wrapped if p['service'] == 'tcpwrapped']
    if remaining:
        result['service_detection_warning'] = (
            'Connections still close before identification on ports ' + ', '.join(remaining)
            + '. Check target access controls and hostname/IP selection.')
        logger.warning(result['service_detection_warning'])


def _parse_nmap_xml(xml_path: Path, target: str) -> dict:
    """
    Parse nmap XML file into a structured dict.

    Args:
        xml_path: Path to nmap XML output.
        target:   Original target string.

    Returns:
        Structured scan result dict.
    """
    result = {
        "target": target,
        "hostname": "",
        "os_guess": "",
        "open_ports": [],
        "raw_xml_path": str(xml_path),
        "error": None,
    }

    if not xml_path.exists():
        result["error"] = f"XML file not found: {xml_path}"
        return result

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        result["error"] = f"XML parse error: {exc}"
        return result

    # ── Host-level info ────────────────────────────────────────────────────
    host_el = root.find("host")
    if host_el is None:
        # --open suppresses the <host> tag when no ports are open.
        # Treat this as 0 open ports rather than a fatal error, so
        # downstream modules that don't require ports can still run.
        logger.info("No host element in nmap XML — target may be down or all ports filtered.")
        return result

    # Hostname
    hn = host_el.find(".//hostname[@type='PTR']")
    if hn is not None:
        result["hostname"] = hn.get("name", "")

    # OS guess (best accuracy)
    best_os = None
    best_acc = 0
    for os_match in host_el.findall(".//osmatch"):
        acc = int(os_match.get("accuracy", "0"))
        if acc > best_acc:
            best_acc = acc
            best_os = os_match.get("name", "")
    result["os_guess"] = best_os or ""

    # ── Ports ─────────────────────────────────────────────────────────────
    ports = []
    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        svc = port_el.find("service")
        ports.append({
            "port":     int(port_el.get("portid", 0)),
            "protocol": port_el.get("protocol", "tcp"),
            "state":    state_el.get("state", "open"),
            "service":  svc.get("name", "unknown") if svc is not None else "unknown",
            "service_method": svc.get("method", "") if svc is not None else "",
            "tunnel":   svc.get("tunnel", "") if svc is not None else "",
            "product":  svc.get("product", "") if svc is not None else "",
            "version":  svc.get("version", "") if svc is not None else "",
        })

    result["open_ports"] = sorted(ports, key=lambda p: p["port"])
    logger.info("Nmap found %d open ports on %s", len(ports), target)
    return result
