"""Gobuster directory enumeration against discovered HTTP endpoints."""
import re
import shutil
import subprocess
from pathlib import Path
from modules.web import http_endpoints


def run_gobuster(target, ports, output_dir, verbose=False, demo=False, wordlist=None):
    result = {'findings': [], 'error': None}
    if demo:
        result['findings'] = [{'url': f'http://{target}', 'paths': ['/admin (Status: 403)', '/login (Status: 200)']}]
        return result
    if not shutil.which('gobuster'):
        return {**result, 'error': 'gobuster not installed.'}
    candidates = [Path(wordlist)] if wordlist else [Path('/usr/share/wordlists/dirb/common.txt'), Path('/usr/share/seclists/Discovery/Web-Content/common.txt')]
    words = next((p for p in candidates if p.is_file()), None)
    if words is None:
        return {**result, 'error': 'No Gobuster wordlist found. Set --wordlist.'}
    for port, url in http_endpoints(target, ports):
        raw = output_dir / f'gobuster_{port}.txt'
        finding = {'url': url, 'paths': [], 'warnings': []}
        cmd = ['gobuster', 'dir', '-u', url, '-w', str(words),
               '-t', '4', '--timeout', '10s', '-o', str(raw)]
        try:
            # At most two recovery options, each recorded for the report.
            for attempt in range(3):
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                diagnostic = proc.stderr + proc.stdout
                (output_dir / f'gobuster_{port}_attempt_{attempt}.log').write_text(diagnostic, encoding='utf-8')
                if not proc.returncode:
                    break
                if 'failed to verify certificate' in diagnostic and '-k' not in cmd:
                    cmd += ['-k']
                    finding['warnings'].append('Certificate verification failed; retried without certificate validation.')
                    continue
                wildcard = re.search(r'non existing urls.*?\(Length: (\d+)\)', diagnostic, re.S)
                if wildcard and '--exclude-length' not in cmd:
                    cmd += ['--exclude-length', wildcard[1]]
                    finding['warnings'].append(f'Wildcard responses detected; excluded response length {wildcard[1]}. Valid paths of that size may be omitted.')
                    continue
                break
            text = raw.read_text(errors='replace') if raw.exists() else proc.stdout
            finding['paths'] = parse_paths(text)
            if proc.returncode:
                finding['error'] = proc.stderr.strip() or f'Exit code {proc.returncode}'
                result['error'] = 'Gobuster failed on one or more endpoints; see findings.'
        except subprocess.TimeoutExpired:
            finding['error'] = f'Gobuster timed out for {url}'
            result['error'] = finding['error']
        result['findings'].append(finding)
    return result


def parse_paths(text):
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if re.match(r'^/?\S+\s+\(Status:\s*\d{3}\)', line):
            paths.append(line if line.startswith('/') else '/' + line)
    return paths
