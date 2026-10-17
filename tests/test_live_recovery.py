import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
from modules.content import run_gobuster, parse_paths
from modules.web import assessment_ports, _parse_nikto_output


class RecoveryTests(unittest.TestCase):
    def test_nikto_metadata_is_not_a_finding(self):
        text = '+ Target Host: example.test\n+ Target Port: 80\n+ GET /README.md: Readme Found.\n+ 8031 requests: 0 errors'
        self.assertEqual(_parse_nikto_output(Path('/tmp/does-not-exist-recon-nikto.txt'), text), ['+ GET /README.md: Readme Found.'])

    def test_modern_gobuster_output(self):
        self.assertEqual(parse_paths('app  (Status: 403) [Size: 318]\n/login (Status: 200)\nProgress: 2'),
                         ['/app  (Status: 403) [Size: 318]', '/login (Status: 200)'])

    def test_cert_and_wildcard_retry_options_are_recorded(self):
        failures = [CompletedProcess([], 1, '', 'tls: failed to verify certificate'),
                    CompletedProcess([], 1, '', 'server returns status code for non existing urls. x (Length: 0)'),
                    CompletedProcess([], 0, '/login (Status: 200)', '')]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); words = base / 'words'; words.write_text('login')
            with patch('modules.content.shutil.which', return_value='gobuster'), patch('modules.content.subprocess.run', side_effect=failures) as proc:
                result = run_gobuster('example.test', [{'port': 443, 'service': 'https'}], base, wordlist=words)
            self.assertIsNone(result['error'])
            self.assertEqual(len(result['findings'][0]['warnings']), 2)
            self.assertIn('-k', proc.call_args.args[0])
            self.assertIn('--exclude-length', proc.call_args.args[0])

    def test_fingerprint_fallback_does_not_overwrite_nmap(self):
        original = {'port': 80, 'product': '', 'version': ''}
        state = {'nmap': {'open_ports': [original]}, 'whatweb': {'findings': [
            {'url': 'http://example.test:80', 'technologies': [{'name': 'Apache', 'version': '2.4.68'}]}]}}
        ports = assessment_ports(state)
        self.assertEqual(ports[0]['version'], '2.4.68')
        self.assertEqual(ports[0]['fingerprint_source'], 'whatweb')
        self.assertEqual(original['version'], '')
        original.update(product='nginx', version='1.24.0')
        self.assertEqual(assessment_ports(state)[0]['product'], 'nginx')


class PartialFingerprintTests(unittest.TestCase):
    def test_known_product_missing_version(self):
        state = {'nmap': {'open_ports': [{'port': 80, 'product': 'Apache httpd', 'version': ''}]},
                 'whatweb': {'findings': [{'url': 'http://example.test', 'technologies': [{'name': 'Apache', 'version': '2.4.68'}]}]}}
        self.assertEqual(assessment_ports(state)[0]['version'], '2.4.68')


class CLIFailureTests(unittest.TestCase):
    def test_failed_discovery_exits_nonzero(self):
        import os
        import subprocess
        import sys
        script = Path(__file__).resolve().parents[1] / 'recon.py'
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, str(script), '--target', 'example.test'],
                                  cwd=tmp, env={**os.environ, 'PATH': '/nonexistent'},
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 1)
            self.assertIn('SCAN INCOMPLETE', proc.stdout)
            report = next((Path(tmp) / 'output').glob('*/report_*.html')).read_text()
            self.assertIn('Port coverage is unknown', report)
