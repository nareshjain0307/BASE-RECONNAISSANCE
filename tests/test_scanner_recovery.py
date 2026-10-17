import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.scanner import run_nmap


def xml(service, port=22):
    return (f'<nmaprun><host><ports><port protocol="tcp" portid="{port}">'
            f'<state state="open"/><service method="probed" {service}/>'
            '</port></ports></host></nmaprun>')


class ScannerRecoveryTests(unittest.TestCase):
    def scan(self, retry):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.commands = []

        def execute(cmd, **kwargs):
            self.commands.append(cmd)
            if len(self.commands) == 1:
                content = xml('name="tcpwrapped"')
            elif isinstance(retry, Exception):
                raise retry
            else:
                content = retry
            Path(cmd[cmd.index('-oX') + 1]).write_text(content)
            return subprocess.CompletedProcess(cmd, 0, 'scan output', '')

        with patch('modules.scanner._check_nmap', return_value=True), patch(
                'modules.scanner.subprocess.run', side_effect=execute):
            return run_nmap('example.test', 'quick', Path(self.tmp.name))

    def test_recovers_identification_and_keeps_original_evidence(self):
        result = self.scan(xml('name="ssh" product="OpenSSH" version="9.2"'))
        self.assertEqual(result['open_ports'][0]['service'], 'ssh')
        self.assertEqual(result['open_ports'][0]['version'], '9.2')
        self.assertIn('tcpwrapped', Path(result['raw_xml_path']).read_text())
        cmd = self.commands[1]
        self.assertEqual(cmd[cmd.index('-p') + 1], '22')
        self.assertIn('-T3', cmd)

    def test_persistent_wrapping_is_not_replaced_with_port_guess(self):
        result = self.scan(xml('name="tcpwrapped"'))
        self.assertEqual(result['open_ports'][0]['service'], 'tcpwrapped')
        self.assertIn('Connections still close', result['service_detection_warning'])

    def test_timeout_preserves_discovery(self):
        result = self.scan(subprocess.TimeoutExpired('nmap', 300))
        self.assertIsNone(result['error'])
        self.assertEqual(result['open_ports'][0]['service'], 'tcpwrapped')
        self.assertIn('retry failed', result['service_detection_warning'])

    def test_port_table_guess_does_not_count_as_recovery(self):
        result = self.scan(xml('name="ssh"').replace('method="probed"', 'method="table"'))
        self.assertEqual(result['open_ports'][0]['service'], 'tcpwrapped')

    def test_successful_detection_does_not_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'nmap.xml').write_text(xml('name="ssh"'))
            with patch('modules.scanner._check_nmap', return_value=True), patch(
                    'modules.scanner.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
                result = run_nmap('example.test', 'quick', Path(tmp))
            self.assertEqual(result['open_ports'][0]['service'], 'ssh')
            self.assertEqual(run.call_count, 1)
