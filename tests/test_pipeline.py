import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from modules.pipeline import Tool, execute
from modules.vuln import run_searchsploit
from modules.web import http_endpoints
from recon import run_scan
from modules.report import generate_html, generate_json, generate_csv


class PipelineTests(unittest.TestCase):
    def test_stage_dependencies_and_retry(self):
        calls = []
        def run(name):
            calls.append(name)
            return {'error': None}
        tools = [Tool('nmap', 'discovery', lambda s: True, lambda s: run('nmap')),
                 Tool('whatweb', 'enumeration', lambda s: s['nmap']['status'] == 'ok', lambda s: run('whatweb')),
                 Tool('searchsploit', 'assessment', lambda s: s['whatweb']['status'] == 'ok', lambda s: run('searchsploit'))]
        state = {'whatweb': {'status': 'error', 'error': 'old failure'}}
        execute(tools, state, {t.name for t in tools}, 4, lambda s: None, lambda **e: None)
        self.assertEqual(calls, ['nmap', 'whatweb', 'searchsploit'])
        execute(tools, state, {t.name for t in tools}, 4, lambda s: None, lambda **e: None)
        self.assertEqual(len(calls), 3)

    def test_discovery_failure_blocks_followups(self):
        tools = [Tool('nmap', 'discovery', lambda s: True, lambda s: {'error': 'failed'}),
                 Tool('nikto', 'assessment', lambda s: True, lambda s: self.fail('must not run'))]
        state = execute(tools, {}, {'nmap', 'nikto'}, 1, lambda s: None, lambda **e: None)
        self.assertEqual(state['nikto']['status'], 'skipped')

    def test_filter_cached_candidates_per_actual_version(self):
        entries = [{'id': '1', 'title': 'Apache 2.4.49 - Example', 'path': '', 'type': ''},
                   {'id': '2', 'title': 'Apache - Unknown version', 'path': '', 'type': ''}]
        ports = [{'port': 80, 'product': 'Apache httpd', 'version': '2.4.68'},
                 {'port': 443, 'product': 'Apache httpd', 'version': '2.4.49'}]
        with patch('modules.vuln._tool_available', return_value=True), patch('modules.vuln._run_single_query', return_value=entries) as query:
            data = run_searchsploit(ports, Path('/tmp'))
        self.assertEqual(query.call_count, 1)
        self.assertEqual([r['exploit_count'] for r in data['results']], [0, 1])
        self.assertEqual(data['total_unverified'], 2)

    def test_tls_on_nonstandard_port(self):
        self.assertEqual(list(http_endpoints('::1', [{'port': 9443, 'service': 'http', 'tunnel': 'ssl'}])), [(9443, 'https://[::1]:9443')])

    def test_demo_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); raw = base / 'raw'; raw.mkdir()
            data = run_scan('demo-target', 'quick', base, raw, 4, False, True, {}, quiet=True)
            self.assertEqual(data['gobuster']['status'], 'ok')
            self.assertEqual(data['searchsploit']['total_exploits'], 3)
            html = generate_html(data, base / 'report.html', raw).read_text()
            self.assertEqual(html.count('<span'), html.count('</span>'))
            generate_json(data, base / 'report.json')
            generate_csv(data, base / 'report.csv')

class IntegrationTests(unittest.TestCase):
    def test_webui_job_and_saved_status(self):
        import threading
        import webui
        with tempfile.TemporaryDirectory() as tmp, patch.object(webui, 'OUTPUT_ROOT', Path(tmp)):
            sid = webui.start_scan('demo-target', 'quick', 4,
                                   ['whatweb', 'gobuster', 'searchsploit'], True)
            job = next(t for t in threading.enumerate() if t.name == f'scan-{sid}')
            job.join(timeout=5)
            self.assertFalse(job.is_alive())
            rec = webui.find_record(sid)
            self.assertEqual(rec['status'], 'done', rec.get('error'))
            self.assertIn(b'Gobuster', webui.render_index([]))
            self.assertIn(b'Scan complete', webui.render_status(sid))
            saved = webui.disk_record(sid)
            self.assertEqual(saved['state']['nikto']['status'], 'skipped')
            self.assertEqual(saved['state']['gobuster']['status'], 'ok')
            with webui.SCANS_LOCK:
                webui.SCANS.pop(sid)

    def test_gobuster_command_and_output(self):
        from subprocess import CompletedProcess
        from modules.content import run_gobuster
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); words = base / 'words.txt'; words.write_text('login\n')
            with patch('modules.content.shutil.which', return_value='/bin/gobuster'), patch('modules.content.subprocess.run', return_value=CompletedProcess([], 0, '/login (Status: 200)\n', '')) as process:
                result = run_gobuster('example.test', [{'port': 9443, 'service': 'https'}], base, wordlist=words)
            command = process.call_args.args[0]
            self.assertIn('https://example.test:9443', command)
            self.assertEqual(result['findings'][0]['paths'], ['/login (Status: 200)'])

    def test_searchsploit_failure_is_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('modules.vuln._tool_available', return_value=True), patch('modules.vuln._run_single_query', side_effect=RuntimeError('failed')):
                result = run_searchsploit([{'port': 80, 'product': 'Apache', 'version': '2.4.68'}], Path(tmp))
                self.assertTrue(result['error'])
                self.assertEqual(result['results'][0]['error'], 'failed')


if __name__ == '__main__':
    unittest.main()
