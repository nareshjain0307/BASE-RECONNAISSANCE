import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import webui
from modules.pipeline import Tool, execute


class LiveResultTests(unittest.TestCase):
    def test_completed_results_arrive_before_parallel_tool_finishes(self):
        release = threading.Event(); received = threading.Event(); events = []
        def slow(state):
            if not release.wait(5):
                raise RuntimeError('test gate timed out')
            return {'error': None}
        def emit(**event):
            events.append(event)
            if event.get('name') == 'fast' and event.get('result'):
                received.set()
        tools = [Tool('fast', 'assessment', lambda s: True, lambda s: {'findings': ['ready'], 'error': None}),
                 Tool('slow', 'assessment', lambda s: True, slow)]
        thread = threading.Thread(target=execute, args=(tools, {}, {'fast', 'slow'}, 2, lambda s: None, emit))
        thread.start()
        try:
            self.assertTrue(received.wait(2))
            self.assertTrue(thread.is_alive())
            self.assertEqual(next(e for e in events if e.get('result') and e['name'] == 'fast')['result']['findings'], ['ready'])
        finally:
            release.set(); thread.join(5)

    def test_web_job_exposes_completed_results_while_nikto_runs(self):
        release = threading.Event(); started = threading.Event()
        def slow_nikto(*args, **kwargs):
            started.set(); release.wait(5)
            return {'findings': [], 'error': None}
        with tempfile.TemporaryDirectory() as tmp, patch.object(webui, 'OUTPUT_ROOT', Path(tmp)), patch('recon.run_nikto', side_effect=slow_nikto):
            sid = webui.start_scan('demo-target', 'quick', 4, ['whatweb', 'nikto', 'searchsploit'], True)
            try:
                self.assertTrue(started.wait(2))
                rec = webui.find_record(sid)
                self.assertEqual(rec['status'], 'running')
                self.assertIn('nmap', rec['results'])
                self.assertIn('whatweb', rec['results'])
                self.assertEqual(next(t for t in webui.tool_statuses(rec) if t['name'] == 'nikto')['status'], 'running')
                page = webui.render_status(sid).decode()
                self.assertIn('Results so far', page)
                self.assertIn('2.2.8', page)
                self.assertIn('Completed', page)
                self.assertFalse(any('result' in event for event in rec['events']))
            finally:
                release.set()
                job = next((t for t in threading.enumerate() if t.name == f'scan-{sid}'), None)
                if job: job.join(5)
                with webui.SCANS_LOCK: webui.SCANS.pop(sid, None)

    def test_tool_findings_are_escaped_and_snapshot_is_independent(self):
        html = webui.render_findings({'gobuster': {'status': 'ok', 'findings': [{'url': '<script>', 'paths': ['<img onerror=x>']}]}})
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('&lt;img onerror=x&gt;', html)
