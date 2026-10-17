import unittest
from webui import scan_outcome, render_status, SCANS, SCANS_LOCK


class WebUIOutcomeTests(unittest.TestCase):
    def test_failures_and_skips_have_distinct_outcomes(self):
        self.assertEqual(scan_outcome({'nmap': {'error': 'Timed out'}})[0], 'error')
        self.assertEqual(scan_outcome({'gobuster': {'status': 'error', 'error': 'Failed'}})[0], 'done_with_errors')
        self.assertEqual(scan_outcome({'smbclient': {'status': 'skipped', 'error': 'Ports not open'}}), ('done', None))

    def test_failed_scan_keeps_report_links_and_skip_status(self):
        sid = 'test-ui-outcomes'
        record = {'id': sid, 'target': 'test', 'status': 'done_with_errors',
                  'error': 'Gobuster failed', 'reports': {'html': 'report.html'},
                  'events': [{'type': 'task', 'name': 'smbclient', 'status': 'skipped'}]}
        with SCANS_LOCK:
            SCANS[sid] = record
        try:
            page = render_status(sid).decode()
            self.assertIn('Scan finished with issues', page)
            self.assertIn('dot skip', page)
            self.assertIn('/download/test-ui-outcomes/json', page)
            self.assertNotIn('setInterval(poll', page)
        finally:
            with SCANS_LOCK:
                SCANS.pop(sid)
