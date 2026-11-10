"""ROI for Applications v2: the run priced against the manual baseline (agentic-patching.py roi_appv2)."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
console = None


def load_console():
    """agentic-patching.py, loaded on first use rather than at import: loading it wires hooks into appv2 and reads
    .env, which must not happen before test_appv2 has run. The environment and appv2 are put back afterwards."""
    global console
    if console is None:
        import os
        import appv2
        env, hooks = dict(os.environ), dict(vars(appv2))
        spec = importlib.util.spec_from_file_location('console', ROOT / 'agentic-patching.py')
        console = importlib.util.module_from_spec(spec)
        sys.modules['console'] = console          # its dataclasses look themselves up here
        spec.loader.exec_module(console)
        os.environ.clear(); os.environ.update(env)
        for k, v in hooks.items():
            setattr(appv2, k, v)
    return console


def run(outcomes, status='complete'):
    hosts = [{'app': app, 'host': f'node{i}', 'env': env, 'outcome': o}
             for i, (app, env, o) in enumerate(outcomes)]
    return {'status': status, 'started_at': '2026-11-10T10:00:00Z', 'finished_at': '2026-11-10T10:20:00Z',
            'event': {'artifact': 'mina-core', 'version': '2.2.5.rhlw-00002', 'cves': ['CVE-2026-41635']},
            'playbooks': [{'app': 'workflow-engine', 'changes': [{'cves': ['CVE-2026-41635']}, {'cves': ['CVE-2023-44981']}]}],
            'hosts': hosts}


class RoiV2(unittest.TestCase):
    def setUp(self):
        load_console()
        self.b = console.roi_baseline()

    def test_nothing_dispatched_is_absent(self):
        self.assertIsNone(console.roi_appv2({}, self.b))
        self.assertIsNone(console.roi_appv2(run([('workflow-engine', 'prod', 'skipped')]), self.b))

    def test_counts_and_saving(self):
        r = console.roi_appv2(run([('workflow-engine', 'qa', 'patched'), ('workflow-engine', 'prod', 'patched')]), self.b)
        m = r['measured']
        self.assertEqual((m['sites'], m['gated'], m['apps'], m['changes'], m['advisories'], m['patched']),
                         (2, 1, 1, 2, 2, 2))
        self.assertGreater(r['saved']['minutes'], 0)
        self.assertEqual(r['left']['minutes'], 0)
        self.assertIsNotNone(r['auto']['lead_hours'])
        self.assertTrue(any(p['sites'] == 2 for p in r['curve']))

    def test_unpatched_sites_are_charged_back(self):
        full = console.roi_appv2(run([('workflow-engine', 'qa', 'patched'), ('workflow-engine', 'prod', 'patched')]), self.b)
        part = console.roi_appv2(run([('workflow-engine', 'qa', 'patched'), ('workflow-engine', 'prod', 'rejected')]), self.b)
        self.assertEqual(part['left']['sites'], 1)
        self.assertLess(part['saved']['minutes'], full['saved']['minutes'])

    def test_report_with_v2_only(self):
        rep = console.roi_report({}, None, [], None, run([('workflow-engine', 'qa', 'patched')]))
        self.assertEqual(rep['sides'], {'infra': False, 'app': False, 'appv2': True})
        self.assertEqual(rep['combined']['minutes'], rep['appv2']['saved']['minutes'])

    def test_pdf_report_carries_roi(self):
        import tempfile, appv2
        st = dict(run([('workflow-engine', 'qa', 'patched')]), run_id='r1', simulated=True)
        st['event'].update(group='org.apache.mina')
        st['playbooks'][0]['changes'] = [{'artifact': 'mina-core', 'from': '2.2.5', 'to': '2.2.5.rhlw-00002',
                                          'source': 'lightwell', 'cves': ['CVE-2026-41635']},
                                         {'artifact': 'zookeeper', 'from': '3.5.9', 'to': '3.5.9.rhlw-00001',
                                          'source': 'lightwell', 'cves': ['CVE-2023-44981']}]
        saved = (appv2.H.roi, appv2.H.env)
        out = tempfile.mkdtemp()
        appv2.configure(roi=console.appv2_roi, env=lambda k, d='': out if k == 'REPORTS_DIR' else d)
        try:
            rep = appv2.write_report(st)
        finally:
            appv2.configure(roi=saved[0], env=saved[1])
        import zlib, re
        raw = (Path(out) / rep['file']).read_bytes()
        text = b''.join(zlib.decompress(m) if m[:1] == b'x' else m
                        for m in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.S))
        self.assertIn(b'Return on investment', text)
        self.assertIn(b'CVE-2023-44981', text)                       # the extra change's CVE is listed too
        self.assertIn(b'2.2.5 -> 2.2.5.rhlw-00002', text)             # the arrow prints

    def test_report_with_nothing_still_refuses(self):
        with self.assertRaises(console.BackendUnavailable):
            console.roi_report({}, None, [], None, {})


if __name__ == '__main__':
    unittest.main()
