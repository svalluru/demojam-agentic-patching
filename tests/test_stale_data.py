"""Stale data: one lab's runtime data, simulated records kept out of history, per-site versions, stale gates.

    python3 -m unittest discover -s tests
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'rag-setup'))
from test_roi_v2 import load_console  # noqa: E402

import appv2   # noqa: E402
import ingest  # noqa: E402


class LabGuard(unittest.TestCase):
    def setUp(self):
        self.c = load_console()
        self.tmp = Path(tempfile.mkdtemp(prefix='labguard-'))
        self.saved = (self.c.ROOT, self.c.RUNTIME_DIR, self.c.LAB_FILE, self.c.demo_mode, self.c.lab_id,
                      dict(self.c.SIM.runs), dict(appv2._BOM_UPDATES))
        self.c.ROOT = self.tmp
        self.c.RUNTIME_DIR = self.tmp / 'runs'
        self.c.LAB_FILE = self.c.RUNTIME_DIR / 'lab.json'
        self.c.demo_mode = lambda: False
        (self.tmp / 'runs').mkdir()
        (self.tmp / 'runs' / 'appv2-events.json').write_text('[]')
        (self.tmp / 'runs' / 'nexus-poller.json').write_text('["a:b:1.rhlw-00001"]')
        (self.tmp / 'rag-setup' / 'data' / 'runs').mkdir(parents=True)
        (self.tmp / 'rag-setup' / 'data' / 'runs' / 'rec.md').write_text('a record')

    def tearDown(self):
        (self.c.ROOT, self.c.RUNTIME_DIR, self.c.LAB_FILE, self.c.demo_mode, self.c.lab_id,
         runs, bom) = self.saved
        self.c.SIM.runs = runs
        appv2._BOM_UPDATES.clear(); appv2._BOM_UPDATES.update(bom)

    def at(self, lab):
        self.c.lab_id = lambda: lab
        return self.c.lab_guard()

    def test_first_start_tags_without_archiving(self):
        msg = self.at('api.cluster-a')
        self.assertIn('tagged with api.cluster-a', msg)
        self.assertTrue((self.tmp / 'runs' / 'nexus-poller.json').exists())
        self.assertEqual(json.loads(self.c.LAB_FILE.read_text())['lab'], 'api.cluster-a')

    def test_same_lab_keeps_everything(self):
        self.at('api.cluster-a')
        self.assertEqual(self.at('api.cluster-a'), '')
        self.assertTrue((self.tmp / 'runs' / 'appv2-events.json').exists())

    def test_a_new_lab_archives_runs_and_learning_records(self):
        self.at('api.cluster-a')
        appv2._BOM_UPDATES['x|h|g:a'] = '1'
        msg = self.at('api.cluster-b')
        self.assertIn('api.cluster-a', msg)
        self.assertFalse((self.tmp / 'runs' / 'nexus-poller.json').exists())     # the poller starts with no memory
        self.assertFalse((self.tmp / 'rag-setup' / 'data' / 'runs').exists())    # old hosts' history is not ingested
        archived = next((self.tmp / 'runs' / 'archive').iterdir())
        self.assertTrue((archived / 'nexus-poller.json').exists())               # moved, not deleted
        self.assertTrue((archived / 'rag-runs' / 'rec.md').exists())
        self.assertEqual(appv2._BOM_UPDATES, {})
        self.assertEqual(json.loads(self.c.LAB_FILE.read_text())['lab'], 'api.cluster-b')


class SimulatedRecords(unittest.TestCase):
    def test_simulated_records_are_recognised(self):
        d = Path(tempfile.mkdtemp())
        sim = d / 'a.md'; sim.write_text('Result: SUCCESS\n\nNOTE: simulated run. Automation Orchestrator was unreachable')
        real = d / 'b.md'; real.write_text('Result: SUCCESS\n\nWhat happened: patched')
        named = d / 'c-SIMULATED.md'; named.write_text('x')
        self.assertEqual([ingest.is_simulated(p) for p in (sim, real, named)], [True, False, True])


class PerSiteVersions(unittest.TestCase):
    def app(self, site_versions=None):
        dep = {'group': 'org.springframework.security', 'artifact': 'spring-security-web', 'version': '5.7.11'}
        if site_versions:
            dep['site_versions'] = site_versions
        return {'app': 'workflow-engine', 'dependencies': [dep],
                'servers': [{'host': h, 'site': s, 'env': e} for h, s, e in
                            (('node1', 'lab', 'qa'), ('node2', 'edge-site-1', 'prod'), ('node3', 'core-dc-1', 'prod'))]}

    def test_a_site_left_out_of_a_run_is_still_offered_the_fix(self):
        ev = {'group': 'org.springframework.security', 'artifact': 'spring-security-web', 'version': '5.7.11.rhlw-00006'}
        imp = appv2.impact(ev, [self.app({'node1': '5.7.11.rhlw-00006', 'node2': '5.7.11.rhlw-00006'})])
        self.assertEqual([t['site'] for t in imp['targets']], ['core-dc-1'])
        self.assertEqual(imp['other'], [{'app': 'workflow-engine', 'installed': '5.7.11.rhlw-00006',
                                         'why': 'already on this build'}])

    def test_load_bom_keeps_site_versions_until_every_site_matches(self):
        saved = (appv2.H.demo_mode, dict(appv2._BOM_UPDATES))
        try:
            appv2.H.demo_mode = staticmethod(lambda: True)
            app = next(a for a in appv2.load_bom() if a['servers'])
            dep, hosts = app['dependencies'][0], [s['host'] for s in app['servers']]
            ga = f"{dep['group']}:{dep['artifact']}"
            appv2._BOM_UPDATES.clear()
            appv2._BOM_UPDATES[f"{app['app']}|{hosts[0]}|{ga}"] = 'X'
            d = next(x for x in next(a for a in appv2.load_bom() if a['app'] == app['app'])['dependencies']
                     if x['artifact'] == dep['artifact'])
            self.assertEqual((d['version'], d.get('site_versions')), (dep['version'], {hosts[0]: 'X'}))
            for h in hosts:
                appv2._BOM_UPDATES[f"{app['app']}|{h}|{ga}"] = 'X'
            d = next(x for x in next(a for a in appv2.load_bom() if a['app'] == app['app'])['dependencies']
                     if x['artifact'] == dep['artifact'])
            self.assertEqual((d['version'], d.get('site_versions')), ('X', None))
        finally:
            appv2.H.demo_mode = saved[0]
            appv2._BOM_UPDATES.clear(); appv2._BOM_UPDATES.update(saved[1])


class ReadFromHosts(unittest.TestCase):
    def test_health_output_and_jar_names_parse(self):
        out = ('node1 | CHANGED | rc=0 >>\n{"status":"UP","jars":{"mina-core":"mina-core-2.2.5.rhlw-00002.jar"}}\n'
               'node3 | UNREACHABLE! => {\n    "msg": "timeout"\n}\n')
        bodies = appv2._parse_health_output(out)
        self.assertEqual(list(bodies), ['node1'])
        jar = bodies['node1']['jars']['mina-core']
        self.assertEqual(appv2._jar_version('mina-core', jar), '2.2.5.rhlw-00002')
        self.assertEqual(appv2._jar_version('zookeeper', jar), '')


class StaleGates(unittest.TestCase):
    def test_a_gate_waiting_more_than_a_day_is_listed_stale(self):
        c = load_console()
        old = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 3 * 86400))
        new = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 600))
        rows = [{'execution_id': 'a', 'status': 'paused', 'outcome': 'awaiting_approval', 'created_at': old},
                {'execution_id': 'b', 'status': 'paused', 'outcome': 'awaiting_approval', 'created_at': new},
                {'execution_id': 'c', 'status': 'paused', 'outcome': 'awaiting_approval', 'created_at': old,
                 'simulated': True}]
        out = c.PatchingAgent()._settle_finished(rows)
        self.assertEqual([r['outcome'] for r in out], ['stale', 'awaiting_approval', 'awaiting_approval'])


if __name__ == '__main__':
    unittest.main()
