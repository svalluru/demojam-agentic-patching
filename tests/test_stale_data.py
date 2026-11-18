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
                      dict(self.c.SIM.runs), dict(appv2._BOM_UPDATES), self.c.RAG_DATA_DIR, appv2.state_dir)
        # Every place the archive reads must point into the temp dir, or the test moves the repo's real runtime data.
        self.c.ROOT = self.tmp
        self.c.RAG_DATA_DIR = self.tmp / 'rag-setup' / 'data' / 'runs'
        appv2.state_dir = lambda: self.tmp / 'runs'
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
         runs, bom, self.c.RAG_DATA_DIR, appv2.state_dir) = self.saved
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


class LabGuardEdges(LabGuard):
    def test_archive_runs_works_without_a_lab_id(self):
        self.c.lab_id = lambda: ''
        msg = self.c.lab_guard(force=True)
        self.assertIn('archived', msg)
        self.assertFalse((self.tmp / 'runs' / 'nexus-poller.json').exists())

    def test_a_separate_applications_state_dir_is_archived_too(self):
        state = self.tmp / 'state'; state.mkdir()
        (state / 'appv2-bom-updates.json').write_text('{}')
        appv2.state_dir = lambda: state
        self.at('api.cluster-a'); self.at('api.cluster-b')
        self.assertFalse((state / 'appv2-bom-updates.json').exists())
        archived = next((self.tmp / 'runs' / 'archive').iterdir())
        self.assertTrue((archived / 'appv2-state' / 'appv2-bom-updates.json').exists())


class SimulatedRecords(unittest.TestCase):
    def test_simulated_records_are_recognised(self):
        d = Path(tempfile.mkdtemp())
        sim = d / 'a.md'; sim.write_text('Result: SUCCESS\n\nNOTE: simulated run. Automation Orchestrator was unreachable')
        real = d / 'b.md'; real.write_text('Result: SUCCESS\n\nWhat happened: patched')
        named = d / 'c-SIMULATED.md'; named.write_text('x')
        self.assertEqual([ingest.is_simulated(p) for p in (sim, real, named)], [True, False, True])


class PerSiteVersions(unittest.TestCase):
    def app(self, site_versions=None):
        dep = {'group': 'org.springframework', 'artifact': 'spring-webmvc', 'version': '5.3.18'}
        if site_versions:
            dep['site_versions'] = site_versions
        return {'app': 'workflow-engine', 'dependencies': [dep],
                'servers': [{'host': h, 'site': s, 'env': e} for h, s, e in
                            (('node1', 'lab', 'qa'), ('node2', 'edge-site-1', 'prod'), ('node3', 'core-dc-1', 'prod'))]}

    def test_a_site_left_out_of_a_run_is_still_offered_the_fix(self):
        ev = {'group': 'org.springframework', 'artifact': 'spring-webmvc', 'version': '5.3.18.rhlw-00010'}
        imp = appv2.impact(ev, [self.app({'node1': '5.3.18.rhlw-00010', 'node2': '5.3.18.rhlw-00010'})])
        self.assertEqual([t['site'] for t in imp['targets']], ['core-dc-1'])
        self.assertEqual(imp['other'], [{'app': 'workflow-engine', 'installed': '5.3.18.rhlw-00010',
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
        out = ('node1 | CHANGED | rc=0 >>\n{"status":"UP","jars":{"json":"json-20220320.0.0.rhlw-00003.jar",'
               '"json-path":"json-path-2.8.0.jar"}}\n'
               'node3 | UNREACHABLE! => {\n    "msg": "timeout"\n}\n')
        bodies = appv2._parse_health_output(out)
        self.assertEqual(list(bodies), ['node1'])
        jars = bodies['node1']['jars']
        self.assertEqual(appv2._jar_version('json', jars['json']), '20220320.0.0.rhlw-00003')
        self.assertEqual(appv2._jar_version('json-path', jars['json-path']), '2.8.0')
        self.assertEqual(appv2._jar_version('json', jars['json-path']), '')       # json is a prefix of json-path
        self.assertEqual(appv2._jar_version('spring-core', jars['json']), '')

    def test_real_aap_output_with_colour_codes_parses(self):
        # Copied from a live AAP ad-hoc command's stored stdout (format=json, 'content').
        out = ('SSH password: \n\x1b[0;33mnode1 | CHANGED | rc=0 >>\x1b[0m\n\x1b[0;33m{"status":"UP","jars":'
               '{"json":"json-20220320.jar"}}\x1b[0m\n\x1b[0;33mnode3 | CHANGED | rc=0 >>\x1b[0m\n'
               '\x1b[0;33m{"status":"UP","jars":{"json":"json-20220320.jar"}}\x1b[0m\n')
        bodies = appv2._parse_health_output(out)
        self.assertEqual(sorted(bodies), ['node1', 'node3'])
        self.assertEqual(bodies['node3']['jars']['json'], 'json-20220320.jar')


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


class RefreshVersionsLive(unittest.TestCase):
    """Item 1 of the second review: the AAP stdout comes back as JSON with the text under 'content', the way the
    console's AAP helper (which parses every body as JSON) can read it."""

    def setUp(self):
        self.saved = (appv2.H.demo_mode, appv2.H.aap_call, appv2.H.env, dict(appv2._BOM_UPDATES), appv2._persist)
        appv2._persist = lambda: None
        appv2.H.demo_mode = staticmethod(lambda: False)
        # APPV2_STATE_DIR into a temp dir: refresh_versions clears the estate cache file, and without this the test
        # deleted the real runs/appv2-estate-reasoning.json.
        tmp = tempfile.mkdtemp(prefix='refresh-')
        appv2.H.env = staticmethod(lambda k, d='': {'BOM_DIR': str(ROOT / 'app-data' / 'bom'),
                                                    'APPV2_STATE_DIR': tmp}.get(k, d))
        appv2._BOM_UPDATES.clear()
        appv2._BOM_UPDATES['workflow-engine|org.springframework:spring-webmvc'] = '5.3.18.rhlw-00010'
        self.calls = []

        def aap(path, method='GET', body=None):
            self.calls.append(path)
            if path.startswith(('/inventories/', '/credentials/')):
                return {'results': [{'id': 7, 'name': path.split('name=')[1].replace('%20', ' ')}]}
            if path == '/ad_hoc_commands/':
                return {'id': 11}
            if path.endswith('/stdout/?format=json'):
                return {'content': 'node1 | CHANGED | rc=0 >>\n{"status":"UP","jars":{"spring-webmvc":'
                                   '"spring-webmvc-5.3.18.jar","spring-core":"spring-core-5.3.18.jar"}}\n'}
            return {'status': 'successful'}
        appv2.H.aap_call = staticmethod(aap)

    def tearDown(self):
        appv2.H.demo_mode, appv2.H.aap_call, appv2.H.env, bom, appv2._persist = self.saved
        appv2._BOM_UPDATES.clear(); appv2._BOM_UPDATES.update(bom)

    def test_readings_replace_a_stale_app_level_write_back(self):
        code, body = appv2.refresh_versions()
        self.assertEqual(code, 200, body)
        self.assertEqual(body['versions']['workflow-engine']['node1']['spring-webmvc'], '5.3.18')
        # node1 runs the seeded jar again: the stale app-level "patched" record is gone.
        self.assertNotIn('workflow-engine|org.springframework:spring-webmvc', appv2._BOM_UPDATES)
        self.assertTrue(any(c.endswith('?format=json') for c in self.calls))

    def test_a_refused_command_does_not_poll_a_missing_id(self):
        real = appv2.H.aap_call
        appv2.H.aap_call = staticmethod(lambda path, method='GET', body=None:
                                        {} if path == '/ad_hoc_commands/' else real(path, method, body))
        code, body = appv2.refresh_versions()
        self.assertEqual(code, 200)
        self.assertTrue(body['errors'])
        self.assertFalse([c for c in self.calls if '/ad_hoc_commands/None' in c])


class SettleOnlyReadings(unittest.TestCase):
    """Item 2: a run read without steps (an AO hiccup) is not cached as its final outcome."""

    def test_an_empty_reading_is_not_cached(self):
        c = load_console()
        c.PatchingAgent._settled = {}
        a = c.PatchingAgent()
        replies = iter([{'outcome': 'rejected', 'steps': []}, {'outcome': 'patched', 'steps': [{'name': 'x'}]}])
        a.run_detail = lambda eid: next(replies)
        row = {'execution_id': 'e1', 'status': 'completed', 'outcome': 'completed'}
        self.assertEqual(a._settle_finished([dict(row)])[0]['outcome'], 'completed')   # list's own reading kept
        self.assertEqual(a._settle_finished([dict(row)])[0]['outcome'], 'patched')     # read again, now settled
        c.PatchingAgent._settled = {}


class SourceRebuildPerSite(unittest.TestCase):
    """Item 3: a source rebuild keeps versions sites were patched to, even when only per-site write-backs exist."""

    def test_per_site_patched_versions_reach_the_pom_edits(self):
        saved = (appv2.H.demo_mode, dict(appv2._BOM_UPDATES))
        try:
            appv2.H.demo_mode = staticmethod(lambda: True)
            app = next(a for a in appv2.load_bom() if a['app'] == 'workflow-engine')
            dep = next(d for d in app['dependencies'] if d['artifact'] == 'spring-webmvc')
            appv2._BOM_UPDATES.clear()
            host = app['servers'][0]['host']
            appv2._BOM_UPDATES[f"workflow-engine|{host}|{dep['group']}:spring-webmvc"] = dep['version'] + '.rhlw-00010'
            edits = appv2.source_changes('workflow-engine', [])
            self.assertIn({'name': f"{dep['group']}:spring-webmvc", 'from': dep['version'],
                           'to': dep['version'] + '.rhlw-00010'}, edits)
        finally:
            appv2.H.demo_mode = saved[0]
            appv2._BOM_UPDATES.clear(); appv2._BOM_UPDATES.update(saved[1])


if __name__ == '__main__':
    unittest.main()
