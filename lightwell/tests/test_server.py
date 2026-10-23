import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server                                                              # noqa: E402
from store import Store                                                    # noqa: E402

OSV = {'queries': {'PyPI|django|2.2': ['GHSA-1']},
       'vulns': {'GHSA-1': {'id': 'GHSA-1', 'aliases': ['CVE-2020-1'], 'summary': '=cmd|calc', 'database_specific': {'severity': 'HIGH'},
                            'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'django'}, 'ranges': [
                                {'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.2.28'}]}]}]}}}
REPO = {'ref': 'main', 'commit': 'abc123def456', 'manifests': {'requirements.txt': 'django==2.2\n'}}


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        (base / 'demo' / 'repos').mkdir(parents=True)
        (base / 'demo' / 'repos' / 'acme__app.json').write_text(json.dumps(REPO))
        (base / 'demo' / 'repos' / 'gitlab.com__grp__sub__proj.json').write_text(json.dumps(REPO))
        (base / 'demo' / 'osv.json').write_text(json.dumps(OSV))
        server.DEMO_DIR = base / 'demo'
        server.STORE = Store(base / 'data')
        server.MODE = 'demo'
        server.GITLAB_HOSTS = ['gitlab.com', 'git.example.com']
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.url = f'http://127.0.0.1:{cls.httpd.server_address[1]}'
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                return r.status, raw, r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers

    def js(self, *a, **k):
        code, raw, _ = self.call(*a, **k)
        return code, json.loads(raw)

    def wait_done(self, scan_id):
        for _ in range(50):
            _, d = self.js('GET', f'/v1/scans/{scan_id}')
            if d['scan']['status'] == 'done':
                return d['scan']
            time.sleep(0.1)
        self.fail('scan did not finish')

    def test_mode_and_health(self):
        self.assertEqual(self.js('GET', '/healthz')[1], {'ok': True})
        code, d = self.js('GET', '/v1/mode')
        self.assertEqual((code, d['mode'], d['demo_repos']), (200, 'demo', ['acme/app', 'gitlab.com/grp/sub/proj']))
        self.assertEqual(d['gitlab_hosts'], ['gitlab.com', 'git.example.com'])
        self.assertEqual((d['lightwell']['source'], d['lightwell']['sample']), ('sample', True))

    def test_scan_end_to_end_and_csv(self):
        code, d = self.js('POST', '/v1/scans', {'repos': ['https://github.com/acme/app', 'acme/missing', 'https://gitlab.com/grp/sub/proj']})
        self.assertEqual(code, 202)
        scan = self.wait_done(d['id'])
        ok, bad, gl = scan['repos']
        self.assertEqual((ok['status'], ok['summary']['high'], ok['commit'], ok['host']), ('done', 1, 'abc123def456', 'github.com'))
        self.assertEqual((gl['status'], gl['slug'], gl['host'], gl['summary']['high']), ('done', 'gitlab.com/grp/sub/proj', 'gitlab.com', 1))
        self.assertEqual(ok['findings'][0]['vulns'][0]['suggested_fix'], '2.2.28')
        self.assertEqual(bad['status'], 'error')
        self.assertIn('not recorded', bad['error'])
        code, raw, hdr = self.call('GET', f'/v1/scans/{d["id"]}/findings.csv')
        self.assertEqual(code, 200)
        self.assertIn('text/csv', hdr['Content-Type'])
        self.assertIn('GHSA-1', raw.decode())
        header = raw.decode().splitlines()[0]
        self.assertIn('host', header.split(','))
        self.assertIn('gitlab.com/grp/sub/proj', raw.decode())
        for col in ('lightwell_status', 'lightwell_build', 'lightwell_build_date', 'lightwell_fixes_this', 'lightwell_severity', 'lightwell_nearest_version', 'lightwell_lead_days', 'sample_coverage', 'declared_range'):
            self.assertIn(col, header)
        self.assertEqual(ok['summary']['lightwell']['not_covered'], 1)         # temp catalog is empty, so nothing is covered
        self.assertIn(d['id'], [x['id'] for x in self.js('GET', '/v1/scans')[1]['scans']])

    def test_remediation_in_demo_mode(self):
        _, d = self.js('POST', '/v1/scans', {'repos': ['acme/app']})
        scan = self.wait_done(d['id'])
        body = {'scan': d['id'], 'url': 'acme/app', 'sources': ['osv']}
        code, p = self.js('POST', '/v1/remediations/preview', body)
        self.assertEqual(code, 200)
        self.assertEqual([(c['name'], c['to'], c['source']) for c in p['plan']['changes']], [('django', '2.2.28', 'osv')])
        self.assertEqual(p['plan']['offered'], {'lightwell': 0, 'another': 0, 'osv': 1})
        self.assertFalse(p['plan']['allow_major'])
        self.assertTrue(self.js('POST', '/v1/remediations/preview', {**body, 'allow_major': True})[1]['plan']['allow_major'])
        code, p = self.js('POST', '/v1/remediations/preview', {**body, 'sources': ['lightwell']})
        self.assertEqual((code, p['plan']['changes'], len(p['plan']['skipped'])), (200, [], 1))
        self.assertEqual(self.js('POST', '/v1/remediations', {**body, 'sources': ['lightwell']})[0], 400)       # nothing to change
        code, r = self.js('POST', '/v1/remediations', body)
        self.assertEqual(code, 202)
        code, run = self.js('GET', f'/v1/remediations/{r["id"]}')
        self.assertEqual(code, 200)
        run = run['run']
        self.assertEqual((run['mode'], run['push'], run['branch']), ('demo', False, 'fix/dependency-vulnerabilities'))
        self.assertIn('+django==2.2.28', run['result']['diff'])
        self.assertEqual([s['id'] for s in run['stages']], ['clone', 'edit', 'build'])
        self.assertEqual(run['result']['java']['version'], 17)                                              # nothing in the recorded files, so the default
        _, r3 = self.js('POST', '/v1/remediations', {**body, 'java': 11})
        self.assertEqual(self.js('GET', f'/v1/remediations/{r3["id"]}')[1]['run']['result']['java'], {'version': 11, 'reason': 'chosen when the run was approved'})
        self.assertEqual(self.js('POST', '/v1/remediations', {**body, 'java': 12})[0], 400)
        self.assertEqual(self.js('POST', '/v1/remediations', {**body, 'java': 'abc'})[0], 400)
        _, r2 = self.js('POST', '/v1/remediations', {**body, 'push': True})
        self.assertEqual([s['id'] for s in self.js('GET', f'/v1/remediations/{r2["id"]}')[1]['run']['stages']], ['clone', 'edit', 'build', 'push'])
        self.assertEqual(scan['repos'][0]['status'], 'done')

    def test_remediation_rejects_bad_requests(self):
        _, d = self.js('POST', '/v1/scans', {'repos': ['acme/app']})
        self.wait_done(d['id'])
        for body in ({}, {'scan': 'nope', 'url': 'acme/app', 'sources': ['osv']}, {'scan': d['id'], 'url': 'acme/other', 'sources': ['osv']},
                     {'scan': '0' * 12, 'url': 'acme/app', 'sources': ['osv']}, {'scan': d['id'], 'url': 'acme/app', 'sources': 'osv'}):
            self.assertEqual(self.js('POST', '/v1/remediations/preview', body)[0], 400, body)
        self.assertEqual(self.js('GET', '/v1/remediations/' + '0' * 12)[0], 404)
        self.assertEqual(self.js('GET', '/v1/remediations/..%2fx')[0], 404)

    def test_mode_reports_whether_remediation_is_ready(self):
        self.assertTrue(self.js('GET', '/v1/mode')[1]['remediation']['ready'])
        with mock.patch.object(server, 'MODE', 'live'), mock.patch.object(server, 'AAP_BASE_URL', ''):
            self.assertFalse(self.js('GET', '/v1/mode')[1]['remediation']['ready'])
            self.assertIn('AAP_BASE_URL', self.js('GET', '/v1/mode')[1]['remediation']['detail'])

    def test_validation(self):
        self.assertEqual(self.js('POST', '/v1/scans', {'repos': []})[0], 400)
        self.assertEqual(self.js('POST', '/v1/scans', {'repos': ['https://bitbucket.org/a/b']})[0], 400)
        self.assertEqual(self.js('POST', '/v1/scans', {'repos': ['https://unlisted.example.com/a/b']})[0], 400)   # not in GITLAB_HOSTS
        self.assertEqual(self.js('POST', '/v1/scans', {'repos': ['https://169.254.169.254/latest']})[0], 400)
        self.assertEqual(self.js('PUT', '/v1/repos', {'repos': ['https://git.example.com/a/b']})[0], 200)       # listed, so accepted
        self.assertEqual(self.js('POST', '/v1/scans', {'repos': ['a/b'] * 1 + [f'o/r{i}' for i in range(30)]})[0], 400)
        self.assertEqual(self.js('POST', '/v1/scans', {'repos': 'a/b'})[0], 400)
        code, _, _ = self.call('POST', '/v1/scans', None)
        self.assertEqual(code, 400)
        self.assertEqual(self.js('GET', '/v1/scans/not-an-id')[0], 404)
        self.assertEqual(self.js('GET', '/v1/scans/' + '0' * 12)[0], 404)
        self.assertEqual(self.js('GET', '/v1/scans/..%2f..%2fetc%2fpasswd')[0], 404)
        self.assertEqual(self.js('GET', '/nope')[0], 404)

    def test_oversized_body(self):
        req = urllib.request.Request(self.url + '/v1/scans', data=b'x' * (server.MAX_BODY + 10), method='POST')
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 413)

    def test_repo_list_roundtrip(self):
        self.assertEqual(self.js('PUT', '/v1/repos', {'repos': ['acme/app', 'acme/app', ' acme/other ']})[1]['repos'],
                         ['acme/app', 'acme/other'])
        self.assertEqual(self.js('GET', '/v1/repos')[1]['repos'], ['acme/app', 'acme/other'])
        self.assertEqual(self.js('PUT', '/v1/repos', {'repos': ['bad host/x']})[0], 400)

    def test_progress_writer_keeps_latest_step_and_a_capped_log(self):
        entry = {'url': 'a/b', 'status': 'running'}
        report = server.progress_writer(entry)
        report('fetch', 'running', 'reading')
        report('fetch', 'done', 'main at abc')
        report('coverage', 'running', 'django 2.2', done=3, total=9)
        p = entry['progress']
        self.assertEqual((p['steps']['fetch']['state'], p['steps']['fetch']['detail']), ('done', 'main at abc'))
        self.assertEqual((p['steps']['coverage']['done'], p['steps']['coverage']['total']), (3, 9))
        self.assertEqual([e['step'] for e in p['log']], ['fetch', 'fetch', 'coverage'])
        for _ in range(server.MAX_LOG + 20):
            report('coverage', 'running', 'x')
        self.assertEqual(len(p['log']), server.MAX_LOG)

    def test_running_scan_carries_progress_and_the_server_clock(self):
        with server._LOCK:
            server.SCANS['feedfeedfeed'] = {'id': 'feedfeedfeed', 'status': 'running', 'repos': [{'url': 'a/b', 'status': 'running'}]}
        server.progress_writer(server.SCANS['feedfeedfeed']['repos'][0])('osv', 'running', 'asking')
        try:
            got = server.get_scan('feedfeedfeed')['repos'][0]['progress']
            self.assertIn('now', got)
            self.assertEqual(got['steps']['osv']['detail'], 'asking')
        finally:
            with server._LOCK:
                del server.SCANS['feedfeedfeed']

    def test_csv_formula_guard(self):
        self.assertEqual(server._cell('=SUM(A1)'), "'=SUM(A1)")
        self.assertEqual(server._cell('safe'), 'safe')
        self.assertEqual(server._cell(None), '')


class ReuseTests(unittest.TestCase):
    """A scan can carry over the finished results of an earlier one, so only the new repositories run."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        (base / 'demo' / 'repos').mkdir(parents=True)
        (base / 'demo' / 'repos' / 'acme__app.json').write_text(json.dumps(REPO))
        (base / 'demo' / 'repos' / 'acme__other.json').write_text(json.dumps(REPO))
        (base / 'demo' / 'repos' / 'gitlab.com__grp__sub__proj.json').write_text(json.dumps(REPO))
        (base / 'demo' / 'osv.json').write_text(json.dumps(OSV))
        server.DEMO_DIR = base / 'demo'
        server.STORE = Store(base / 'data')
        server.MODE = 'demo'
        server.GITLAB_HOSTS = ['gitlab.com']
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.url = f'http://127.0.0.1:{cls.httpd.server_address[1]}'
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()
        server.SCANS.clear()                                  # the in-memory scans are module state, shared with the other classes

    def post(self, body):
        req = urllib.request.Request(self.url + '/v1/scans', data=json.dumps(body).encode(), method='POST')
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def finish(self, scan_id):
        for _ in range(50):
            with urllib.request.urlopen(f'{self.url}/v1/scans/{scan_id}', timeout=5) as r:
                scan = json.loads(r.read())['scan']
            if scan['status'] == 'done':
                return scan
            time.sleep(0.1)
        self.fail('scan did not finish')

    def run_scans(self, *bodies):
        """Posts each body in turn, waiting for it; returns the scans and the repository specs that were actually scanned."""
        real, seen, scans = server.scan_repository, [], []

        def spy(spec, *a, **k):
            seen.append(spec)
            return real(spec, *a, **k)
        with mock.patch.object(server, 'scan_repository', spy):
            for body in bodies:
                code, d = self.post(body(scans[-1]['id'] if scans else None) if callable(body) else body)
                scans.append(self.finish(d['id']) if d.get('id') else d)
        return scans, seen

    def test_only_the_new_repositories_run_and_the_new_scan_holds_all_of_them_in_order(self):
        scans, seen = self.run_scans({'repos': ['acme/app']},
                                     lambda prev: {'repos': ['https://github.com/acme/other', 'https://github.com/acme/app.git'], 'reuse': prev})
        first, second = scans
        self.assertEqual(seen, ['acme/app', 'https://github.com/acme/other'])          # app was not run a second time
        self.assertEqual([r['slug'] for r in second['repos']], ['acme/other', 'acme/app'])
        other, app = second['repos']
        self.assertEqual((other.get('reused'), app['reused'], app['reused_from']), (None, True, first['id']))
        self.assertEqual((app['scanned_at'], app['status'], app['url']), (first['repos'][0]['scanned_at'], 'done', 'https://github.com/acme/app.git'))
        self.assertEqual(app['findings'], first['repos'][0]['findings'])
        with urllib.request.urlopen(f'{self.url}/v1/scans/{second["id"]}/findings.csv', timeout=5) as r:
            csv_text = r.read().decode()
        self.assertEqual(sum('GHSA-1' in line for line in csv_text.splitlines()), 2)      # one row for each repository

    def test_a_failed_repository_runs_again(self):
        scans, seen = self.run_scans({'repos': ['acme/missing']}, lambda prev: {'repos': ['acme/missing'], 'reuse': prev})
        self.assertEqual(seen, ['acme/missing', 'acme/missing'])
        self.assertNotIn('reused', scans[1]['repos'][0])

    def test_nothing_new_starts_no_scan(self):
        before = len(json.loads(urllib.request.urlopen(self.url + '/v1/scans', timeout=5).read())['scans'])
        scans, seen = self.run_scans({'repos': ['acme/app']}, lambda prev: {'repos': ['acme/app', 'github.com/acme/app'], 'reuse': prev})
        self.assertEqual(seen, ['acme/app'])
        self.assertEqual((scans[1]['id'], scans[1]['reused']), (None, 2))
        after = len(json.loads(urllib.request.urlopen(self.url + '/v1/scans', timeout=5).read())['scans'])
        self.assertEqual(after, before + 1)                                              # only the first scan was created

    def test_a_branch_or_folder_is_a_different_repository(self):
        scans, seen = self.run_scans({'repos': ['acme/app']}, lambda prev: {'repos': ['acme/app/tree/main/svc'], 'reuse': prev})
        self.assertEqual(seen, ['acme/app', 'acme/app/tree/main/svc'])

    def test_a_bad_unknown_or_other_mode_scan_is_ignored_and_everything_runs(self):
        for reuse in ('not-an-id', '0' * 12, 123, ['x'], None):
            scans, seen = self.run_scans({'repos': ['acme/app']}, {'repos': ['acme/app'], 'reuse': reuse})
            self.assertEqual(seen, ['acme/app', 'acme/app'], reuse)
        first, _ = self.run_scans({'repos': ['acme/app']})[0][0], None
        with server._LOCK:
            server.SCANS[first['id']]['mode'] = 'live'
        scans, seen = self.run_scans({'repos': ['acme/app'], 'reuse': first['id']})
        self.assertEqual(seen, ['acme/app'])


class DotenvTests(unittest.TestCase):
    def test_first_file_wins_and_blank_values_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict('os.environ', clear=False):
            first, second = Path(tmp, 'a.env'), Path(tmp, 'b.env')
            first.write_text('T_AAP_URL=\nT_AAP_TOKEN=mine  # note\n')
            second.write_text('T_AAP_URL=https://c.example/api\r\nT_AAP_TOKEN=other\r\n')
            server.load_dotenv(first)
            server.load_dotenv(second)
            self.assertEqual(server.env('T_AAP_URL'), 'https://c.example/api')
            self.assertEqual(server.env('T_AAP_TOKEN'), 'mine')
            for k in ('T_AAP_URL', 'T_AAP_TOKEN'):
                del __import__('os').environ[k]


if __name__ == '__main__':
    unittest.main()
