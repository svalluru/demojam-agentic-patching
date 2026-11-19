"""Containers: the third side of the console. Red Hat Advanced Cluster Security (ACS) says which running images carry
a CVE; the fix is never applied in place: rebuild the image (a Lightwell jar, or a newer UBI base), scan it, sign it,
roll it out lab first and production after approval, and let ACS rescan.

Intake does not poll every image. Three sources:
  1. From the fix: each Lightwell build in the Applications inbox becomes one targeted ACS query (component and
     version) across every cluster on that Central.
  2. Pushed by ACS: a policy notifier (generic webhook) posts violations to /api/ctr/webhook.
  3. Reconcile: one narrow query (fixable, important or critical), capped, for base-image fixes.

Demo mode answers the same ACS API calls from fixtures in the same JSON shapes, so the parsing below is the code that
runs against a real Central (ACS_URL, ACS_TOKEN). The run itself is a demo simulator until an AO workflow and AAP
templates exist for containers; live mode says so instead of pretending.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any

import appv2


class _Hooks:
    env = staticmethod(lambda k, d='': d)
    demo_mode = staticmethod(lambda: True)
    demo_pause = staticmethod(lambda f=1.0: time.sleep(0.35 * f))
    llm = None                 # prompt -> text (the console's vLLM)
    rag_search = None          # (store, query) -> [text] (the console's history search)
    acs_call = None            # tests: (method, path, params, body) -> dict


H = _Hooks()


def configure(**kw) -> None:
    for k, v in kw.items():
        setattr(H, k, v)


def env(key: str, default: str = '') -> str:
    return (H.env(key, default) or default).strip()


now_iso = appv2.now_iso


class AcsError(RuntimeError):
    pass


# ---------------------------------------------------------------------------- demo fixtures (ACS API shapes)

UBI_FIX = 'registry.access.redhat.com/ubi9/ubi-minimal@sha256:' + hashlib.sha256(b'ubi9-minimal-9.5').hexdigest()
DEMO_CLUSTER = {'id': 'c-x8v2s', 'name': 'cluster-x8v2s'}


def _vuln(cve: str, cvss: float, fixed: str, sev: str = 'IMPORTANT_VULNERABILITY_SEVERITY') -> dict:
    return {'cve': cve, 'cvss': cvss, 'fixedBy': fixed, 'severity': sev}


_SPRING = ['CVE-2023-20860', 'CVE-2024-38816', 'CVE-2024-38819', 'CVE-2024-38828', 'CVE-2025-41242',
           'CVE-2026-22735', 'CVE-2026-22737', 'CVE-2026-22741', 'CVE-2026-22745']
DEMO_IMAGES = {
    'sha256:wf142': {'name': {'registry': 'quay.io', 'remote': 'telco/workflow-engine', 'tag': '1.4.2',
                              'fullName': 'quay.io/telco/workflow-engine:1.4.2'},
                     'base': 'registry.access.redhat.com/ubi9/ubi-minimal:9.4',
                     'components': [
                         {'name': 'spring-webmvc', 'version': '5.3.18', 'source': 'JAVA',
                          'vulns': [_vuln(c, 8.1 if i == 1 else 6.5, '6.2.19') for i, c in enumerate(_SPRING)]},
                         {'name': 'spring-expression', 'version': '5.3.18', 'source': 'JAVA',
                          'vulns': [_vuln(c, 6.5, '6.2.19') for c in ('CVE-2023-20861', 'CVE-2023-20863', 'CVE-2024-38808')]},
                         {'name': 'spring-core', 'version': '5.3.18', 'source': 'JAVA',
                          'vulns': [_vuln('CVE-2025-41249', 5.9, '6.2.19')]},
                         {'name': 'openssl-libs', 'version': '3.0.7-27.el9', 'source': 'OS',
                          'vulns': [_vuln('CVE-2024-5535', 7.4, '3.2.2-6.el9_5'), _vuln('CVE-2024-6119', 7.5, '3.2.2-6.el9_5')]}]},
    'sha256:inv201': {'name': {'registry': 'quay.io', 'remote': 'telco/inventory-service', 'tag': '2.0.1',
                               'fullName': 'quay.io/telco/inventory-service:2.0.1'},
                      'base': 'registry.access.redhat.com/ubi9/ubi-minimal:9.4',
                      'components': [
                          {'name': 'json', 'version': '20220320', 'source': 'JAVA', 'vulns': [_vuln('CVE-2022-45688', 7.5, '20230227')]},
                          {'name': 'json-path', 'version': '2.8.0', 'source': 'JAVA', 'vulns': [_vuln('CVE-2023-51074', 5.3, '2.9.0')]},
                          {'name': 'woodstox-core', 'version': '6.0.3', 'source': 'JAVA', 'vulns': [_vuln('CVE-2022-40152', 6.5, '6.4.0')]},
                          {'name': 'glibc', 'version': '2.34-100.el9', 'source': 'OS', 'vulns': [_vuln('CVE-2024-33599', 7.6, '2.34-125.el9_5')]}]},
    'sha256:ric093': {'name': {'registry': 'quay.io', 'remote': 'telco/ric-xapp', 'tag': '0.9.3',
                               'fullName': 'quay.io/telco/ric-xapp:0.9.3'},
                      'base': 'registry.access.redhat.com/ubi9/python-311:1',
                      'components': [{'name': 'ricxappframe', 'version': '3.2.1', 'source': 'PYTHON',
                                      'vulns': [_vuln('CVE-2025-1111', 5.0, ''), _vuln('CVE-2025-1112', 4.3, ''), _vuln('CVE-2025-1113', 4.0, '')]}]},
}
DEMO_DEPLOYMENTS = {
    'd-wf-lab': {'name': 'workflow-engine', 'namespace': 'nfvo-lab', 'image': 'sha256:wf142', 'replicas': 1, 'labels': {'env': 'lab'}},
    'd-wf-prod': {'name': 'workflow-engine', 'namespace': 'nfvo-prod', 'image': 'sha256:wf142', 'replicas': 3, 'labels': {'env': 'prod'}},
    'd-inv-lab': {'name': 'inventory-service', 'namespace': 'oss-lab', 'image': 'sha256:inv201', 'replicas': 1, 'labels': {'env': 'lab'}},
    'd-inv-prod': {'name': 'inventory-service', 'namespace': 'oss-prod', 'image': 'sha256:inv201', 'replicas': 2, 'labels': {'env': 'prod'}},
    'd-ric': {'name': 'ric-xapp', 'namespace': 'ric', 'image': 'sha256:ric093', 'replicas': 2, 'labels': {'env': 'prod'}},
}
DEMO_ALERTS = {'d-wf-prod': [{'policy': {'name': 'Shell Spawned by Java Application', 'severity': 'HIGH_SEVERITY'},
                              'lifecycleStage': 'RUNTIME', 'time': '2026-11-18T09:12:00Z',
                              'violations': [{'message': '/bin/sh executed in workflow-engine-7d9f (outside the process baseline)'}]}]}
DEMO_CALLERS = {'d-wf-lab': ['order-portal (lab)'], 'd-wf-prod': ['order-portal', 'service-assurance', 'inventory-service'],
                'd-inv-lab': ['workflow-engine (lab)'], 'd-inv-prod': ['workflow-engine', 'order-portal'], 'd-ric': ['near-rt-ric']}
DEMO_WINDOWS = {'nfvo-prod': '00:00-04:00 America/Chicago', 'oss-prod': '01:00-05:00 America/New_York', 'ric': '02:00-03:00 UTC'}
DEMO_REASONING = {
    'd-wf-prod': 'The last rollout here needed a 60 s readiness window while 340 NETCONF sessions reconnected; a runtime '
                 'alert is open on this deployment, so it goes first once the lab is clean. Roll one pod at a time '
                 '(maxUnavailable 1): the order portal retries, assurance pauses closed-loop actions for about 3 minutes.',
    'd-wf-lab': 'Lab copy, no live traffic: roll out first and compare the rescan with production.',
    'd-inv-prod': 'Two replicas: a rolling update keeps one serving. Topology sync pauses for about a minute.',
    'd-inv-lab': 'Lab copy, safe to roll out at any time.',
}
DEMO_NODES = [['Node', 'cluster-x8v2s-master-0 · RHCOS 4.19.3', 'kernel: 2 CVEs', 'Fixed in OpenShift 4.19.5 (cluster update)'],
              ['Platform', 'OpenShift 4.19.3', 'kube-apiserver: 1 CVE', 'Fixed in OpenShift 4.19.5']]


def _q(params: dict) -> dict[str, list[str]]:
    """An ACS search query ('Component:x+Component Version:y') -> {field: [values]}."""
    out: dict[str, list[str]] = {}
    for part in (params.get('query') or '').split('+'):
        if ':' in part:
            k, v = part.split(':', 1)
            out.setdefault(k.strip().lower(), []).extend(x.strip() for x in v.split(','))
    return out


def _demo_api(method: str, path: str, params: dict, body: Any) -> dict:
    q = _q(params)
    if path == '/v1/images':
        comp, ver = q.get('component', []), q.get('component version', [])
        fixable = q.get('fixable') == ['true']
        rows = []
        for iid, img in DEMO_IMAGES.items():
            cs = img['components']
            if comp and not any(c['name'] in comp and (not ver or c['version'] in ver) for c in cs):
                continue
            vulns = [v for c in cs for v in c['vulns']]
            if fixable and not any(v['fixedBy'] for v in vulns):
                continue
            rows.append({'id': iid, 'name': img['name']['fullName'], 'cves': len(vulns),
                         'fixableCves': sum(1 for v in vulns if v['fixedBy'])})
        return {'images': rows}
    if path.startswith('/v1/images/'):
        img = DEMO_IMAGES.get(path.rsplit('/', 1)[1])
        if not img:
            raise AcsError(f'ACS: no image {path}')
        return {'id': path.rsplit('/', 1)[1], 'name': img['name'],
                'metadata': {'v1': {'labels': {'base': img['base']}}},
                'scan': {'components': [{'name': c['name'], 'version': c['version'], 'source': c['source'],
                                         'vulns': c['vulns']} for c in img['components']]}}
    if path == '/v1/deployments':
        sha = q.get('image sha', [])
        return {'deployments': [{'id': did, 'name': d['name'], 'namespace': d['namespace'],
                                 'clusterName': DEMO_CLUSTER['name'], 'clusterId': DEMO_CLUSTER['id']}
                                for did, d in DEMO_DEPLOYMENTS.items() if not sha or d['image'] in sha]}
    if path.startswith('/v1/deployments/'):
        d = DEMO_DEPLOYMENTS.get(path.rsplit('/', 1)[1])
        if not d:
            raise AcsError(f'ACS: no deployment {path}')
        return {'id': path.rsplit('/', 1)[1], 'name': d['name'], 'namespace': d['namespace'],
                'clusterName': DEMO_CLUSTER['name'], 'clusterId': DEMO_CLUSTER['id'], 'replicas': d['replicas'],
                'labels': d['labels'], 'containers': [{'image': {'id': d['image'],
                                                                 'name': DEMO_IMAGES[d['image']]['name']}}]}
    if path == '/v1/alerts':
        did = (q.get('deployment id') or [''])[0]
        return {'alerts': [dict(a, deployment={'id': did}) for a in DEMO_ALERTS.get(did, [])]}
    if path == '/v2/vulnerability-exceptions/deferral' and method == 'POST':
        return {'exception': {'id': 'def-' + uuid.uuid4().hex[:6], 'status': 'PENDING', **(body or {})}}
    raise AcsError(f'ACS demo: {method} {path} is not staged')


def acs_call(method: str, path: str, params: dict | None = None, body: Any = None) -> dict:
    """One ACS Central API call. Demo: the fixtures above. Live: ACS_URL with an API token (ACS_TOKEN)."""
    params = {k: v for k, v in (params or {}).items() if v not in (None, '')}
    if H.acs_call:
        return H.acs_call(method, path, params, body)
    if H.demo_mode():
        return _demo_api(method, path, params, body)
    base, token = env('ACS_URL').rstrip('/'), env('ACS_TOKEN')
    if not (base and token):
        raise AcsError('ACS is not configured: set ACS_URL (the Central route) and ACS_TOKEN (an API token)')
    url = base + path + ('?' + urllib.parse.urlencode(params) if params else '')
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json',
                                          'Accept': 'application/json'})
    ctx = ssl.create_default_context(cafile=env('SSL_CERT_FILE') or None)
    if env('ACS_VERIFY_TLS', 'true').lower() in ('false', '0', 'no'):
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            raw = r.read().decode() or '{}'
    except urllib.error.HTTPError as e:
        raise AcsError(f'ACS {method} {path}: HTTP {e.code} {e.read().decode(errors="replace")[:200]}') from e
    except OSError as e:
        raise AcsError(f'ACS {method} {path}: {e}') from e
    return json.loads(raw)


def acs_get(path: str, **params) -> dict:
    return acs_call('GET', path, params)


# ---------------------------------------------------------------------------- intake: fixes

_WEBHOOK: list[dict] = []          # policy violations ACS pushed
_FIX_CACHE: dict[str, Any] = {}


def _image_app(full_name: str) -> str:
    """quay.io/telco/workflow-engine:1.4.2 -> workflow-engine (the BOM app name, for the Applications cross-link)."""
    return full_name.rsplit('/', 1)[-1].split('@')[0].split(':')[0]


def _image_detail(iid: str) -> dict:
    d = acs_get(f'/v1/images/{iid}')
    name = d.get('name') or {}
    return {'id': d.get('id', iid), 'name': name.get('fullName') or str(name), 'components': (d.get('scan') or {}).get('components') or [],
            'base': (((d.get('metadata') or {}).get('v1') or {}).get('labels') or {}).get('base', '')}


def _lightwell_fixes() -> list[dict]:
    out = []
    for ev in appv2.events().all():
        comp, up = ev['artifact'], appv2.upstream(ev['version'])
        found = []
        for ver in dict.fromkeys([up, appv2._canon(up)]):         # org.json: 20220320 in the jar, 20220320.0.0 at Lightwell
            found = acs_get('/v1/images', query=f'Component:{comp}+Component Version:{ver}', pagination_limit=50).get('images') or []
            if found:
                break
        if found:
            out.append({'id': f"lw-{ev['id']}", 'kind': 'lightwell', 'component': comp, 'from': up, 'to': ev['version'],
                        'cves': list(ev.get('cves') or []), 'source': 'Lightwell build in Nexus → ACS query',
                        'images': [{'id': i['id'], 'name': i['name']} for i in found]})
    return out


def _base_fixes() -> list[dict]:
    """The reconcile query: fixable images (capped), whose OS packages a newer UBI fixes."""
    rows = acs_get('/v1/images', query='Fixable:true', pagination_limit=int(env('CTR_RECONCILE_LIMIT', '50'))).get('images') or []
    imgs, cves = [], []
    for r in rows:
        d = _image_detail(r['id'])
        os_v = [v for c in d['components'] if c.get('source') == 'OS' for v in c.get('vulns') or [] if v.get('fixedBy')]
        if os_v:
            imgs.append({'id': d['id'], 'name': d['name'], 'base': d['base']})
            cves += [v['cve'] for v in os_v if v['cve'] not in cves]
    if not imgs:
        return []
    return [{'id': 'base-ubi9', 'kind': 'base', 'component': 'UBI base image', 'from': imgs[0].get('base') or 'ubi9',
             'to': env('CTR_UBI_IMAGE', UBI_FIX), 'cves': cves, 'source': 'ACS reconcile (fixable OS packages)',
             'images': [{'id': i['id'], 'name': i['name']} for i in imgs]}]


def fixes() -> dict:
    """Everything the Containers inbox lists: Lightwell builds found in running images, base-image fixes, and the
    policy violations ACS pushed. Kept for a minute live (each is an ACS query)."""
    hit = _FIX_CACHE.get('v')
    if not H.demo_mode() and hit and time.time() - hit[0] < 60:
        return hit[1]
    out = {'ok': True, 'source': 'demo' if H.demo_mode() else 'acs', 'fixes': [], 'errors': [],
           'cluster': DEMO_CLUSTER['name'] if H.demo_mode() else env('ACS_URL'), 'nodes': DEMO_NODES if H.demo_mode() else []}
    for part in (_lightwell_fixes, _base_fixes):
        try:
            out['fixes'] += part()
        except AcsError as e:
            out['errors'].append(str(e))
    out['fixes'] += list(_WEBHOOK)
    out['ok'] = not out['errors'] or bool(out['fixes'])
    _FIX_CACHE['v'] = (time.time(), out)
    return out


def accept_webhook(body: bytes, token: str = '') -> tuple[int, dict]:
    """An ACS generic-webhook notifier: one alert (policy violation). CTR_WEBHOOK_TOKEN, when set, must match the
    header ACS is configured to send."""
    want = env('CTR_WEBHOOK_TOKEN')
    if want and token != want:
        return 401, {'ok': False, 'error': 'bad webhook token'}
    if not want and not H.demo_mode():
        return 503, {'ok': False, 'error': 'CTR_WEBHOOK_TOKEN is not set, so no webhook is trusted'}
    try:
        a = (json.loads(body or b'{}').get('alert')) or {}
    except ValueError:
        return 400, {'ok': False, 'error': 'not JSON'}
    pol, dep = a.get('policy') or {}, a.get('deployment') or {}
    imgs = [{'id': (c.get('image') or {}).get('id', ''), 'name': ((c.get('image') or {}).get('name') or {}).get('fullName', '')}
            for c in dep.get('containers') or []]
    if not pol.get('name') or not imgs:
        return 400, {'ok': False, 'error': 'expected an alert with a policy and a deployment with containers'}
    fid = 'pol-' + hashlib.sha1(f"{pol['name']}|{dep.get('id', '')}".encode()).hexdigest()[:10]
    if not any(f['id'] == fid for f in _WEBHOOK):
        _WEBHOOK.append({'id': fid, 'kind': 'policy', 'component': pol['name'], 'from': '', 'to': '',
                         'cves': [], 'source': f"ACS policy violation · {dep.get('namespace', '')}/{dep.get('name', '')}",
                         'detail': '; '.join(v.get('message', '') for v in a.get('violations') or [])[:300], 'images': imgs})
    _FIX_CACHE.clear()
    return 200, {'ok': True, 'fix': fid}


# ---------------------------------------------------------------------------- run state

STAGES = ['assess', 'plan', 'build', 'lab', 'gate', 'prod', 'verify']
STEPS = ['commit', 'build_scan', 'sign', 'deploy', 'health', 'approval', 'verify', 'notify']
_LOCK = threading.Lock()
_RUN: dict[str, Any] = {'status': 'idle'}
_HISTORY: list[dict] = []
BUSY = ('assessing', 'generating', 'running', 'awaiting_approval')


def state() -> dict:
    with _LOCK:
        return json.loads(json.dumps(_RUN))


def _set(**kw) -> None:
    with _LOCK:
        _RUN.update(kw)


def _trace(msg: str) -> None:
    with _LOCK:
        _RUN.setdefault('events', []).append({'at': now_iso(), 'msg': msg})


def reset() -> tuple[int, dict]:
    with _LOCK:
        if _RUN.get('status') in ('running',):
            return 409, {'ok': False, 'error': 'a run is in progress'}
        _RUN.clear()
        _RUN['status'] = 'idle'
    return 200, {'ok': True}


def _servers_patched(app: str, component: str) -> dict | None:
    """The newest Applications run that patched this app's servers with this library: the servers are fixed, the
    image is not."""
    for r in appv2.runs():
        arts = (r.get('artifacts') or {}).get(app) or []
        patched = [h for h in r.get('hosts') or [] if h.get('app') == app and h.get('outcome') == 'patched']
        if component in arts and patched:
            return {'run_id': r.get('run_id'), 'patched': len(patched), 'mode': r.get('test_mode', 'swap'),
                    'version': (r.get('event') or {}).get('version', '')}
    return None


def _risk(fix: dict, prod: bool, runtime: bool, replicas: int) -> tuple[int, str]:
    score = 35 + min(30, 4 * len(fix.get('cves') or [])) + (15 if prod else 0) + (15 if runtime else 0) + (5 if replicas > 2 else 0)
    why = [f"{len(fix.get('cves') or [])} CVEs"] + (['production'] if prod else []) + (['runtime alert open'] if runtime else []) \
        + ([f'{replicas} replicas'] if replicas > 2 else [])
    return min(100, score), ', '.join(why)


def _reasoning(t: dict, fix: dict) -> tuple[str, str]:
    if H.demo_mode():
        return DEMO_REASONING.get(t['deployment_id']) or 'No rollout history for this deployment yet.', 'demo'
    facts = (f"{t['namespace']}/{t['name']} on {t['cluster']} ({t['env']}, {t['replicas']} replicas). Callers: "
             f"{', '.join(t['callers']) or 'unknown'}. Window: {t['window'] or 'any time'}. "
             f"{'Runtime alert: ' + t['runtime'] if t['runtime'] else ''}")
    store = env('CTR_VECTOR_DB_ID')
    hist = []
    if store and H.rag_search:
        try:
            hist = H.rag_search(store, f"{t['name']} {t['namespace']} rollout")[:3]
        except Exception:
            hist = []
    if H.llm:
        try:
            text = H.llm(f"You plan a container rollout for {fix['component']} ({len(fix.get('cves') or [])} CVEs).\n"
                         f"Facts: {facts}\nPast rollouts:\n" + '\n'.join(hist or ['none']) +
                         "\nIn at most 60 words: who is affected, what to check first, and whether to go now.")
            if text and text.strip():
                return text.strip()[:600], 'rag+llm' if hist else 'llm'
        except Exception:
            pass
    return facts, 'rules'


def start_assess(fix_id: str) -> tuple[int, dict]:
    if state().get('status') in BUSY:
        return 409, {'ok': False, 'error': 'a containers run is open: finish or reset it first'}
    try:
        fix = next((f for f in fixes()['fixes'] if f['id'] == fix_id), None)
    except AcsError as e:
        return 503, {'ok': False, 'error': str(e)}
    if not fix:
        return 404, {'ok': False, 'error': f'no fix {fix_id}'}
    with _LOCK:
        _RUN.clear()
        _RUN.update(status='assessing', run_id=uuid.uuid4().hex[:8], fix=fix, started_at=now_iso(), events=[],
                    stages={k: 'pending' for k in STAGES}, simulated=bool(H.demo_mode()))
        _RUN['stages']['assess'] = 'active'
    threading.Thread(target=_assess, args=(fix,), daemon=True).start()
    return 200, {'ok': True}


def _assess(fix: dict) -> None:
    try:
        targets = []
        for img in fix['images']:
            _trace(f"ACS: deployments running {img['name']}")
            for d in acs_get('/v1/deployments', query=f"Image Sha:{img['id']}").get('deployments') or []:
                dd = acs_get(f"/v1/deployments/{d['id']}")
                ns = dd.get('namespace', '')
                envname = (dd.get('labels') or {}).get('env') or ('prod' if 'prod' in ns else 'lab')
                alerts = [a for a in acs_get('/v1/alerts', query=f"Deployment Id:{d['id']}").get('alerts') or []
                          if a.get('lifecycleStage') == 'RUNTIME']
                runtime = (alerts[0].get('violations') or [{}])[0].get('message', '') if alerts else ''
                t = {'key': f"{dd.get('clusterName', '')}/{ns}/{dd.get('name', '')}", 'deployment_id': d['id'],
                     'cluster': dd.get('clusterName', ''), 'namespace': ns, 'name': dd.get('name', ''),
                     'env': envname, 'replicas': int(dd.get('replicas') or 1), 'image': img['name'], 'image_id': img['id'],
                     'runtime': runtime, 'callers': DEMO_CALLERS.get(d['id'], []) if H.demo_mode() else [],
                     'window': DEMO_WINDOWS.get(ns, '') if H.demo_mode() else json.loads(env('CTR_WINDOWS', '{}') or '{}').get(ns, '')}
                t['risk'], t['risk_why'] = _risk(fix, envname == 'prod', bool(runtime), t['replicas'])
                t['reasoning'], t['reasoning_source'] = _reasoning(t, fix)
                targets.append(t)
            H.demo_pause(0.5)
        targets.sort(key=lambda t: (t['env'] == 'prod', -t['risk']))
        servers = []
        if fix['kind'] == 'lightwell':
            for app in sorted({_image_app(i['name']) for i in fix['images']}):
                sp = _servers_patched(app, fix['component'])
                if sp:
                    servers.append(dict(sp, app=app))
        _set(status='assessed', impact={'targets': targets, 'servers': servers}, selected=[t['key'] for t in targets])
        with _LOCK:
            _RUN['stages']['assess'] = 'done'
        _trace(f'{len(targets)} deployment(s) run the affected image(s)')
    except AcsError as e:
        _set(status='failed', error=str(e))


# ---------------------------------------------------------------------------- plan and checks

ALLOWED_FILES = re.compile(r'^(pom\.xml|Containerfile|gitops/[\w.-]+/[\w.-]+/[\w.-]+/kustomization\.yaml)$')
PINNED = re.compile(r'@sha256:([0-9a-f]{64}|\$\{BUILD_DIGEST\})$')


def build_change(fix: dict, targets: list[dict]) -> list[dict]:
    """The change for each image: pom.xml to the Lightwell build, the base to a pinned UBI digest, and each
    deployment's GitOps image reference to the digest the build produces."""
    edits = []
    if fix['kind'] == 'lightwell':
        edits.append({'file': 'pom.xml', 'what': f"{fix['component']} version", 'from': fix['from'], 'to': fix['to']})
    if fix['kind'] == 'base':
        edits.append({'file': 'Containerfile', 'what': 'FROM', 'from': f"FROM {fix['from']}", 'to': f"FROM {fix['to']}"})
    for t in targets:
        repo = t['image'].split('@')[0].rsplit(':', 1)[0]
        edits.append({'file': f"gitops/{t['cluster']}/{t['namespace']}/{t['name']}/kustomization.yaml", 'what': 'image',
                      'from': t['image'], 'to': f'{repo}@sha256:${{BUILD_DIGEST}}'})
    return edits


def check_container_change(edits: list[dict]) -> list[dict]:
    """The system's checks on a drafted change, before anything is built: only the files a fix may touch, a
    Lightwell build for a pom change, and pinned digests for every image reference."""
    files = [e['file'] for e in edits]
    bad_files = [f for f in files if not ALLOWED_FILES.match(f)]
    poms = [e for e in edits if e['file'] == 'pom.xml']
    froms = [e for e in edits if e['file'] == 'Containerfile']
    gitops = [e for e in edits if e['file'].startswith('gitops/')]
    allowed_reg = [r.strip() for r in env('CTR_ALLOWED_REGISTRIES', 'registry.access.redhat.com,registry.redhat.io').split(',') if r.strip()]
    return [
        {'id': 'files', 'ok': not bad_files, 'detail': 'only pom.xml, the Containerfile and GitOps image references'
         if not bad_files else f'unexpected file(s): {", ".join(bad_files)}'},
        {'id': 'lightwell', 'ok': all(appv2.is_lightwell(e['to']) for e in poms),
         'detail': 'pom.xml moves to a Lightwell build of the same version' if poms else 'no pom.xml change'},
        {'id': 'base', 'ok': all(PINNED.search(e['to']) and e['to'].split()[-1].split('/')[0] in allowed_reg for e in froms),
         'detail': 'the base image is pinned by digest, from a Red Hat registry' if froms else 'no base-image change'},
        {'id': 'pinned', 'ok': bool(gitops) and all(PINNED.search(e['to']) for e in gitops),
         'detail': 'every deployment gets the built image by digest, never a tag'},
    ]


def start_generate(keys: list[str] | None = None) -> tuple[int, dict]:
    st = state()
    if st.get('status') != 'assessed':
        return 409, {'ok': False, 'error': 'assess a fix first'}
    targets = [t for t in st['impact']['targets'] if keys is None or t['key'] in keys]
    if not targets:
        return 400, {'ok': False, 'error': 'no deployment selected'}
    edits = build_change(st['fix'], targets)
    checks = check_container_change(edits)
    with _LOCK:
        _RUN.update(status='generated', selected=[t['key'] for t in targets], change=edits, checks=checks,
                    ok=all(c['ok'] for c in checks))
        _RUN['stages']['plan'] = 'done'
    return 200, {'ok': True}


# ---------------------------------------------------------------------------- run (demo simulator)

def start_dispatch() -> tuple[int, dict]:
    st = state()
    if st.get('status') != 'generated':
        return 409, {'ok': False, 'error': 'prepare the change first'}
    if not st.get('ok'):
        return 400, {'ok': False, 'error': 'the change failed its checks'}
    if not H.demo_mode():
        return 503, {'ok': False, 'error': 'The container run is not set up on this lab yet (AO workflow "Container Patch" '
                     'and its AAP templates). Intake and assessment read ACS live; the run is shown in demo mode.'}
    sel = set(st['selected'])
    hosts = [dict(t, outcome='pending', steps={}, detail='') for t in st['impact']['targets'] if t['key'] in sel]
    _set(status='running', hosts=hosts)
    threading.Thread(target=_simulate, daemon=True).start()
    return 200, {'ok': True}


def _step(key: str, step: str, value: str, outcome: str | None = None, detail: str | None = None) -> None:
    with _LOCK:
        for h in _RUN.get('hosts') or []:
            if h['key'] == key:
                h['steps'][step] = value
                if outcome:
                    h['outcome'] = outcome
                if detail is not None:
                    h['detail'] = detail


def _stage(name: str, value: str) -> None:
    with _LOCK:
        _RUN['stages'][name] = value


def _simulate() -> None:
    st = state()
    fix, hosts = st['fix'], st['hosts']
    _stage('build', 'active')
    for img in dict.fromkeys(h['image'] for h in hosts):
        mine = [h for h in hosts if h['image'] == img]
        for step, msg in (('commit', 'commit the change to Gitea'), ('build_scan', 'build and roxctl image check: 0 fixable critical'),
                          ('sign', 'cosign sign, push to Quay')):
            for h in mine:
                _step(h['key'], step, 'active', 'running')
            H.demo_pause(0.6)
            for h in mine:
                _step(h['key'], step, 'done')
            _trace(f'{img}: {msg}')
    _stage('build', 'done')
    for h in hosts:
        if h['env'] == 'prod':
            continue
        _rollout(h, fix)
    _stage('lab', 'done')
    prod = [h for h in hosts if h['env'] == 'prod']
    if prod:
        for h in prod:
            _step(h['key'], 'approval', 'waiting', 'awaiting_approval', 'lab rolled out and verified; waiting for approval')
        _stage('gate', 'active')
        _set(status='awaiting_approval')
        _trace(f'{len(prod)} production deployment(s) wait for approval')
        return
    _finish()


def _rollout(h: dict, fix: dict) -> None:
    for step in ('deploy', 'health', 'verify', 'notify'):
        _step(h['key'], step, 'active', 'running')
        H.demo_pause(0.5)
        _step(h['key'], step, 'done')
    gone = len(fix.get('cves') or [])
    _step(h['key'], 'verify', 'done', 'patched', f'running the new digest; ACS rescan: {gone} CVE{"s" if gone != 1 else ""} gone')
    _trace(f"{h['key']}: rolled out and verified")


def decide(key: str, decision: str) -> tuple[int, dict]:
    if decision not in ('approved', 'rejected'):
        return 400, {'ok': False, 'error': 'decision is approved or rejected'}
    st = state()
    h = next((x for x in st.get('hosts') or [] if x['key'] == key), None)
    if not h or h.get('outcome') != 'awaiting_approval':
        return 409, {'ok': False, 'error': f'{key} is not waiting for approval'}
    if decision == 'approved':
        _step(key, 'approval', 'done', 'running', '')
        threading.Thread(target=_after_approve, args=(h, st['fix']), daemon=True).start()
    else:
        expiry = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 30 * 86400))
        req = {'cves': list(st['fix'].get('cves') or []),
               'scope': {'imageScope': {'remote': h['image'].split('/', 1)[-1].split(':')[0], 'tag': h['image'].rsplit(':', 1)[-1]}},
               'comment': 'Rejected at the console gate: rebuild planned for the next window',
               'exceptionExpiry': {'expiryType': 'TIME', 'expiresOn': expiry}}
        try:
            res = acs_call('POST', '/v2/vulnerability-exceptions/deferral', body=req)
            ref = (res.get('exception') or {}).get('id', '')
        except AcsError as e:
            ref = f'not filed: {e}'
        _step(key, 'approval', 'rejected', 'deferred', f'deferred in ACS until {expiry} ({ref})')
        with _LOCK:
            _RUN.setdefault('deferrals', []).append({'key': key, 'request': req, 'ref': ref})
        _settle()
    return 200, {'ok': True}


def _after_approve(h: dict, fix: dict) -> None:
    _rollout(h, fix)
    _settle()


def _settle() -> None:
    st = state()
    if all(x['outcome'] in ('patched', 'deferred', 'failed') for x in st.get('hosts') or []):
        _finish()


def _finish() -> None:
    with _LOCK:
        hosts = _RUN.get('hosts') or []
        _RUN['summary'] = {k: sum(1 for h in hosts if h['outcome'] == k) for k in ('patched', 'deferred', 'failed')}
        _RUN['status'] = 'complete'
        _RUN['finished_at'] = now_iso()
        for s in ('gate', 'prod', 'verify'):
            _RUN['stages'][s] = 'done'
        rec = json.loads(json.dumps(_RUN))
    _HISTORY.append({k: rec.get(k) for k in ('run_id', 'fix', 'started_at', 'finished_at', 'summary', 'simulated')})


def runs() -> list[dict]:
    return list(reversed(_HISTORY))
