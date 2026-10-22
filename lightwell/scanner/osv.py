"""
OSV.dev client: which known vulnerabilities affect a package at a version.

Two steps, the way OSV is meant to be used:
  1. POST /v1/querybatch with every distinct (ecosystem, name, version). The
     answer is only advisory ids.
  2. GET /v1/vulns/{id} once per distinct id, for severity, aliases, fixed
     versions and references.

FixtureOsv answers from a recorded file with the same interface, so demo mode
and the tests open no socket.
"""
from __future__ import annotations

import json
import math
import re
from functools import cmp_to_key
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .http import request, UpstreamError

ECOSYSTEM = {'maven': 'Maven', 'pypi': 'PyPI', 'npm': 'npm'}
BATCH = 500                                  # OSV allows 1000; stay well inside it
SEVERITY_ORDER = ['critical', 'high', 'moderate', 'low', 'unknown']


# ---------------------------------------------------------------------- CVSS

_AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
_AC = {'L': 0.77, 'H': 0.44}
_UI = {'N': 0.85, 'R': 0.62}
_CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}


def _roundup(x: float) -> float:
    n = round(x * 100000)
    return n / 100000.0 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score from a CVSS v3.0 or v3.1 vector. None for anything else."""
    if not vector.startswith('CVSS:3'):
        return None
    try:
        m = dict(p.split(':', 1) for p in vector.split('/')[1:])
        changed = m['S'] == 'C'
        pr = {'N': 0.85, 'L': 0.68 if changed else 0.62, 'H': 0.5 if changed else 0.27}[m['PR']]
        iss = 1 - (1 - _CIA[m['C']]) * (1 - _CIA[m['I']]) * (1 - _CIA[m['A']])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
        expl = 8.22 * _AV[m['AV']] * _AC[m['AC']] * pr * _UI[m['UI']]
        if impact <= 0:
            return 0.0
        total = impact + expl
        return _roundup(min(1.08 * total if changed else total, 10))
    except (KeyError, ValueError):
        return None


def severity_label(score: float | None) -> str:
    if score is None:
        return 'unknown'
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'moderate'
    if score > 0:
        return 'low'
    return 'unknown'


def _word(label: str) -> str:
    label = (label or '').strip().lower()
    return {'critical': 'critical', 'high': 'high', 'moderate': 'moderate', 'medium': 'moderate',
            'low': 'low'}.get(label, 'unknown')


def severity_of(vuln: dict) -> tuple[str, float | None, str]:
    """(label, score, vector). The CVSS v3 score wins when there is a vector, otherwise the
    database's own label (GitHub advisories carry one)."""
    vector = ''
    for s in vuln.get('severity') or []:
        if str(s.get('type', '')).upper().startswith('CVSS_V3') and s.get('score'):
            vector = str(s['score'])
            break
    if not vector:
        for s in vuln.get('severity') or []:
            if s.get('score'):
                vector = str(s['score'])
                break
    score = cvss3_score(vector) if vector else None
    if score is not None:
        return severity_label(score), score, vector
    db = (vuln.get('database_specific') or {}).get('severity')
    return _word(db or ''), None, vector


# ------------------------------------------------------------------ versions

_TOKEN = re.compile(r'\d+|[A-Za-z]+')
_PRE = {'alpha': -4, 'a': -4, 'beta': -3, 'b': -3, 'rc': -2, 'cr': -2, 'pre': -3, 'snapshot': -5, 'dev': -5, 'm': -3}
_POST = {'sp': 1, 'post': 1, 'patch': 1, 'final': 0, 'ga': 0, 'release': 0}
_ZERO = (1, 0, '')                       # what a missing trailing component counts as


def vkey(version: str) -> list:
    """Components of a Maven, PyPI or npm style version. A pre-release word (rc, beta) sorts below a
    missing component and a post-release word (sp, post) above it. An approximation, good enough
    to pick the fixed version that sits on or just above an installed one."""
    version = re.sub(r'^[vV]', '', version.strip())
    out = []
    for tok in _TOKEN.findall(version):
        if tok.isdigit():
            out.append((1, int(tok), ''))
        elif tok.lower() in _POST:
            out.append((2, _POST[tok.lower()], tok.lower()) if _POST[tok.lower()] else _ZERO)
        else:
            out.append((0, _PRE.get(tok.lower(), -1), tok.lower()))
    return out


def vcmp(a: str, b: str) -> int:
    ka, kb = vkey(a), vkey(b)
    n = max(len(ka), len(kb))
    ka += [_ZERO] * (n - len(ka))
    kb += [_ZERO] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _norm(eco: str, name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower() if eco == 'PyPI' else name


def fixed_versions(vuln: dict, eco: str, name: str, installed: str | None) -> tuple[list[str], str | None]:
    """(all fixed versions for this package, the one that applies to `installed`)."""
    fixes: list[str] = []
    applies: str | None = None
    for aff in vuln.get('affected') or []:
        pkg = aff.get('package') or {}
        if pkg.get('ecosystem') != eco or _norm(eco, pkg.get('name', '')) != _norm(eco, name):
            continue
        for rng in aff.get('ranges') or []:
            if rng.get('type') not in ('ECOSYSTEM', 'SEMVER'):
                continue
            introduced = '0'
            for ev in rng.get('events') or []:
                if 'introduced' in ev:
                    introduced = ev['introduced']
                elif 'fixed' in ev:
                    fixes.append(ev['fixed'])
                    if installed and vcmp(installed, introduced) >= 0 and vcmp(installed, ev['fixed']) < 0:
                        if applies is None or vcmp(ev['fixed'], applies) < 0:
                            applies = ev['fixed']
    fixes = sorted(set(fixes), key=cmp_to_key(vcmp))
    if applies is None and installed:
        later = [f for f in fixes if vcmp(f, installed) > 0]
        applies = later[0] if later else None
    return fixes, applies


# -------------------------------------------------------------------- client

def _summarize(vuln: dict, eco: str, name: str, version: str | None) -> dict:
    label, score, vector = severity_of(vuln)
    fixes, applies = fixed_versions(vuln, eco, name, version)
    aliases = [a for a in vuln.get('aliases') or []]
    refs = [r.get('url') for r in vuln.get('references') or [] if r.get('url')][:4]
    return {
        'id': vuln.get('id', ''),
        'aliases': aliases,
        'cve': next((a for a in [vuln.get('id', '')] + aliases if a.startswith('CVE-')), ''),
        'summary': vuln.get('summary') or (vuln.get('details') or '').split('\n', 1)[0][:200],
        'severity': label,
        'score': score,
        'vector': vector,
        'fixed_versions': fixes,
        'suggested_fix': applies,
        'published': vuln.get('published', ''),
        'url': f'https://osv.dev/vulnerability/{vuln.get("id", "")}',
        'references': refs,
    }


class OsvClient:
    def __init__(self, base_url: str = 'https://api.osv.dev', timeout: float = 20, workers: int = 8):
        self.base = base_url.rstrip('/')
        self.timeout = timeout
        self.workers = workers
        self._detail: dict[str, dict] = {}

    def _post(self, path: str, body: dict) -> dict:
        payload, _ = request('OSV.dev', f'{self.base}{path}', method='POST', body=body, timeout=self.timeout)
        return payload                                          # type: ignore[return-value]

    def _fetch(self, vid: str) -> dict:
        payload, _ = request('OSV.dev', f'{self.base}/v1/vulns/{vid}', timeout=self.timeout)
        return payload                                           # type: ignore[return-value]

    def _get_vuln(self, vid: str) -> dict:
        if vid not in self._detail:
            doc = self._fetch(vid)
            if severity_of(doc)[0] == 'unknown':
                self._borrow_severity(doc)
            self._detail[vid] = doc
        return self._detail[vid]

    def _borrow_severity(self, doc: dict) -> None:
        """PYSEC and some other advisories carry no severity while their GHSA alias does.
        Copy the alias's severity in, and say where it came from."""
        for alias in sorted(doc.get('aliases') or [], key=lambda a: not a.startswith('GHSA-')):
            if alias.startswith('CVE-'):
                continue                                         # OSV rarely holds a CVE record of its own
            try:
                other = self._fetch(alias)
            except UpstreamError:
                continue
            if severity_of(other)[0] != 'unknown':
                doc['severity'] = other.get('severity') or []
                doc['database_specific'] = {**(doc.get('database_specific') or {}),
                                            'severity': (other.get('database_specific') or {}).get('severity')}
                doc['_severity_from'] = alias
                return

    def ids_for(self, queries: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
        """queries: (ecosystem, name, version) -> advisory ids."""
        out: dict[tuple[str, str, str], list[str]] = {}
        for i in range(0, len(queries), BATCH):
            chunk = queries[i:i + BATCH]
            body = {'queries': [{'version': v, 'package': {'name': n, 'ecosystem': e}} for e, n, v in chunk]}
            results = self._post('/v1/querybatch', body).get('results') or []
            for q, res in zip(chunk, results):
                ids = [v['id'] for v in (res or {}).get('vulns') or []]
                token = (res or {}).get('next_page_token')
                while token:                                    # a package with very many advisories
                    e, n, v = q
                    page = self._post('/v1/query', {'version': v, 'package': {'name': n, 'ecosystem': e},
                                                    'page_token': token})
                    ids += [x['id'] for x in page.get('vulns') or []]
                    token = page.get('next_page_token')
                out[q] = ids
        return out

    def details(self, ids: list[str]) -> dict[str, dict]:
        todo = [i for i in dict.fromkeys(ids) if i not in self._detail]
        if todo:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                list(pool.map(self._get_vuln, todo))
        return {i: self._detail[i] for i in dict.fromkeys(ids)}

    def lookup(self, components: list) -> dict[tuple[str, str, str], list[dict]]:
        """Findings for every pinned component. Key is (ecosystem, name, version)."""
        queries = list(dict.fromkeys(
            (ECOSYSTEM[c.ecosystem], c.name, c.version) for c in components
            if c.version and c.ecosystem in ECOSYSTEM))
        ids = self.ids_for(queries)
        docs = self.details([i for v in ids.values() for i in v])
        return {q: [_summarize(docs[i], q[0], q[1], q[2]) for i in vids if i in docs]
                for q, vids in ids.items()}


class FixtureOsv:
    """Same interface, answers from demo/osv.json. Opens no socket."""

    def __init__(self, path: Path):
        data = json.loads(Path(path).read_text()) if Path(path).exists() else {}
        self.queries = data.get('queries', {})
        self.vulns = data.get('vulns', {})
        self.missing: list[str] = []

    def lookup(self, components: list) -> dict[tuple[str, str, str], list[dict]]:
        out = {}
        for c in components:
            if not c.version or c.ecosystem not in ECOSYSTEM:
                continue
            q = (ECOSYSTEM[c.ecosystem], c.name, c.version)
            key = '|'.join(q)
            if key not in self.queries:
                self.missing.append(key)
                out[q] = []
                continue
            out[q] = [_summarize(self.vulns[i], *q) for i in self.queries[key] if i in self.vulns]
        return out


class RecordingOsv(OsvClient):
    """Live client that also keeps the raw answers, for building demo/osv.json."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.recorded_queries: dict[str, list[str]] = {}

    def ids_for(self, queries):
        out = super().ids_for(queries)
        for q, ids in out.items():
            self.recorded_queries['|'.join(q)] = ids
        return out

    def snapshot(self) -> dict:
        used = {i for ids in self.recorded_queries.values() for i in ids}
        return {'queries': self.recorded_queries, 'vulns': {i: slim(self._detail[i]) for i in used if i in self._detail}}


def slim(doc: dict) -> dict:
    """Keep only what the scanner reads, so the recorded file stays small enough to commit."""
    out = {'id': doc.get('id', ''), 'aliases': doc.get('aliases') or [], 'summary': doc.get('summary', ''),
           'details': (doc.get('details') or '').split('\n', 1)[0][:300],
           'severity': doc.get('severity') or [], 'published': doc.get('published', ''),
           'references': [{'url': r['url']} for r in (doc.get('references') or []) if r.get('url')][:4],
           'affected': [{'package': {'ecosystem': (a.get('package') or {}).get('ecosystem'),
                                     'name': (a.get('package') or {}).get('name')},
                         'ranges': [r for r in a.get('ranges') or [] if r.get('type') in ('ECOSYSTEM', 'SEMVER')]}
                        for a in doc.get('affected') or []]}
    label = (doc.get('database_specific') or {}).get('severity')
    if label:
        out['database_specific'] = {'severity': label}
    if doc.get('_severity_from'):
        out['_severity_from'] = doc['_severity_from']
    return out
