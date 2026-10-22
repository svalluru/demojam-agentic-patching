"""
Scan one repository: manifests -> components -> OSV findings, in a plain dict that is
safe to store as JSON and to hand straight to the page.
"""
from __future__ import annotations

import copy
from datetime import date, datetime, timezone
from functools import cmp_to_key

from .http import UpstreamError
from .lightwell import UnconfiguredCatalog
from .osv import ECOSYSTEM, SEVERITY_ORDER, vcmp
from .parse import Component, manifest_kind, parse_manifest
from .pom import PomResolver
from .repo import parse_repo

MAX_UNEVALUATED = 200
_VKEY = cmp_to_key(vcmp)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _match_detail(detail: dict, vulns: list[dict]) -> dict:
    """Line Lightwell's own advisories up with the OSV findings for the same package version, by id, CVE or alias.
    Each Lightwell advisory gets `osv` (the matching finding's id, severity and score) or None when OSV did not flag
    it. Works on a copy: the sample catalog hands the same dict to every scan."""
    detail = copy.deepcopy(detail)
    by_id: dict[str, dict] = {}
    for v in vulns:
        for x in [v['id'], v['cve']] + list(v['aliases']):
            if x:
                by_id.setdefault(x, v)
    for a in detail.get('advisories', []):
        hit = next((by_id[k] for k in [a['id'], a['cve']] + list(a.get('aliases') or []) if k and k in by_id), None)
        a['osv'] = {'id': hit['id'], 'severity': hit['severity'], 'score': hit['score']} if hit else None
        if hit:
            hit['lightwell_severity'] = a.get('score')
    built = {b['build']: b.get('created_at') for b in detail.get('builds') or []}
    matched = detail.get('build') or {}
    for a in detail.get('advisories', []):
        if not a.get('credited'):
            continue
        when = built.get(a.get('fixed_in')) or (matched.get('created_at') if a.get('fixed_in') == matched.get('version') else '')
        days = _days(a.get('published'), when)
        if days is not None:
            a['fix_built'], a['lead_days'] = str(when)[:10], days
    return detail


def _days(start, end) -> int | None:
    """Whole days from one ISO date to another, or None when either is missing or unreadable."""
    try:
        return (date.fromisoformat(str(end)[:10]) - date.fromisoformat(str(start)[:10])).days
    except ValueError:
        return None


def apply_coverage(findings: list[dict], catalog, progress=None) -> dict:
    """Annotate findings with Lightwell coverage and return the summary block."""
    counts = {'remediated': 0, 'predisclosure': 0, 'other_version': 0, 'not_covered': 0, 'not_checked': 0}
    resolved = total = 0
    for i, f in enumerate(findings):
        c = f['component']
        if progress:
            progress('coverage', 'running', f"{c['name']} {c['version']}", done=i, total=len(findings))
        found = sorted({x for v in f['vulns'] for x in [v['cve']] + list(v['aliases']) if x.startswith('CVE-')})
        cov = catalog.check(c['ecosystem'], c['name'], c['version'], found)
        status = 'other_version' if cov['status'] == 'not_covered' and (cov.get('versions') or {}).get('nearest') else cov['status']
        counts[status] += 1
        covers = cov['status'] in ('remediated', 'predisclosure')
        ids = set(cov.get('cves') or [])
        itemised = covers and bool(ids)
        n = 0
        for v in f['vulns']:
            v['lightwell_fixed'] = itemised and bool(ids & ({v['id'], v['cve']} | set(v['aliases'])))
            n += v['lightwell_fixed']
        total += len(f['vulns'])
        resolved += n
        f['lightwell'] = {'status': status, 'build': cov.get('build'), 'embargo_days': cov.get('embargo_days'),
                          'note': cov.get('note', ''), 'resolves': n if itemised else None, 'of': len(f['vulns'])}
        if cov.get('versions'):
            f['lightwell']['versions'] = cov['versions']
        if cov.get('detail'):
            f['lightwell']['detail'] = _match_detail(cov['detail'], f['vulns'])
            leads = [a['lead_days'] for a in f['lightwell']['detail'].get('advisories', []) if 'lead_days' in a]
            if leads:
                f['lightwell']['lead_days'] = max(leads)
    facts = getattr(catalog, 'facts', None)
    return {**counts, 'issues_resolved': resolved, 'issues_total': total,
            'source': catalog.source, 'sample': catalog.sample, 'catalog': facts() if facts and findings else None}


def scan_repository(spec: str, repos, osv, catalog=None, gitlab_hosts=(), progress=None, pom_resolution: str = 'off', pom_fetch=None, ranges: bool = False) -> dict:
    """`repos` is a RepoRouter (or DemoRepos): anything with snapshot(ref). Never raises for an expected failure: the result carries status and error so one bad
    repository does not stop the rest of a scan. `progress(step, state, detail='', done=None, total=None)` is told where the scan is, for the page to show.
    `pom_resolution` is off (each pom.xml read alone), repo (versions may come from a parent or BOM in the same repository) or all (also
    published parents and BOMs, fetched with `pom_fetch`). With `ranges`, a dependency declared as a range is looked up at the lowest version
    the range allows, and the result says so."""
    emit = progress or (lambda *a, **k: None)
    result: dict = {'url': spec, 'status': 'error', 'error': '', 'scanned_at': now_iso()}
    emit('fetch', 'running', 'Checking the repository address')
    try:
        ref = parse_repo(spec, gitlab_hosts)
    except ValueError as exc:
        result['error'] = str(exc)
        emit('fetch', 'failed', result['error'])
        return result
    result['slug'] = ref.slug
    result['host'] = ref.host
    emit('fetch', 'running', f'Reading the file list and manifests from {ref.host}')
    try:
        snap = repos.snapshot(ref)
    except UpstreamError as exc:
        result['error'] = exc.message
        emit('fetch', 'failed', result['error'])
        return result
    emit('fetch', 'done', f'{snap.ref} at {(snap.commit or "")[:10]}, {len(snap.manifests)} manifest files')

    emit('parse', 'running', 'Reading dependency versions from the manifests')
    notes = list(snap.notes)
    manifests, comps = [], []
    resolver = None
    if pom_resolution in ('repo', 'all'):
        resolver = PomResolver({p: t for p, t in snap.manifests if manifest_kind(p) == 'pom'}, pom_fetch if pom_resolution == 'all' else None)
    for path, text in snap.manifests:
        found, n = parse_manifest(path, text, resolver, ranges)
        notes += n
        manifests.append({'path': path, 'kind': manifest_kind(path), 'components': len(found)})
        comps += found

    pinned = [c for c in comps if c.version and c.ecosystem in ECOSYSTEM]
    unevaluated = [c for c in comps if not c.version]
    emit('parse', 'done', f'{len(pinned)} pinned components' + (f', {len(unevaluated)} without a version' if unevaluated else '')
         + (f', {resolver.fetches} parent or BOM POMs fetched' if resolver and resolver.fetches else '')
         + (f', {sum(1 for c in pinned if c.declared)} from ranges' if ranges and any(c.declared for c in pinned) else ''))
    n_queries = len({(c.ecosystem, c.name, c.version) for c in pinned})
    emit('osv', 'running', f'Asking OSV.dev about {n_queries} package versions')
    try:
        looked_up = osv.lookup(pinned)
    except UpstreamError as exc:
        result.update({'ref': snap.ref, 'commit': snap.commit, 'error': exc.message})
        emit('osv', 'failed', exc.message)
        return result
    if getattr(osv, 'missing', None):
        notes.append(f'Demo mode has no recorded answer for {len(set(osv.missing))} packages, shown as clean.')

    # One entry per distinct package version, remembering every manifest that declared it.
    merged: dict[tuple[str, str, str], dict] = {}
    exact: set = set()                                 # versions some manifest states exactly: not just a range's lowest bound
    declared: dict[tuple[str, str, str], list[str]] = {}
    exclusive: set = set()
    for c in pinned:
        key = (c.ecosystem, c.name, c.version)
        if c.declared:
            if c.declared not in declared.setdefault(key, []):
                declared[key].append(c.declared)
            if c.exclusive:
                exclusive.add(key)
        else:
            exact.add(key)
        m = merged.setdefault(key, {'component': {'ecosystem': c.ecosystem, 'name': c.name, 'version': c.version,
                                                  'purl': c.purl, 'scopes': [], 'sources': [], 'pinned': True},
                                    'vulns': []})
        if c.scope not in m['component']['scopes']:
            m['component']['scopes'].append(c.scope)
        if c.source not in m['component']['sources']:
            m['component']['sources'].append(c.source)
    for key, m in merged.items():
        m['component']['ranges'] = [] if key in exact else declared.get(key, [])
        m['component']['range_exclusive'] = key in exclusive and key not in exact
    from_ranges = sum(1 for m in merged.values() if m['component']['ranges'])
    findings = []
    for (eco, name, ver), m in merged.items():
        vulns = looked_up.get((ECOSYSTEM[eco], name, ver), [])
        if vulns:
            m['vulns'] = sorted(vulns, key=lambda v: (_rank(v['severity']), -(v['score'] or 0), v['id']))
            fixes = [v['suggested_fix'] for v in m['vulns'] if v['suggested_fix']]
            # The lowest version that clears every advisory is the highest of the per-advisory fixes.
            m['fix_all'] = max(fixes, key=lambda x: _VKEY(x)) if fixes else None
            m['unfixed'] = sum(1 for v in m['vulns'] if not v['suggested_fix'])
            findings.append(m)
    findings.sort(key=lambda f: (_rank(f['vulns'][0]['severity']), -(f['vulns'][0]['score'] or 0), f['component']['name']))

    emit('osv', 'done', f'{len(findings)} of {len(merged)} package versions have known vulnerabilities')
    catalog = catalog or UnconfiguredCatalog('No Lightwell catalog was supplied to this scan.')
    if findings:
        emit('coverage', 'running', 'Checking Lightwell coverage', done=0, total=len(findings))
    coverage = apply_coverage(findings, catalog, progress)
    covered = coverage['remediated'] + coverage['predisclosure']
    emit('coverage', 'done', f'{covered} of {len(findings)} vulnerable components have a Lightwell build' if findings else 'Nothing to check')
    counts = {s: 0 for s in SEVERITY_ORDER}
    issue_ids = set()
    for f in findings:
        for v in f['vulns']:
            counts[v['severity'] if v['severity'] in counts else 'unknown'] += 1
            issue_ids.add(v['id'])
    ecos = sorted({c.ecosystem for c in comps})
    result.update({
        'status': 'done', 'ref': snap.ref, 'commit': snap.commit, 'private': snap.private,
        'ecosystems': ecos, 'manifests': manifests,
        'components': len(merged), 'from_ranges': from_ranges, 'unevaluated': len(unevaluated),
        'unevaluated_components': [{'name': c.name, 'ecosystem': c.ecosystem, 'source': c.source, 'note': c.note}
                                   for c in unevaluated[:MAX_UNEVALUATED]],
        'findings': findings,
        'summary': {**counts, 'vulnerable_components': len(findings), 'issues': sum(counts.values()),
                    'distinct_advisories': len(issue_ids), 'lightwell': coverage},
        'notes': list(dict.fromkeys(notes)),
    })
    return result
