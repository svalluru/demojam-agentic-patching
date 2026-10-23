"""
Lightwell coverage: for a package version that has known vulnerabilities, does Lightwell have a
remediated build of exactly that version, and which of the advisories does that build address?

Lightwell delivers its fixes as remediated builds in repositories on packages.redhat.com, and Red Hat
publishes an API for them (https://console.redhat.com/api/lightwell/v0.1, OpenAPI at .../openapi.json).
Three providers answer the question behind one check():

  FixtureCatalog       demo mode. Reads demo/lightwell_catalog.json, a small SAMPLE written by hand.
                       It is not Lightwell's catalog and every answer is marked sample.
  LightwellApiCatalog  live mode with credentials. Asks the Lightwell Network API.
  UnconfiguredCatalog  live mode without credentials. Says coverage was not checked, and why.

check() returns a dict with a status:

  remediated     a build of this exact version exists
  predisclosure  a build exists in the predisclosure tier, members only
  not_covered    no build of this exact version
  other_version  (set by the scan, not by a catalog) not_covered, but a remediated build of another version exists
  not_checked    coverage could not be determined (no credentials, or the service refused or failed)

The API provider has not been exercised against the live service from this repository's tests, which use
responses shaped like the published specification. Its first real run is the credential check
(GET /v1/lightwell/status). Secrets are never put in a result, a note or an error message.
"""
from __future__ import annotations

import json
import re
import time
from functools import cmp_to_key
from pathlib import Path
from urllib.parse import quote

from .http import UpstreamError, request
from .osv import vcmp

STATUSES = ('remediated', 'predisclosure', 'other_version', 'not_covered', 'not_checked')


def _norm_py(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def _key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    return ecosystem, (_norm_py(name) if ecosystem == 'pypi' else name), version


def _result(status: str, build: str | None = None, cves: list | None = None, note: str = '',
            embargo_days: int | None = None, detail: dict | None = None, versions: dict | None = None) -> dict:
    out = {'status': status, 'build': build, 'cves': list(cves or []), 'embargo_days': embargo_days, 'note': note}
    if detail:
        out['detail'] = detail
    if versions:
        out['versions'] = versions
    return out


MAX_VERSIONS = 12                               # versions listed per tier for one package
_VKEY = cmp_to_key(vcmp)


def package_facts(rows: list[dict]) -> dict:
    """What Lightwell holds for one package, whatever version is installed: the remediated builds (best build per upstream
    version) and the versions in the validated tier. Validated repositories list no advisories: they are a catalog tier,
    not a CVE fix, and nothing here counts them as coverage."""
    remediated: dict[str, dict] = {}
    validated: set[str] = set()
    for r in rows:
        repo = str(r.get('repository') or '')
        parsed = parse_build(r)
        if parsed:
            up, build = parsed
            if up not in remediated or _build_rank(build) > _build_rank(remediated[up]['build']):
                remediated[up] = {'version': up, 'build': build, 'repository': repo}
        elif 'validated' in repo and r.get('version'):
            validated.add(str(r['version']))
    return {'remediated': sorted(remediated.values(), key=lambda x: _VKEY(x['version'])),
            'validated': sorted(validated, key=_VKEY)}


def _window(items: list, installed: str, version=lambda x: x) -> list:
    """At most MAX_VERSIONS items, ascending: the ones nearest above the installed version first, then those at or below it."""
    above = [x for x in items if vcmp(version(x), installed) > 0]
    below = [x for x in items if vcmp(version(x), installed) <= 0]
    keep = above[:MAX_VERSIONS * 2 // 3] + below[-(MAX_VERSIONS - min(len(above), MAX_VERSIONS * 2 // 3)):]
    return sorted(keep, key=lambda x: _VKEY(version(x)))


def package_view(facts: dict, installed: str) -> dict:
    """package_facts() read against the installed version: is the package carried at all, which remediated and validated
    versions are listed (capped), the nearest remediated version above the installed one, and whether the exact installed
    version is in the validated tier."""
    rem, val = facts.get('remediated') or [], facts.get('validated') or []
    nearest = next((x for x in rem if vcmp(x['version'], installed) > 0), None)
    return {'carried': bool(rem or val), 'installed': installed,
            'remediated_total': len(rem), 'validated_total': len(val),
            'remediated': _window(rem, installed, lambda x: x['version']), 'validated': _window(val, installed),
            'nearest': {'version': nearest['version'], 'build': nearest['build']} if nearest else None,
            'exact_validated': any(vcmp(v, installed) == 0 for v in val)}


class FixtureCatalog:
    source = 'sample'
    sample = True

    def __init__(self, path: Path):
        data = json.loads(Path(path).read_text()) if Path(path).exists() else {}
        self.note = data.get('note', '')
        self._index = {_key(e['ecosystem'], e['name'], e['version']): e for e in data.get('entries', [])}
        self._packages = data.get('packages', {})
        self._repositories = data.get('repositories')

    def facts(self) -> dict | None:
        return {'repositories': self._repositories} if self._repositories else None

    def describe(self) -> dict:
        return {'source': self.source, 'sample': True, 'entries': len(self._index), 'note': self.note}

    def check(self, ecosystem: str, name: str, version: str, cves: list | None = None) -> dict:
        e = self._index.get(_key(ecosystem, name, version))
        held = self._packages.get('|'.join(_key(ecosystem, name, '')[:2]))
        versions = package_view(held, version) if held is not None else None
        if e is None:
            return _result('not_covered', note='No build of this exact version in the sample catalog.', versions=versions)
        return _result(e['status'], e.get('build'), e.get('cves'), e.get('note', ''), e.get('embargo_days'), e.get('detail'), versions)


class UnconfiguredCatalog:
    source = 'none'
    sample = False

    def __init__(self, reason: str):
        self.reason = reason

    def describe(self) -> dict:
        return {'source': self.source, 'sample': False, 'entries': 0, 'note': self.reason}

    def check(self, ecosystem: str, name: str, version: str, cves: list | None = None) -> dict:
        return _result('not_checked', note=self.reason)

    def status(self) -> dict:
        return {'ok': False, 'source': self.source, 'detail': self.reason}


# ------------------------------------------------------------------ Lightwell Network API

DEFAULT_BASE = 'https://console.redhat.com/api/lightwell/v0.1'
DEFAULT_TOKEN_URL = 'https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token'
API_ECOSYSTEM = {'maven': 'maven', 'pypi': 'python', 'npm': 'npm'}
PAGE = 100
MAX_PAGES = 20
MAX_DETAIL_CALLS = 120                          # extra lookups per scan for the "more detail" view
DETAIL_TEXT = 600                               # characters of an advisory's text kept
MAX_DETAIL_ADVISORIES = 50
TOKEN_MARGIN = 60                               # seconds before expiry at which a token is replaced
_LOCAL = re.compile(r'^(.+?)(?:\+rhlw\.|\.rhlw-|-rhlw-)')


def parse_build(row: dict) -> tuple[str, str] | None:
    """(upstream version, full build version) for a Lightwell-patched row, or None for a validated one.

    Seen in the live API (October 2026):
      Java    version '5.3.18', release 'rhlw-00006'  -> build '5.3.18.rhlw-00006'
      Python  version '3.0.1+rhlw.1', release null    -> build '3.0.1+rhlw.1'
    The '.rhlw-N' form inside `version`, which Red Hat's guides describe, is accepted, and so is '-rhlw-N'
    (seen on some Jackson builds, for example '2.13.4.1-rhlw-00015')."""
    version = str(row.get('version') or '')
    release = str(row.get('release') or '')
    if release.startswith('rhlw-'):
        return version, f'{version}.{release}'
    m = _LOCAL.match(version)
    return (m.group(1), version) if m else None


def _build_rank(build: str) -> tuple[int, int]:
    m = re.search(r'rhlw[-.](\d+)(?:-n(\d+))?$', build)
    return (int(m.group(1)), int(m.group(2) or 0)) if m else (0, 0)


class LightwellApiCatalog:
    """Coverage from the Lightwell Network API. The credentials are a Red Hat Hybrid Cloud Console service
    account in a user access group with the Repositories viewer role."""

    source = 'api'
    sample = False

    def __init__(self, client_id: str, client_secret: str, base_url: str = DEFAULT_BASE,
                 token_url: str = DEFAULT_TOKEN_URL, demo: bool = False, timeout: float = 20):
        self._id, self._secret = client_id, client_secret
        self.base = base_url.rstrip('/')
        self.token_url = token_url
        self.demo = demo
        self.timeout = timeout
        self._token = ''
        self._expires = 0.0
        self._versions: dict[tuple, list[dict]] = {}
        self._advisories: dict[tuple, list[dict]] = {}
        self._repos: dict[str, dict] = {}
        self._catalog: dict | None = None
        self._detail_calls = 0
        self.error = ''
        self._refused = ''                      # set when credentials or access are refused: stop asking

    # ---------------------------------------------------------------- plumbing
    def _bearer(self) -> str:
        if self._token and self._expires > time.time() + TOKEN_MARGIN:
            return self._token
        try:
            payload, _ = request('Red Hat SSO', self.token_url, method='POST', timeout=self.timeout,
                                 form={'grant_type': 'client_credentials', 'client_id': self._id,
                                       'client_secret': self._secret, 'scope': 'api.console'})
        except UpstreamError as exc:
            if exc.status in (400, 401, 403):
                raise UpstreamError('Red Hat SSO', f'the service account credentials were rejected (HTTP {exc.status}). '
                                                   'Check LIGHTWELL_CLIENT_ID and LIGHTWELL_CLIENT_SECRET in lightwell/.env.',
                                    exc.status)
            raise
        token = (payload or {}).get('access_token')                       # type: ignore[union-attr]
        if not token:
            raise UpstreamError('Red Hat SSO', 'the token answer had no access_token')
        self._token = token
        self._expires = time.time() + int((payload or {}).get('expires_in', 300))   # type: ignore[union-attr]
        return self._token

    def _get(self, path: str, **params) -> dict:
        q = {k: v for k, v in params.items() if v is not None}
        if self.demo and path in ('/package_versions', '/packages'):
            q['demo'] = 'true'
        bearer = self._bearer()
        url = f'{self.base}{path}' + ('?' + '&'.join(f'{k}={quote(str(v), safe="")}' for k, v in q.items()) if q else '')
        try:
            payload, _ = request('Lightwell API', url, headers={'Authorization': f'Bearer {bearer}'}, timeout=self.timeout)
        except UpstreamError as exc:
            if exc.status == 401:
                self._token, self._expires = '', 0.0                      # a stale token must not be reused
                raise UpstreamError('Lightwell API', 'the token was refused (HTTP 401). Check the service account and '
                                                      'that it is in a group with the Repositories viewer role.', 401)
            if exc.status == 403:
                raise UpstreamError('Lightwell API', 'access refused (HTTP 403). The service account needs the '
                                                      'Repositories viewer role and a Lightwell Network membership.', 403)
            raise
        return payload                                                    # type: ignore[return-value]

    def _list(self, **params) -> list[dict]:
        out: list[dict] = []
        for page in range(MAX_PAGES):
            body = self._get('/package_versions', limit=PAGE, offset=page * PAGE, **params)
            rows = body.get('data') or []
            out += rows
            if len(rows) < PAGE or len(out) >= int((body.get('meta') or {}).get('count', len(out))):
                break
        return out

    @staticmethod
    def _split(ecosystem: str, name: str) -> tuple[str, str]:
        if ecosystem == 'maven':
            group, _, artifact = name.partition(':')
            return group, artifact
        return '', (_norm_py(name) if ecosystem == 'pypi' else name)

    def _same_package(self, row: dict, ecosystem: str, group: str, name: str) -> bool:
        if ecosystem == 'maven':
            return row.get('group') == group and row.get('name') == name
        rn = row.get('name') or ''
        return (_norm_py(rn) if ecosystem == 'pypi' else rn) == name

    # ---------------------------------------------------------------- the check
    def _builds(self, ecosystem: str, name: str) -> list[dict]:
        group, short = self._split(ecosystem, name)
        key = (ecosystem, group, short)
        if key not in self._versions:
            rows = self._list(ecosystem=API_ECOSYSTEM[ecosystem], name=short)
            self._versions[key] = [r for r in rows if self._same_package(r, ecosystem, group, short)]
        return self._versions[key]

    def check(self, ecosystem: str, name: str, version: str, cves: list | None = None) -> dict:
        if ecosystem not in API_ECOSYSTEM:
            return _result('not_checked', note=f'The Lightwell API does not list {ecosystem} packages.')
        if self._refused:
            return _result('not_checked', note=f'The Lightwell API could not answer: {self._refused}')
        try:
            held = self._builds(ecosystem, name)
            versions = package_view(package_facts(held), version)
            builds = []
            for row in held:
                parsed = parse_build(row)
                if parsed and vcmp(parsed[0], version) == 0:     # Lightwell writes 1.9.0 where Maven Central says 1.9
                    builds.append((parsed[1], row))
            if not builds:
                return _result('not_covered', note='No Lightwell build of this exact version.', versions=versions)
            best, row = max(builds, key=lambda b: _build_rank(b[0]))
            predisclosure = bool(re.search(r'-n\d+$', best)) or 'predisclosure' in str(row.get('repository', '')).lower()
            resolved, newer = self._itemise(ecosystem, name, version, best)
            note = 'From the Lightwell Network API.'
            if resolved is None:
                note += ' Which advisories this build addresses could not be itemised.'
            elif not resolved:
                note += (f' An advisory names a newer build ({newer}) than the one found in the package list ({best}), so no advisory is credited to it.'
                         if newer else ' Lightwell lists no advisory for this build, so which CVEs it addresses is not itemised.')
            return _result('predisclosure' if predisclosure else 'remediated', best, resolved, note,
                           detail=self._detail(ecosystem, name, version, best, row), versions=versions)
        except UpstreamError as exc:
            self._remember(exc)
            return _result('not_checked', note=f'The Lightwell API could not answer: {exc.message}')

    def package_facts(self, ecosystem: str, name: str) -> dict:
        return package_facts(self._builds(ecosystem, name))

    def facts(self) -> dict | None:
        """The Lightwell repositories this account can see, for the catalog panel. One call, cached. Optional: a failure
        leaves the panel out and changes nothing else."""
        if self._catalog is None:
            try:
                rows = self._get('/repositories', limit=100).get('data') or []
            except UpstreamError:
                return None
            keep = ('name', 'security_level', 'content_type', 'build_count', 'advisory_count', 'package_count')
            repos = [{k: r[k] for k in keep if r.get(k) is not None} for r in rows
                     if self.demo or not str(r.get('name', '')).endswith('-demo')]
            self._catalog = {'repositories': repos} if repos else {}
        return self._catalog or None

    # ---------------------------------------------------------------- more detail
    # Everything below is optional colour. A failure here never changes the coverage answer and never marks the
    # credentials as refused: the detail is simply left out.
    def _repo_facts(self, repo_name: str) -> dict:
        if repo_name not in self._repos:
            facts: dict = {}
            self._detail_calls += 1
            try:
                for r in self._get('/repositories', name=repo_name, limit=5).get('data') or []:
                    if r.get('name') == repo_name:
                        facts = {k: r[k] for k in ('name', 'security_level', 'content_type', 'build_count', 'advisory_count',
                                                    'package_count', 'published_distribution_url') if r.get(k) not in (None, '')}
                        if r.get('feature_name'):
                            facts['features'] = [x.strip() for x in str(r['feature_name']).split(',') if x.strip()]
                        break
            except UpstreamError:
                facts = {}
            self._repos[repo_name] = facts
        return self._repos[repo_name]

    def _package_detail(self, ecosystem: str, name: str, row: dict, build: str) -> dict:
        """The package detail endpoint for one build: its builds with dates (Maven), its distribution files (Python)."""
        uuid = row.get('repository_uuid')
        if not uuid or ecosystem not in ('maven', 'pypi'):
            return {}
        if ecosystem == 'maven':
            group, short = self._split(ecosystem, name)
            path = f"/repositories/{uuid}/maven_packages/{quote(group, safe='')}/{quote(short, safe='')}/{quote(build, safe='')}"
        else:
            path = f"/repositories/{uuid}/python_packages/{quote(str(row.get('name') or name), safe='')}/{quote(build, safe='')}"
        self._detail_calls += 1
        try:
            return self._get(path)
        except UpstreamError:
            return {}

    def _detail(self, ecosystem: str, name: str, version: str, best: str, row: dict) -> dict:
        if self._detail_calls >= MAX_DETAIL_CALLS:
            return {'note': f'More detail was skipped: this scan reached its limit of {MAX_DETAIL_CALLS} extra Lightwell lookups.'}
        detail: dict = {'build': {'version': best, 'created_at': row.get('created_at') or '', 'repository': row.get('repository') or ''}}
        facts = self._repo_facts(str(row.get('repository') or ''))
        if facts:
            detail['repository'] = facts
        pkg = self._package_detail(ecosystem, name, row, best)
        builds = []
        for b in pkg.get('builds') or []:
            v, rel = str(b.get('version') or ''), str(b.get('release') or '')
            builds.append({'build': f'{v}.{rel}' if rel else v, 'created_at': b.get('created_at') or ''})
        if builds:
            detail['builds'] = sorted(builds, key=lambda b: _build_rank(b['build']), reverse=True)
            made = next((b['created_at'] for b in builds if b['build'] == best and b['created_at']), '')
            if made:                                                      # the build's own date, not when the row was listed
                detail['build'] = {**detail['build'], 'created_at': made, 'listed_at': row.get('created_at') or ''}
        for key in ('summary', 'license', 'project_url'):
            if pkg.get(key):
                detail[key] = str(pkg[key])
        author = pkg.get('author')
        author = author.get('name') if isinstance(author, dict) else author
        if author:
            detail['author'] = str(author)
        files = [{'filename': d.get('filename') or '', 'type': d.get('packagetype') or '', 'size': d.get('size'),
                  'sha256': d.get('sha256') or '', 'created_at': d.get('created_at') or ''} for d in pkg.get('distributions') or []]
        if files:
            detail['distributions'] = files
        try:
            rows = self._advisory_rows(ecosystem, name, version)
        except UpstreamError:
            rows = []
        limit = _build_rank(best)
        advisories = []
        for adv in rows[:MAX_DETAIL_ADVISORIES]:
            fixed = [f for f in adv.get('fixed_versions') or [] if _LOCAL.match(str(f)) and vcmp((parse_build({'version': f}) or ('',))[0] or '~', version) == 0]
            lowest = min(fixed, key=_build_rank) if fixed else ''
            advisories.append({
                'id': adv.get('advisory_id') or '', 'cve': adv.get('advisory_name') or '', 'aliases': list(adv.get('aliases') or []),
                'severity': adv.get('severity') or '', 'score': adv.get('severity_score'),
                'summary': adv.get('summary') or '', 'details': str(adv.get('details') or '')[:DETAIL_TEXT],
                'published': adv.get('published') or '', 'modified': adv.get('modified') or '',
                'references': [str(u) for u in adv.get('reference_urls') or []], 'source': adv.get('source') or '',
                'fixed_in': lowest, 'credited': bool(lowest) and _build_rank(lowest) <= limit})
        if advisories:
            detail['advisories'] = advisories
        return detail

    def _remember(self, exc: UpstreamError) -> None:
        self.error = exc.message
        if exc.status in (400, 401, 403) or exc.service == 'Red Hat SSO':
            self._refused = exc.message

    def _advisory_rows(self, ecosystem: str, name: str, version: str) -> list[dict]:
        """Lightwell's advisories for one exact package version (package_name is the Maven coordinates, or the
        normalised Python name)."""
        key = (ecosystem, name, version)
        if key not in self._advisories:
            package = name if ecosystem == 'maven' else (_norm_py(name) if ecosystem == 'pypi' else name)
            rows: list[dict] = []
            for page in range(MAX_PAGES):
                body = self._get('/advisories', package_name=package, package_version=version, limit=PAGE, offset=page * PAGE)
                got = body.get('data') or []
                rows += got
                if len(got) < PAGE or len(rows) >= int((body.get('meta') or {}).get('count', len(rows))):
                    break
            self._advisories[key] = rows
        return self._advisories[key]

    def _itemise(self, ecosystem: str, name: str, version: str, build: str) -> tuple[list[str] | None, str]:
        """(CVE and advisory ids this build is credited with fixing, newest build an advisory names if that is newer
        than `build`). Returns (None, '') when the lookup could not be made and ([], ...) when there is nothing to credit.

        Conservative on purpose. An advisory counts only if a build it names is no newer than the newest one the
        repository actually lists, because crediting a fix that may not be published yet would overstate coverage.
        Lightwell does not publish an advisory for every build, so an empty answer means "not itemised", not "fixes nothing"."""
        try:
            rows = self._advisory_rows(ecosystem, name, version)
        except UpstreamError as exc:
            self._remember(exc)
            return None, ''
        limit = _build_rank(build)
        credited: list[str] = []
        newer = ''
        for adv in rows:
            fixed = [f for f in adv.get('fixed_versions') or [] if _LOCAL.match(str(f)) and vcmp((parse_build({'version': f}) or ('',))[0] or '~', version) == 0]
            if not fixed:
                continue
            lowest = min(fixed, key=_build_rank)
            if _build_rank(lowest) <= limit:
                credited += [adv.get('advisory_id', '')] + list(adv.get('aliases') or [])
            elif not newer or _build_rank(lowest) > _build_rank(newer):
                newer = lowest
        return list(dict.fromkeys(x for x in credited if x)), newer

    # ---------------------------------------------------------------- reporting
    def describe(self) -> dict:
        return {'source': self.source, 'sample': False, 'entries': 0, 'demo_repositories': self.demo, 'error': self.error,
                'note': 'Coverage comes from the Lightwell Network API' + (' (demo repositories).' if self.demo else '.')}

    def status(self) -> dict:
        """Credential and reachability check: a token, then one cheap call. Never reveals the secret."""
        try:
            body = self._get('/repositories', limit=1)
            count = (body.get('meta') or {}).get('count')
            self.error = self._refused = ''
            return {'ok': True, 'source': self.source, 'base_url': self.base, 'demo_repositories': self.demo,
                    'detail': f'Authenticated. {count} repositories are visible to this service account.'}
        except UpstreamError as exc:
            self._remember(exc)
            return {'ok': False, 'source': self.source, 'base_url': self.base, 'detail': exc.message}


LIVE_REASON = ('Coverage is not checked in live mode: set LIGHTWELL_CLIENT_ID and LIGHTWELL_CLIENT_SECRET in lightwell/.env '
               '(a Red Hat console service account in a group with the Repositories viewer role).')


def make_catalog(mode: str, demo_dir: Path, getenv=lambda key, default='': default):
    if mode == 'demo':
        return FixtureCatalog(Path(demo_dir) / 'lightwell_catalog.json')
    cid, secret = getenv('LIGHTWELL_CLIENT_ID'), getenv('LIGHTWELL_CLIENT_SECRET')
    if cid and secret:
        return LightwellApiCatalog(cid, secret, getenv('LIGHTWELL_API_BASE', DEFAULT_BASE) or DEFAULT_BASE,
                                   getenv('LIGHTWELL_TOKEN_URL', DEFAULT_TOKEN_URL) or DEFAULT_TOKEN_URL,
                                   getenv('LIGHTWELL_API_DEMO', '').lower() in ('1', 'true', 'yes'))
    return UnconfiguredCatalog(LIVE_REASON)
