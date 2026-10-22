"""
Effective-POM resolution: the versions a pom.xml leaves to a parent POM or to an imported BOM.

A module's pom.xml usually does not carry the version of a dependency. It comes from the parent POM (often the
root pom.xml of the same repository, or a published one such as spring-boot-starter-parent) or from a BOM imported
into dependencyManagement. Reading one file alone cannot see those, so this module follows the chain:

  * the parent is looked for in the repository first (its relativePath, then any pom with those coordinates), and
    only then fetched as a published POM;
  * an imported BOM is resolved the same way, including the parents and BOMs it has in turn, with a depth limit;
  * properties are inherited, and a child's property overrides its parent's, as in Maven.

Where several places set the same version the order is: the pom's own dependencyManagement, then its imported BOMs
(the first import wins), then what the parent manages.

Published POMs come from one fixed host (Maven Central unless MAVEN_REPO_URL is set by whoever runs the server),
never from an address written in a scanned file. Coordinates are checked before they go into a URL. A POM that
cannot be found or read leaves its dependencies unresolved, with a note saying why, and never stops the scan.

Standard library only.
"""
from __future__ import annotations

import posixpath
import re
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .http import UpstreamError, request

CENTRAL_URL = 'https://repo1.maven.org/maven2'
MAX_DEPTH = 8                                   # parents and BOMs followed from one pom
MAX_FETCHES = 60                                # published POMs fetched for one scan
BUDGET_SECONDS = 90                             # after this a scan stops fetching POMs
MAX_POM_BYTES = 1_000_000
CACHE_ENTRIES = 500
_PROP = re.compile(r'\$\{([^}]+)\}')
_COORD = re.compile(r'^[A-Za-z0-9_.+\-]+$')


def _strip_ns(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def _child(el: ET.Element, name: str) -> ET.Element | None:
    for c in el:
        if _strip_ns(c.tag) == name:
            return c
    return None


def _text(el: ET.Element | None, name: str) -> str:
    c = _child(el, name) if el is not None else None
    return (c.text or '').strip() if c is not None and c.text else ''


def _resolve(value: str, props: dict[str, str], depth: int = 0) -> str | None:
    """Substitute ${...}. None when something stays unresolved."""
    if not value:
        return None
    for _ in range(5):
        m = _PROP.search(value)
        if not m:
            return value
        key = m.group(1)
        if key not in props:
            return None
        value = value[:m.start()] + props[key] + value[m.end():]
    return None


def _plain(*parts: str) -> bool:
    return all(p and _COORD.match(p) and '..' not in p for p in parts)


def mkey(group: str, artifact: str, typ: str = '', classifier: str = '') -> str:
    """How dependencyManagement identifies a dependency: group, artifact, type (jar unless said) and classifier."""
    return f"{group}:{artifact}:{typ or 'jar'}:{classifier}"


# ------------------------------------------------------------------ fetching

class CentralFetcher:
    """Fetches one published POM. The cache is kept for the life of the process, since a published POM never
    changes, and so is a 404, so a missing parent is not asked for again."""

    def __init__(self, base: str = CENTRAL_URL, timeout: float = 15):
        self.base = base.rstrip('/')
        self.timeout = timeout
        self._cache: dict[tuple[str, str, str], str | None] = {}
        self._lock = threading.Lock()

    def __call__(self, group: str, artifact: str, version: str) -> str | None:
        key = (group, artifact, version)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        if not _plain(group, artifact, version):
            return None
        url = f"{self.base}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
        try:
            payload, _ = request('Maven Central', url, raw=True, max_bytes=MAX_POM_BYTES, timeout=self.timeout, retries=1)
            text: str | None = payload.decode('utf-8', 'replace')                       # type: ignore[union-attr]
        except UpstreamError as exc:
            if exc.status != 404:
                raise
            text = None
        with self._lock:
            if len(self._cache) >= CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = text
        return text


# --------------------------------------------------------------------- model

@dataclass
class Pom:
    key: str                                    # 'local:<path>' for a file in the repository, 'group:artifact:version' for a published one
    path: str                                   # repository path, '' for a published POM
    group: str
    artifact: str
    version: str
    parent: dict | None                         # {'g', 'a', 'v', 'rel'}
    props: dict[str, str]
    managed: list[dict]                         # this pom's own dependencyManagement entries, as written

    @property
    def label(self) -> str:
        return self.path or self.key


@dataclass
class Eff:
    props: dict[str, str] = field(default_factory=dict)
    managed: dict[str, str] = field(default_factory=dict)      # mkey -> version; own and inherited are as written, imported are resolved
    sources: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def read_pom(text: str, key: str, path: str = '') -> tuple[Pom | None, str]:
    """(model, '') or (None, why not). A document that declares a DOCTYPE or ENTITY is refused, as everywhere else."""
    if re.search(r'<!(DOCTYPE|ENTITY)', text, re.I):
        return None, 'it declares a DOCTYPE or ENTITY'
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None, 'it is not valid XML'
    parent = None
    pel = _child(root, 'parent')
    if pel is not None:
        rel = _child(pel, 'relativePath')
        parent = {'g': _text(pel, 'groupId'), 'a': _text(pel, 'artifactId'), 'v': _text(pel, 'version'),
                  'rel': '../pom.xml' if rel is None else (rel.text or '').strip()}
    props: dict[str, str] = {}
    prel = _child(root, 'properties')
    if prel is not None:
        for p in prel:
            props[_strip_ns(p.tag)] = (p.text or '').strip()
    managed: list[dict] = []
    dm = _child(root, 'dependencyManagement')
    deps = _child(dm, 'dependencies') if dm is not None else None
    if deps is not None:
        for d in deps:
            managed.append({'g': _text(d, 'groupId'), 'a': _text(d, 'artifactId'), 'v': _text(d, 'version'),
                            'scope': _text(d, 'scope'), 'type': _text(d, 'type'), 'classifier': _text(d, 'classifier')})
    return Pom(key, path, _text(root, 'groupId'), _text(root, 'artifactId'), _text(root, 'version'), parent, props, managed), ''


# ------------------------------------------------------------------ resolver

class PomResolver:
    """Resolves effective properties and managed versions for the pom.xml files of one repository.
    `fetch(group, artifact, version)` returns the text of a published POM, or None when there is none. Without a
    fetch function nothing outside the repository is looked at."""

    def __init__(self, files: dict[str, str] | None = None, fetch=None, max_fetches: int = MAX_FETCHES,
                 budget: float = BUDGET_SECONDS):
        self.files = dict(files or {})
        self.fetch = fetch
        self.max_fetches = max_fetches
        self.fetches = 0
        self.deadline = time.monotonic() + budget
        self._local: dict[str, Pom | None] = {}
        self._remote: dict[tuple[str, str, str], tuple[Pom | None, str]] = {}
        self._eff: dict[str, Eff] = {}
        self._index: dict[tuple[str, str, str], str] | None = None

    # ------------------------------------------------------------- lookup
    def local(self, path: str) -> Pom | None:
        if path not in self._local:
            text = self.files.get(path)
            self._local[path] = read_pom(text, f'local:{path}', path)[0] if text is not None else None
        return self._local[path]

    @staticmethod
    def _coords(pom: Pom) -> tuple[str, str, str]:
        p = pom.parent or {}
        return pom.group or p.get('g', ''), pom.artifact, pom.version or p.get('v', '')

    def _find(self, group: str, artifact: str, version: str) -> Pom | None:
        if self._index is None:
            self._index = {}
            for path in sorted(self.files):
                pom = self.local(path)
                if pom is not None:
                    self._index.setdefault(self._coords(pom), path)
        path = self._index.get((group, artifact, version))
        return self.local(path) if path else None

    def _published(self, group: str, artifact: str, version: str) -> tuple[Pom | None, str]:
        key = (group, artifact, version)
        if key in self._remote:
            return self._remote[key]
        pom, why = None, ''
        if self.fetch is None:
            why = 'published POMs are not fetched in this mode'
        elif not _plain(group, artifact, version):
            why = 'its coordinates are not plain text'
        elif self.fetches >= self.max_fetches or time.monotonic() > self.deadline:
            why = 'this scan reached its limit on fetching POMs'
        else:
            self.fetches += 1
            try:
                text = self.fetch(group, artifact, version)
            except UpstreamError as exc:
                text, why = None, exc.message
            if text is None:
                why = why or 'it was not found'
            else:
                pom, why = read_pom(text, f'{group}:{artifact}:{version}')
        self._remote[key] = (pom, why)
        return pom, why

    def _parent(self, pom: Pom) -> tuple[Pom | None, str, str]:
        """(parent, where it came from, why not)."""
        p = pom.parent
        if not p or not (p['g'] and p['a'] and p['v']):
            return None, '', ''
        if pom.path:
            if p['rel']:
                rel = p['rel'] if p['rel'].endswith('.xml') else posixpath.join(p['rel'], 'pom.xml')
                cand = self.local(posixpath.normpath(posixpath.join(posixpath.dirname(pom.path), rel)))
                if cand is not None and cand.artifact == p['a'] and self._coords(cand)[0] == p['g']:
                    return cand, 'this repository', ''
            cand = self._find(p['g'], p['a'], p['v'])
            if cand is not None:
                return cand, 'this repository', ''
        got, why = self._published(p['g'], p['a'], p['v'])
        return got, 'Maven Central' if got else '', why

    def _bom(self, group: str, artifact: str, version: str) -> tuple[Pom | None, str, str]:
        cand = self._find(group, artifact, version)
        if cand is not None:
            return cand, 'this repository', ''
        got, why = self._published(group, artifact, version)
        return got, 'Maven Central' if got else '', why

    # ---------------------------------------------------------- effective
    def effective(self, pom: Pom, stack: tuple[str, ...] = ()) -> Eff:
        if pom.key in self._eff:
            return self._eff[pom.key]
        if pom.key in stack or len(stack) >= MAX_DEPTH:
            return Eff(problems=[f'{pom.label}: the parent or BOM chain is circular or more than {MAX_DEPTH} deep'])
        stack = stack + (pom.key,)
        eff = Eff()
        parent, where, why = self._parent(pom)
        p = pom.parent
        if parent is not None:
            pe = self.effective(parent, stack)
            eff.props.update(pe.props)
            eff.managed.update(pe.managed)
            eff.sources += pe.sources + [f"parent {p['g']}:{p['a']}:{p['v']} ({where})"]
            eff.problems += pe.problems
        elif p and p['g'] and p['a'] and p['v']:
            eff.problems.append(f"parent POM {p['g']}:{p['a']}:{p['v']} could not be read: {why}")

        group, _, version = self._coords(pom)
        builtin = {'project.version': version, 'version': version, 'project.groupId': group, 'project.artifactId': pom.artifact}
        if p and p['v']:
            builtin['project.parent.version'] = builtin['parent.version'] = p['v']
        eff.props.update({k: v for k, v in builtin.items() if v})
        eff.props.update(pom.props)

        own: dict[str, str] = {}
        imports: list[dict] = []
        for e in pom.managed:
            if e['scope'] == 'import':
                imports.append(e)
            elif e['g'] and e['a'] and e['v']:
                own[mkey(e['g'], e['a'], e['type'], e['classifier'])] = e['v']
        imported: dict[str, str] = {}
        for e in imports:
            g, a, v = (_resolve(e[k], eff.props) for k in ('g', 'a', 'v'))
            if not (g and a and v):
                eff.problems.append(f"BOM {e['g']}:{e['a']} could not be resolved: its group, artifact or version is not plain text")
                continue
            bom, bwhere, bwhy = self._bom(g, a, v)
            if bom is None:
                eff.problems.append(f'BOM {g}:{a}:{v} could not be read: {bwhy}')
                continue
            be = self.effective(bom, stack)
            eff.sources += be.sources + [f'BOM {g}:{a}:{v} ({bwhere})']
            eff.problems += be.problems
            for k, raw in be.managed.items():
                val = _resolve(raw, be.props)
                if val:
                    imported.setdefault(k, val)
        eff.managed.update(imported)
        eff.managed.update(own)
        eff.sources = list(dict.fromkeys(eff.sources))
        eff.problems = list(dict.fromkeys(eff.problems))
        self._eff[pom.key] = eff
        return eff

    def effective_for(self, path: str) -> Eff | None:
        pom = self.local(path)
        return self.effective(pom) if pom is not None else None
