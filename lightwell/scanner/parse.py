"""
Manifest parsers: turn dependency files into components with package URLs.

Standard library only. Every parser returns (components, notes). A note is a
plain sentence about something this parser could not know, so the caller can
show it next to the results instead of letting a partial answer look complete.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import PurePosixPath

from .pom import PomResolver, _child, _resolve, _text, mkey
from .ranges import lower_bound

try:                                    # Python 3.11+
    import tomllib
except ImportError:                     # pragma: no cover - 3.10
    tomllib = None


@dataclass
class Component:
    ecosystem: str                      # maven | pypi | npm
    name: str                           # maven: group:artifact
    version: str | None                 # None when it could not be resolved
    source: str                         # manifest path inside the repo
    scope: str = 'direct'               # direct | transitive | dev
    pinned: bool = True                 # False when only a range was given
    note: str = ''
    declared: str = ''                  # the range as written, when the version is its lowest bound or could not be found
    exclusive: bool = False             # the lowest bound is exclusive, so the real minimum is just above it
    purl: str = field(default='', init=False)

    def __post_init__(self) -> None:
        self.purl = make_purl(self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict:
        return asdict(self)


def _ranged(ecosystem: str, name: str, spec: str, path: str, scope: str, syntax: str, ranges: bool, why: str) -> Component:
    """A dependency declared as a range. With `ranges` its version is the lowest one the range allows, and `declared`
    keeps the range as written; without, or when the range has no lower bound, it has no version."""
    low = lower_bound(syntax, spec) if ranges else None
    if low:
        return Component(ecosystem, name, low[0], path, scope, False,
                         f'declared as {spec}; the lowest version it allows is looked up' + (' (just above it)' if low[1] else ''),
                         declared=spec, exclusive=low[1])
    return Component(ecosystem, name, None, path, scope, False, why, declared=spec)


def _range_note(path: str, comps: list[Component], ranges: bool) -> str:
    """One sentence for a manifest that has ranges, when ranges are looked up by their lowest version; '' otherwise."""
    looked = sum(1 for c in comps if c.declared and c.version)
    skipped = sum(1 for c in comps if c.declared and not c.version)
    if not ranges or not (looked or skipped):
        return ''
    text = (f'{path}: {looked} dependencies are declared as a range, so the lowest version each range allows was looked up. '
            'That is the oldest version the range permits and the one installed is probably newer.') if looked else ''
    if skipped:
        text += f'{" " if text else f"{path}: "}{skipped} ranges have no lower bound and were not evaluated.'
    return text


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    q = lambda s: urllib.parse.quote(s, safe='')
    if ecosystem == 'maven':
        group, _, artifact = name.partition(':')
        base = f'pkg:maven/{q(group)}/{q(artifact)}'
    elif ecosystem == 'npm':
        if name.startswith('@') and '/' in name:
            scope, _, rest = name.partition('/')
            base = f'pkg:npm/{q(scope)}/{q(rest)}'
        else:
            base = f'pkg:npm/{q(name)}'
    else:
        base = f'pkg:{ecosystem}/{q(name)}'
    return f'{base}@{q(version)}' if version else base


# --------------------------------------------------------------------- maven

def parse_pom(text: str, path: str, resolver: PomResolver | None = None, ranges: bool = False) -> tuple[list[Component], list[str]]:
    """`resolver` lets a dependency's version come from a parent POM or an imported BOM. Without one the file is read
    on its own, as it always was."""
    notes: list[str] = []
    # ElementTree expands entities. Refuse documents that declare any rather
    # than parse untrusted XML with an entity-expansion surface.
    if re.search(r'<!(DOCTYPE|ENTITY)', text, re.I):
        return [], [f'{path}: skipped, the file declares a DOCTYPE or ENTITY, which is not parsed.']
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return [], [f'{path}: not valid XML ({exc}).']

    eff = resolver.effective_for(path) if resolver is not None else None
    if eff is None:
        eff = PomResolver({path: text}).effective_for(path)
    props, managed = eff.props, eff.managed                   # type: ignore[union-attr]
    notes += [f'{path}: {why}.' for why in eff.problems]      # type: ignore[union-attr]
    if eff.sources:                                           # type: ignore[union-attr]
        shown = eff.sources[:6]                               # type: ignore[union-attr]
        more = f' and {len(eff.sources) - 6} more' if len(eff.sources) > 6 else ''    # type: ignore[union-attr]
        notes.append(f"{path}: versions managed elsewhere were looked up in {', '.join(shown)}{more}.")
    parent = _child(root, 'parent')

    comps: list[Component] = []
    deps = _child(root, 'dependencies')
    if deps is not None:
        for d in deps:
            g = _resolve(_text(d, 'groupId'), props) or _text(d, 'groupId')
            a = _resolve(_text(d, 'artifactId'), props) or _text(d, 'artifactId')
            if not g or not a:
                continue
            raw = _text(d, 'version')
            held = managed.get(mkey(g, a, _text(d, 'type'), _text(d, 'classifier')))
            ver = _resolve(raw, props) if raw else (_resolve(held, props) if held else None)
            scope = 'dev' if _text(d, 'scope') == 'test' else 'direct'
            if ver is None:
                why = ('version managed by the parent POM or a BOM' if not raw
                       else f'version {raw} could not be resolved')
                comps.append(Component('maven', f'{g}:{a}', None, path, scope, False, why))
            elif re.search(r'[\[\](),]', ver):
                comps.append(_ranged('maven', f'{g}:{a}', ver, path, scope, 'maven', ranges, f'version range {ver} is not evaluated'))
            else:
                comps.append(Component('maven', f'{g}:{a}', ver, path, scope))
    if parent is not None:
        pg, pa, pvv = _text(parent, 'groupId'), _text(parent, 'artifactId'), _text(parent, 'version')
        if pg and pa and pvv:
            comps.append(Component('maven', f'{pg}:{pa}', pvv, path, 'direct', True, 'parent POM'))
    unresolved = [c for c in comps if c.version is None]
    if unresolved:
        notes.append(f'{path}: {len(unresolved)} dependencies have no resolved version (managed by a parent or BOM, '
                     'or a range). A pom.xml alone does not give the full tree.')
    if _range_note(path, comps, ranges):
        notes.append(_range_note(path, comps, ranges))
    notes.append(f'{path}: only direct dependencies are listed; transitive dependencies need a resolved tree.')
    return comps, notes


# -------------------------------------------------------------------- gradle

_GRADLE = re.compile(
    r'''(?x)^\s*(?:api|implementation|compile|compileOnly|runtimeOnly|runtime|testImplementation|testCompile|
        testRuntimeOnly|annotationProcessor|kapt)\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([\w.\-+]+|[\[(][^"']*[\])])["']''')
_PLAIN = re.compile(r'^[\w.\-+]+$')


def parse_gradle(text: str, path: str, ranges: bool = False) -> tuple[list[Component], list[str]]:
    comps = []
    for line in text.splitlines():
        m = _GRADLE.match(line)
        if m:
            g, a, v = m.groups()
            scope = 'dev' if line.lstrip().startswith('test') else 'direct'
            if ranges and (v.endswith('+') or not _PLAIN.match(v)):
                comps.append(_ranged('maven', f'{g}:{a}', v, path, scope, 'maven', True, f'version range {v} is not evaluated'))
            elif _PLAIN.match(v):
                comps.append(Component('maven', f'{g}:{a}', v, path, scope))
    notes = [f'{path}: only dependencies written as group:artifact:version strings are read; '
             'version catalogs, variables and transitive dependencies are not resolved.']
    return comps, ([_range_note(path, comps, ranges)] if _range_note(path, comps, ranges) else []) + notes


# ----------------------------------------------------------------------- pypi

_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*')


def norm_py(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def _pep508(spec: str, path: str, scope: str = 'direct', ranges: bool = False) -> Component | None:
    spec = spec.split(';', 1)[0].split('#', 1)[0].strip()
    m = _NAME.match(spec)
    if not m:
        return None
    name = m.group(0)
    rest = spec[m.end():].strip()
    rest = re.sub(r'^\[[^\]]*\]', '', rest).strip()          # extras
    pin = re.match(r'^===?\s*([A-Za-z0-9._+!-]+)\s*$', rest)
    if pin:
        return Component('pypi', norm_py(name), pin.group(1), path, scope)
    return _ranged('pypi', norm_py(name), rest, path, scope, 'pep440', ranges, f'not pinned ({rest or "no version"}), so not evaluated')


def parse_requirements(text: str, path: str, ranges: bool = False) -> tuple[list[Component], list[str]]:
    comps = []
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith(('-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index',
                            '--extra-index', '-f', '--find-links', '--hash', '--no-binary', '--only-binary')):
            skipped += 1
            continue
        if '://' in line or line.startswith('.'):
            skipped += 1
            continue
        line = re.sub(r'\s--hash=\S+', '', line).rstrip('\\').strip()
        c = _pep508(line, path, ranges=ranges)
        if c:
            comps.append(c)
    notes = [_range_note(path, comps, ranges)] if _range_note(path, comps, ranges) else []
    unpinned = sum(1 for c in comps if not c.pinned and not (ranges and c.declared))
    if unpinned:
        notes.append(f'{path}: {unpinned} requirements are not pinned with ==, so they are not evaluated. '
                     'A lock file or a pip freeze gives exact versions.')
    if skipped:
        notes.append(f'{path}: {skipped} option, include or URL lines were skipped.')
    return comps, notes


def parse_pyproject(text: str, path: str, ranges: bool = False) -> tuple[list[Component], list[str]]:
    if tomllib is None:
        return [], [f'{path}: skipped, TOML parsing needs Python 3.11 or newer.']
    try:
        data = tomllib.loads(text)
    except Exception as exc:
        return [], [f'{path}: not valid TOML ({exc}).']
    comps: list[Component] = []
    proj = data.get('project') or {}
    for s in proj.get('dependencies') or []:
        c = _pep508(s, path, ranges=ranges)
        if c:
            comps.append(c)
    for group, specs in (proj.get('optional-dependencies') or {}).items():
        for s in specs:
            c = _pep508(s, path, 'dev', ranges)
            if c:
                comps.append(c)
    poetry = (data.get('tool') or {}).get('poetry') or {}
    for section, scope in (('dependencies', 'direct'), ('dev-dependencies', 'dev')):
        for name, spec in (poetry.get(section) or {}).items():
            if name.lower() == 'python':
                continue
            ver = spec if isinstance(spec, str) else (spec or {}).get('version') if isinstance(spec, dict) else None
            ver = (ver or '').strip()
            if re.match(r'^=?=?\s*\d[\w.+!-]*$', ver) and not ver.startswith(('^', '~')):
                comps.append(Component('pypi', norm_py(name), ver.lstrip('= '), path, scope))
            else:
                comps.append(_ranged('pypi', norm_py(name), ver, path, scope, 'poetry', ranges, f'range {ver or "unspecified"} is not evaluated'))
    notes = [_range_note(path, comps, ranges)] if _range_note(path, comps, ranges) else []
    loose = sum(1 for c in comps if not c.pinned and not (ranges and c.declared))
    if loose:
        notes.append(f'{path}: {"dependencies given as ranges are" if not ranges else f"{loose} dependencies with no version at all are"} not evaluated; a lock file gives exact versions.')
    return comps, notes


def parse_poetry_lock(text: str, path: str) -> tuple[list[Component], list[str]]:
    if tomllib is None:
        return [], [f'{path}: skipped, TOML parsing needs Python 3.11 or newer.']
    try:
        data = tomllib.loads(text)
    except Exception as exc:
        return [], [f'{path}: not valid TOML ({exc}).']
    comps = [Component('pypi', norm_py(p['name']), p['version'], path, 'transitive')
             for p in data.get('package', []) if p.get('name') and p.get('version')]
    return comps, []


def parse_pipfile_lock(text: str, path: str) -> tuple[list[Component], list[str]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], [f'{path}: not valid JSON ({exc}).']
    comps = []
    for section, scope in (('default', 'transitive'), ('develop', 'dev')):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get('version', '')
            if ver.startswith('=='):
                comps.append(Component('pypi', norm_py(name), ver[2:], path, scope))
    return comps, []


# ------------------------------------------------------------------------ npm

def parse_package_json(text: str, path: str, ranges: bool = False) -> tuple[list[Component], list[str]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], [f'{path}: not valid JSON ({exc}).']
    comps = []
    for section, scope in (('dependencies', 'direct'), ('devDependencies', 'dev'), ('optionalDependencies', 'direct')):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            if re.match(r'^\d+\.\d+\.\d+([-+][\w.]+)?$', spec):
                comps.append(Component('npm', name, spec, path, scope))
            else:
                comps.append(_ranged('npm', name, spec, path, scope, 'npm', ranges, f'range {spec} is not evaluated; a lock file gives exact versions'))
    notes = [_range_note(path, comps, ranges)] if _range_note(path, comps, ranges) else []
    loose = sum(1 for c in comps if not c.pinned and not (ranges and c.declared))
    if loose:
        notes.append(f'{path}: {"dependencies given as ranges are" if not ranges else f"{loose} dependencies with no version at all are"} not evaluated; package-lock.json gives exact versions.')
    return comps, notes


def parse_package_lock(text: str, path: str) -> tuple[list[Component], list[str]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], [f'{path}: not valid JSON ({exc}).']
    comps: dict[tuple[str, str], Component] = {}
    pk = data.get('packages')
    if isinstance(pk, dict):                                   # lockfile v2 and v3
        for key, meta in pk.items():
            if not key or 'node_modules/' not in key or not isinstance(meta, dict):
                continue
            name = key.rsplit('node_modules/', 1)[-1]
            ver = meta.get('version')
            if name and ver:
                scope = 'dev' if meta.get('dev') else 'transitive'
                comps[(name, ver)] = Component('npm', name, ver, path, scope)
    else:                                                      # lockfile v1
        def walk(deps: dict) -> None:
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get('version'):
                    comps[(name, meta['version'])] = Component(
                        'npm', name, meta['version'], path, 'dev' if meta.get('dev') else 'transitive')
                    walk(meta.get('dependencies') or {})
        walk(data.get('dependencies') or {})
    return list(comps.values()), []


# ------------------------------------------------------------------ dispatch

REQ_NAME = re.compile(r'^requirements[\w.\-]*\.(txt|in)$', re.I)
SKIP_DIRS = {'node_modules', '.git', 'target', 'build', 'dist', 'venv', '.venv', 'env', '__pycache__',
             'vendor', 'third_party', '.tox', '.gradle', '.idea'}


def manifest_kind(path: str) -> str | None:
    p = PurePosixPath(path)
    if any(part in SKIP_DIRS for part in p.parts[:-1]):
        return None
    name = p.name
    if name == 'pom.xml':
        return 'pom'
    if name in ('build.gradle', 'build.gradle.kts'):
        return 'gradle'
    if name == 'pyproject.toml':
        return 'pyproject'
    if name == 'poetry.lock':
        return 'poetry.lock'
    if name == 'Pipfile.lock':
        return 'pipfile.lock'
    if name == 'package.json':
        return 'package.json'
    if name == 'package-lock.json':
        return 'package-lock'
    if REQ_NAME.match(name) or (p.parent.name == 'requirements' and name.endswith('.txt')):
        return 'requirements'
    return None


_PARSERS = {
    'pom': parse_pom, 'gradle': parse_gradle, 'requirements': parse_requirements,
    'pyproject': parse_pyproject, 'poetry.lock': parse_poetry_lock, 'pipfile.lock': parse_pipfile_lock,
    'package.json': parse_package_json, 'package-lock': parse_package_lock,
}


_RANGED = ('gradle', 'requirements', 'pyproject', 'package.json')


def parse_manifest(path: str, text: str, resolver: PomResolver | None = None, ranges: bool = False) -> tuple[list[Component], list[str]]:
    kind = manifest_kind(path)
    if kind is None:
        return [], []
    if kind == 'pom':
        return parse_pom(text, path, resolver, ranges)
    if kind in _RANGED:
        return _PARSERS[kind](text, path, ranges)
    return _PARSERS[kind](text, path)
