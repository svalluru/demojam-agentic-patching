"""
The lowest version a dependency range allows, for the manifests that give a range instead of one version.

    lower_bound('maven',  '[1.0,2.0)')      -> ('1.0', False)
    lower_bound('pep440', '>=1.0,<2.0')     -> ('1.0', False)
    lower_bound('poetry', '^1.2.3')         -> ('1.2.3', False)
    lower_bound('npm',    '>=1.0.0 <2.0.0') -> ('1.0.0', False)

The second value is True when the bound is exclusive (`>1.0`, `(1.0,2.0)`): there is no way to name the next
version, so the bound itself is returned and the caller says it is "just above". None when the range has no lower
bound (`<2.0`, `*`, `latest`, `!=1.5`, a URL), which means there is nothing to look up.

The lowest version is the oldest one the range permits, and the version actually installed is usually newer, so what
is found for it can overstate the exposure. Callers must say so.

Standard library only.
"""
from __future__ import annotations

import re
from functools import cmp_to_key

from .osv import vcmp

_OK = re.compile(r'^\d[\w.+!\-]*$')
_X = re.compile(r'^[xX*]$')
_KEY = cmp_to_key(lambda a, b: vcmp(a[0], b[0]))


def _ok(version: str) -> bool:
    return bool(version) and bool(_OK.match(version))


def _maven(spec: str) -> tuple[str, bool] | None:
    if spec.lower().startswith('latest') or spec in ('+', 'RELEASE', 'LATEST'):
        return None
    if spec[0] not in '[(':
        if spec.endswith('+'):                                   # Gradle prefix: 1.+ allows 1, 1.0, 1.1, ...
            base = spec[:-1].rstrip('.')
            return (base, False) if _ok(base) else None
        return None
    found = re.findall(r'([\[(])\s*([^,\[\]()]*?)\s*(?:,\s*([^,\[\]()]*?))?\s*([\])])', spec)
    if not found:
        return None
    best: tuple[str, bool] | None = None
    for opener, low, _high, _closer in found:
        if not _ok(low):
            return None                                          # one of the intervals has no lower bound
        cand = (low, opener == '(')
        if best is None or vcmp(cand[0], best[0]) < 0:
            best = cand
    return best


def _pep440(spec: str) -> tuple[str, bool] | None:
    cands: list[tuple[str, bool]] = []
    for clause in spec.split(','):
        m = re.match(r'^(~=|===|==|>=|>)\s*([A-Za-z0-9.*+!_\-]+)$', clause.strip())
        if not m:
            continue
        op, version = m.groups()
        version = re.sub(r'\.?\*$', '', version)                 # 2.* and 2.0.* start at 2 and 2.0
        if _ok(version):
            cands.append((version, op == '>'))
    return max(cands, key=_KEY) if cands else None


def _semver(spec: str, pad: bool) -> tuple[str, bool] | None:
    if '://' in spec or re.match(r'^(git|github|file|link|npm|workspace|http)', spec, re.I):
        return None
    lows: list[tuple[str, bool]] = []
    for alt in spec.split('||'):
        text = re.sub(r'(\^|~>|~=|~|>=|<=|>|<|==|=)\s+', r'\1', alt.strip())
        text = re.sub(r'^(\S+)\s+-\s+\S+$', r'>=\1', text)         # 1.2.3 - 2.3.4
        cands: list[tuple[str, bool]] = []
        for token in re.split(r'[\s,]+', text):
            m = re.match(r'^(\^|~>|~=|~|>=|<=|>|<|==|=|!=)?v?(.+)$', token)
            if not m or m.group(1) in ('<', '<=', '!='):
                continue
            parts = []
            for part in m.group(2).split('.'):
                if _X.match(part):
                    break
                parts.append(part)
            version = '.'.join(parts)
            if not _ok(version):
                continue
            if pad and re.match(r'^\d+(\.\d+)*$', version):
                version = '.'.join((version.split('.') + ['0', '0'])[:max(3, version.count('.') + 1)])
            cands.append((version, m.group(1) == '>'))
        if not cands:
            return None                                          # this alternative has no lower bound
        lows.append(max(cands, key=_KEY))
    return min(lows, key=_KEY) if lows else None


def lower_bound(syntax: str, spec: str) -> tuple[str, bool] | None:
    spec = (spec or '').strip()
    if not spec:
        return None
    if syntax == 'maven':
        return _maven(spec)
    if syntax == 'pep440':
        return _pep440(spec)
    if syntax == 'poetry':
        return _semver(spec, pad=False)
    if syntax == 'npm':
        return _semver(spec, pad=True)
    return None
