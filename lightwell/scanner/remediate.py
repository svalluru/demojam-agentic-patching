"""
Turn a finished scan of one repository into the list of dependency changes a remediation job will make.

The person picks which sources of a fix are acceptable. For each vulnerable component the first acceptable one, in
this order, is used:

    lightwell   Lightwell has a build of the exact version in use
    another     Lightwell has no build of that version but has one of a nearby version
    osv         OSV.dev lists a fixed version

A component with no acceptable source is left alone and listed with the reason. Only pom.xml and requirements
files are edited for now; a component declared anywhere else is listed as "edit by hand".

Nothing here touches the network or a repository. The job that does the work receives this list and applies it as
written, so what was approved is what runs.
"""
from __future__ import annotations

import re

from .parse import manifest_kind

SOURCES = ('lightwell', 'another', 'osv')
LABELS = {'lightwell': 'Lightwell', 'another': 'Lightwell with Another Build', 'osv': 'OSV'}
EDITABLE = ('pom', 'requirements')
SAFE_VERSION = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$')
SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,200}$')
SAFE_PATH = re.compile(r'^[A-Za-z0-9_./-]{1,300}$')


def options(finding: dict) -> dict[str, str]:
    """The version each source would move this component to. A source with nothing to offer is absent."""
    lw = finding.get('lightwell') or {}
    out: dict[str, str] = {}
    if lw.get('status') in ('remediated', 'predisclosure') and lw.get('build'):
        out['lightwell'] = lw['build']
    near = (lw.get('versions') or {}).get('nearest')
    if lw.get('status') == 'other_version' and near and near.get('build'):
        out['another'] = near['build']
    if finding.get('fix_all'):
        out['osv'] = finding['fix_all']
    return out


def _tier(finding: dict) -> str:
    return 'predisclosure' if (finding.get('lightwell') or {}).get('status') == 'predisclosure' else 'remediated'


def _safe(change: dict) -> bool:
    return (bool(SAFE_NAME.match(change['name'])) and bool(SAFE_VERSION.match(change['from'])) and bool(SAFE_VERSION.match(change['to']))
            and all(SAFE_PATH.match(p) and '..' not in p.split('/') for p in change['manifests']))


def resolve(findings: list[dict], sources) -> dict:
    """`sources` is any subset of SOURCES. Returns the changes to make, the findings left alone, how many findings each
    source could fix on its own, and which Lightwell repositories the build will need."""
    chosen = [s for s in SOURCES if s in set(sources or ())]
    changes: list[dict] = []
    skipped: list[dict] = []
    offered = {s: 0 for s in SOURCES}
    registry: set[tuple[str, str]] = set()
    for f in findings:
        c = f['component']
        opts = options(f)
        for s in opts:
            offered[s] += 1
        base = {'name': c['name'], 'ecosystem': c['ecosystem'], 'from': c['version']}
        pick = next((s for s in chosen if s in opts), None)
        if pick is None:
            if opts:
                reason = 'Only available as ' + ' or '.join(LABELS[s] for s in SOURCES if s in opts) + ', which is not selected.'
            else:
                reason = 'No fixed version, and Lightwell has no build of this version or a nearby one.'
            skipped.append({**base, 'reason': reason})
            continue
        manifests = [p for p in c['sources'] if manifest_kind(p) in EDITABLE]
        if not manifests:
            kinds = sorted({manifest_kind(p) or p for p in c['sources']})
            skipped.append({**base, 'reason': 'Declared in ' + ', '.join(kinds) + ', which is not edited automatically. Change it by hand.'})
            continue
        change = {**base, 'to': opts[pick], 'source': pick, 'manifests': manifests}
        if not _safe(change):
            skipped.append({**base, 'reason': 'The name, version or file path has characters that are not allowed in an automatic edit.'})
            continue
        if pick != 'osv':
            change['tier'] = _tier(f)
            registry.add((c['ecosystem'], change['tier']))
        changes.append(change)
    return {'sources': chosen, 'changes': changes, 'skipped': skipped, 'offered': offered,
            'registry': [{'ecosystem': e, 'tier': t} for e, t in sorted(registry)]}
