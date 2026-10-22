#!/usr/bin/env python3
"""
Record real scans as demo data, so demo mode can replay them with no network.

    python3 record_demo.py owner/repo https://gitlab.com/group/project [...]
    python3 record_demo.py --local DIR owner/name        record a folder of manifests under a made-up repository name

Runs the live scanner (GitHub or GitLab, and OSV.dev) and writes demo/repos/<slug with / as __>.json
(the manifests, as fetched) and merges the matching OSV answers into demo/osv.json.
Only public repositories belong here: everything written is committed with the code.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from scanner.github import GitHubClient                                   # noqa: E402
from scanner.gitlab import GitLabClient                                   # noqa: E402
from scanner.http import UpstreamError                                    # noqa: E402
from scanner.osv import RecordingOsv                                      # noqa: E402
from scanner.parse import manifest_kind, parse_manifest                    # noqa: E402
from scanner.repo import DemoRepos, RepoRouter, parse_repo                # noqa: E402


def record_local(folder: Path, spec: str, osv: RecordingOsv) -> None:
    """A constructed repository: the manifests come from a local folder, and the scan says so."""
    ref = parse_repo(spec)
    manifests = {str(p.relative_to(folder)): p.read_text() for p in sorted(folder.rglob('*')) if p.is_file() and manifest_kind(str(p.relative_to(folder)))}
    comps = [c for path, text in manifests.items() for c in parse_manifest(path, text)[0]]
    osv.lookup(comps)
    out = ROOT / 'demo' / 'repos' / DemoRepos._file(ref.slug)
    out.write_text(json.dumps({'ref': 'main', 'commit': '0' * 40, 'manifests': manifests,
                               'notes': ['Constructed demo application, not a real repository. Its dependency versions were chosen '
                                         'to show each Lightwell coverage outcome.']}, indent=1))
    print(f'{ref.slug}: {len(manifests)} manifests, {len(comps)} components (constructed) -> {out.relative_to(ROOT)}')


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    router = RepoRouter(GitHubClient(os.environ.get('GITHUB_TOKEN', '')),
                        {'gitlab.com': GitLabClient('gitlab.com', os.environ.get('GITLAB_TOKEN', ''))})
    osv = RecordingOsv()
    (ROOT / 'demo' / 'repos').mkdir(parents=True, exist_ok=True)
    if argv[0] == '--local':
        if len(argv) != 3:
            print(__doc__)
            return 1
        record_local(Path(argv[1]).resolve(), argv[2], osv)
        argv = []
    for spec in argv:
        try:
            ref = parse_repo(spec)
            snap = router.snapshot(ref)
        except (ValueError, UpstreamError) as exc:
            print(f'{spec}: skipped ({getattr(exc, "message", exc)})')
            continue
        if snap.private:
            print(f'{ref.slug}: private, not recorded')
            continue
        comps = [c for p, t in snap.manifests for c in parse_manifest(p, t)[0]]
        osv.lookup(comps)
        out = ROOT / 'demo' / 'repos' / DemoRepos._file(ref.slug)
        out.write_text(json.dumps({'ref': snap.ref, 'commit': snap.commit, 'notes': snap.notes,
                                   'manifests': dict(snap.manifests)}, indent=1))
        print(f'{ref.slug}: {len(snap.manifests)} manifests, {len(comps)} components -> {out.relative_to(ROOT)}')
    path = ROOT / 'demo' / 'osv.json'
    merged = json.loads(path.read_text()) if path.exists() else {'queries': {}, 'vulns': {}}
    snap = osv.snapshot()
    merged['queries'].update(snap['queries'])
    merged['vulns'].update(snap['vulns'])
    path.write_text(json.dumps(merged, indent=1, sort_keys=True))
    print(f'demo/osv.json: {len(merged["queries"])} lookups, {len(merged["vulns"])} advisories')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
