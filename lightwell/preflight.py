#!/usr/bin/env python3
"""
Check that the scanner is ready to demonstrate. It talks only to the scanner's own address, never to GitHub, OSV.dev,
Lightwell or the AAP controller directly, so it makes no network call that the page would not make itself. In live mode
the scanner checks the controller with read-only calls and launches no job.

    ./preflight.py                  checks the scanner on 127.0.0.1:8790 (or LIGHTWELL_HOST / LIGHTWELL_PORT)
    ./preflight.py --scan appsecco/dvja
                                    also runs one real scan through it and reports the result; the scan is saved in the history

Exit status is 0 when nothing failed (warnings do not fail), 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEMO_REPOS = ('appsecco/dvja', 'demojam/lightwell-coverage-demo', 'sunil-samuel/Image-Processor')
OK, WARN, FAIL = 'ok', 'warn', 'FAIL'


def http_fetch(base: str):
    def fetch(method: str, path: str, body=None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method, headers={'Content-Type': 'application/json'} if data else {})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            try:
                return {'ok': False, 'error': json.loads(exc.read()).get('error', f'HTTP {exc.code}')}
            except ValueError:
                return {'ok': False, 'error': f'HTTP {exc.code}'}
    return fetch


def check(fetch, scan: str | None = None, wait: float = 120, tick=time.sleep) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        fetch('GET', '/healthz')
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return [(FAIL, f'The scanner did not answer ({exc}). Start it with ./start.sh and run this again.')]
    out.append((OK, 'The scanner is running.'))
    mode = fetch('GET', '/v1/mode')
    live = mode.get('mode') == 'live'
    out.append((OK, f"Mode: {mode.get('mode')}."))

    status = fetch('GET', '/v1/lightwell/status')
    if live:
        out.append((OK if status.get('ok') else FAIL, 'Lightwell API: ' + str(status.get('detail') or status.get('error') or 'no answer')))
    else:
        out.append((OK if status.get('ok') else FAIL, 'Lightwell coverage: ' + str(status.get('detail') or 'sample catalog')))

    rem = fetch('GET', '/v1/remediation/status')
    if live:
        out.append((OK if rem.get('ok') else WARN, 'Remediation (AAP): ' + str(rem.get('detail') or rem.get('error') or 'no answer')))
    else:
        out.append((OK, 'Remediation: ' + str(rem.get('detail') or 'staged run')))

    if live:
        if not mode.get('github_token'):
            out.append((WARN, 'No GitHub token: GitHub allows 60 API calls an hour, which is about 20 repositories.'))
        out.append((OK, f"Parent and BOM POMs: {mode.get('pom_resolution')}. Version ranges: {'on' if mode.get('ranges') else 'off'}."))
    else:
        have = set(mode.get('demo_repos') or [])
        missing = [r for r in DEMO_REPOS if r not in have]
        out.append((FAIL, 'Recorded repositories missing for the demo script: ' + ', '.join(missing)) if missing
                   else (OK, f'All {len(DEMO_REPOS)} repositories the demo script uses are recorded.'))

    if scan:
        started = fetch('POST', '/v1/scans', {'repos': [scan]})
        if not started.get('id'):
            out.append((FAIL, 'Could not start a scan: ' + str(started.get('error') or 'no scan id')))
            return out
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            got = fetch('GET', '/v1/scans/' + started['id']).get('scan') or {}
            if got.get('status') == 'done':
                break
            tick(1)
        else:
            out.append((FAIL, f'The scan of {scan} did not finish in {wait:.0f} seconds.'))
            return out
        repo = (got.get('repos') or [{}])[0]
        if repo.get('status') != 'done':
            out.append((FAIL, f"The scan of {scan} failed: {repo.get('error') or 'unknown error'}"))
        else:
            lw = repo['summary'].get('lightwell') or {}
            out.append((OK, f"Scanned {scan}: {repo['components']} components, {repo['summary']['vulnerable_components']} vulnerable, "
                            f"{lw.get('remediated', 0) + lw.get('predisclosure', 0)} with a Lightwell build (source: {lw.get('source')})."))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Check that the scanner is ready to demonstrate.')
    ap.add_argument('--host', default=os.environ.get('LIGHTWELL_HOST', '127.0.0.1'))
    ap.add_argument('--port', default=os.environ.get('LIGHTWELL_PORT', '8790'))
    ap.add_argument('--scan', metavar='REPO', help='also scan one repository through the running scanner')
    args = ap.parse_args(argv)
    results = check(http_fetch(f'http://{args.host}:{args.port}'), args.scan)
    for level, text in results:
        print(f'[{level}] {text}')
    failed = sum(1 for level, _ in results if level == FAIL)
    print('Ready.' if not failed else f'{failed} check(s) failed.')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
