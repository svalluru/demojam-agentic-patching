#!/usr/bin/env python3
"""Deliver one Lightwell build to the console as if Nexus had just cached it: the demo's pre-flight step.

    ./nexus-setup/send-event.py org.apache.mina mina-core 2.2.5.rhlw-00002
    ./nexus-setup/send-event.py org.apache.mina mina-core 2.2.5.rhlw-00002 --console http://localhost:8788

The poller only takes the newest build of each version, and the newest is not always the one a Lightwell advisory
names (mina-core 2.2.5: -00009 is newer, -00002 is the one CVE-2026-41635 names). This asks Nexus for the build, so
its lightwell-remediated proxy caches it, then posts the same payload Nexus's webhook would, signed with
NEXUS_WEBHOOK_SECRET from .env, to the console's /api/v2/webhook. A redelivery is the same event.
"""
import argparse
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_env() -> None:
    for line in (ROOT / '.env').read_text().splitlines() if (ROOT / '.env').exists() else []:
        if '=' in line and not line.lstrip().startswith('#'):
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('group'), ap.add_argument('artifact'), ap.add_argument('version')
    ap.add_argument('--console', default='http://localhost:8788')
    a = ap.parse_args()
    load_env()
    secret, nexus = os.environ.get('NEXUS_WEBHOOK_SECRET', ''), os.environ.get('NEXUS_URL', '').rstrip('/')
    if not secret:
        sys.exit('NEXUS_WEBHOOK_SECRET is not set in .env (nexus-setup/deploy.sh writes it)')
    ctx = ssl.create_default_context(cafile=os.environ.get('SSL_CERT_FILE') or None)
    if nexus:
        jar = (f"{nexus}/repository/lightwell-remediated/{a.group.replace('.', '/')}/{a.artifact}/{a.version}/"
               f"{a.artifact}-{a.version}.jar")
        try:
            with urllib.request.urlopen(urllib.request.Request(jar, method='HEAD'), timeout=120, context=ctx) as r:
                print(f'Nexus has it: HTTP {r.status}')
        except Exception as exc:
            sys.exit(f'Nexus does not serve {jar}: {exc}')
    body = json.dumps({'action': 'CREATED', 'repositoryName': 'lightwell-remediated',
                       'component': {'format': 'maven2', 'group': a.group, 'name': a.artifact,
                                     'version': a.version}}).encode()
    req = urllib.request.Request(f"{a.console.rstrip('/')}/api/v2/webhook", body,
                                 {'Content-Type': 'application/json', 'X-Nexus-Webhook-Id': 'rm:repository:component',
                                  'X-Nexus-Webhook-Signature': hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()})
    with urllib.request.urlopen(req, timeout=60) as r:
        ev = json.load(r).get('event') or {}
    print(f"Console event {ev.get('id')}: {ev.get('group')}:{ev.get('artifact')} {ev.get('version')} "
          '(CVEs follow from the Lightwell API within seconds)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
