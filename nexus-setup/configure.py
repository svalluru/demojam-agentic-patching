#!/usr/bin/env python3
"""
Configure a fresh (or existing) Nexus for Applications v2 through its REST API. Run by deploy.sh; safe to re-run.

  1. admin password: replaces the generated one (NEXUS_INITIAL_PASSWORD) with a new one, stored in .env as
     NEXUS_ADMIN_PASSWORD; an existing NEXUS_ADMIN_PASSWORD is used as is.
  2. repository lightwell-remediated: Maven2 proxy of the Lightwell Network Java repository, Layout Policy Strict,
     authenticated with the registry service account (Red Hat's "Configure Nexus to use the Lightwell Network
     repository").
  3. anonymous read, so the commit job and the hosts can fetch the build without a Nexus credential. This makes the
     cached Lightwell builds readable by anyone who can reach the Route: acceptable in a lab, not elsewhere.
  4. a repository webhook (capability "webhook.repository") for component events on that repository, to
     NEXUS_WEBHOOK_TARGET, signed with NEXUS_WEBHOOK_SECRET (generated and stored in .env if missing). Where this
     Nexus has no capabilities API, the manual steps are printed instead.

Standard library only. Secrets are never printed.
"""
import argparse
import base64
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

REMOTE = 'https://packages.redhat.com/lightwell/java/remediated/'
REPO = 'lightwell-remediated'


def read_env(path: Path) -> dict:
    out = {}
    if path.exists():
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env(path: Path, updates: dict) -> None:
    """Replace KEY= lines in place, append the rest. Values with shell-special characters are single-quoted."""
    lines = path.read_text().splitlines() if path.exists() else []
    done = set()
    for i, line in enumerate(lines):
        m = re.match(r'\s*([A-Z0-9_]+)\s*=', line)
        if m and m.group(1) in updates:
            lines[i] = f'{m.group(1)}={_q(updates[m.group(1)])}'
            done.add(m.group(1))
    lines += [f'{k}={_q(v)}' for k, v in updates.items() if k not in done]
    path.write_text('\n'.join(lines) + '\n')


def _q(v: str) -> str:
    return f"'{v}'" if re.search(r'[^A-Za-z0-9_./:@=+-]', v) else v


class Nexus:
    def __init__(self, base: str, user: str, password: str, verify: bool = True):
        self.base, self.auth = base.rstrip('/'), base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE

    def call(self, method: str, path: str, body=None, ctype='application/json', ok=(200, 201, 204)):
        data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={'Authorization': 'Basic ' + self.auth, 'Content-Type': ctype,
                                              'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw and raw[:1] in b'[{' else raw)
        except urllib.error.HTTPError as exc:
            if exc.code in ok:
                return exc.code, None
            return exc.code, exc.read().decode('utf-8', 'replace')[:300]


def proxy_payload(user: str, token: str) -> dict:
    return {
        'name': REPO, 'online': True,
        'storage': {'blobStoreName': 'default', 'strictContentTypeValidation': True},
        'proxy': {'remoteUrl': REMOTE, 'contentMaxAge': 1440, 'metadataMaxAge': 5},
        'negativeCache': {'enabled': True, 'timeToLive': 60},
        'httpClient': {'blocked': False, 'autoBlock': True,
                       'authentication': {'type': 'username', 'username': user, 'password': token}},
        'maven': {'versionPolicy': 'RELEASE', 'layoutPolicy': 'STRICT', 'contentDisposition': 'ATTACHMENT'},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--env', default=str(Path(__file__).resolve().parents[1] / '.env'))
    args = ap.parse_args()
    env_path = Path(args.env)
    env = {**read_env(env_path), **{k: v for k, v in os.environ.items() if k.startswith('NEXUS_')}}
    base = env.get('NEXUS_URL') or sys.exit('NEXUS_URL is not set')
    verify = env.get('NEXUS_VERIFY_TLS', 'false').lower() in ('1', 'true', 'yes')
    user, token = env.get('LIGHTWELL_REGISTRY_USER', ''), env.get('LIGHTWELL_REGISTRY_TOKEN', '')
    if not (user and token):
        sys.exit('LIGHTWELL_REGISTRY_USER and LIGHTWELL_REGISTRY_TOKEN must be set in .env')
    updates = {'NEXUS_URL': base}

    print('Admin password')
    password = env.get('NEXUS_ADMIN_PASSWORD', '')
    if env.get('NEXUS_INITIAL_PASSWORD') and not password:
        password = secrets.token_urlsafe(18)
        code, err = Nexus(base, 'admin', env['NEXUS_INITIAL_PASSWORD'], verify).call(
            'PUT', '/service/rest/v1/security/users/admin/change-password', password.encode(), 'text/plain')
        if code not in (200, 204):
            sys.exit(f'could not change the admin password: HTTP {code} {err}')
        updates['NEXUS_ADMIN_PASSWORD'] = password
        print('  replaced the generated password; stored in .env as NEXUS_ADMIN_PASSWORD')
    elif not password:
        sys.exit('no NEXUS_ADMIN_PASSWORD in .env and no generated password to start from')
    else:
        print('  using NEXUS_ADMIN_PASSWORD from .env')
    nx = Nexus(base, 'admin', password, verify)
    write_env(env_path, updates)                       # keep the password even if a later step fails

    print(f'Repository {REPO}')
    code, existing = nx.call('GET', f'/service/rest/v1/repositories/maven/proxy/{REPO}', ok=(200,))
    if code == 200:
        code, err = nx.call('PUT', f'/service/rest/v1/repositories/maven/proxy/{REPO}', proxy_payload(user, token))
        verb = 'updated'
    else:
        code, err = nx.call('POST', '/service/rest/v1/repositories/maven/proxy', proxy_payload(user, token))
        verb = 'created'
    if code not in (200, 201, 204):
        sys.exit(f'could not configure {REPO}: HTTP {code} {err}')
    print(f'  {verb}: proxy of {REMOTE}, layout Strict, registry service account')

    print('Anonymous read')
    code, err = nx.call('PUT', '/service/rest/v1/security/anonymous',
                        {'enabled': True, 'userId': 'anonymous', 'realmName': 'NexusAuthorizingRealm'})
    print('  enabled' if code in (200, 204) else f'  could not enable: HTTP {code} {err}')

    print('Check the proxy reaches Lightwell')
    probe = f'{base}/repository/{REPO}/org/apache/logging/log4j/log4j-core/maven-metadata.xml'
    try:
        with urllib.request.urlopen(probe, timeout=60, context=nx.ctx) as r:
            versions = re.findall(r'<version>([^<]+)</version>', r.read().decode('utf-8', 'replace'))
        print(f'  log4j-core through Nexus: {", ".join(versions[-3:]) or "no versions"}')
    except Exception as exc:                          # the repository is still right; report and carry on
        print(f'  WARNING: {probe} -> {exc}. Check the registry token and that the cluster can reach packages.redhat.com')

    print('Webhook')
    secret = env.get('NEXUS_WEBHOOK_SECRET') or secrets.token_hex(24)
    target = env.get('NEXUS_WEBHOOK_TARGET', 'http://cve-console:8788/api/v2/webhook')
    write_env(env_path, {'NEXUS_WEBHOOK_SECRET': secret})
    code, caps = nx.call('GET', '/service/rest/v1/capabilities', ok=(200,))
    if code != 200 or not isinstance(caps, list):
        print(f'  this Nexus has no capabilities API (HTTP {code}). Create the webhook by hand:\n'
              f'    Administration > System > Capabilities > Create capability > "Webhook: Repository"\n'
              f'    Repository: {REPO}   Event Types: component   URL: {target}\n'
              f'    Secret Key: the NEXUS_WEBHOOK_SECRET value in .env\n'
              f'  Or skip webhooks: NEXUS_POLL_SECONDS=300 and NEXUS_EVENTS=poller in .env.')
        return
    props = {'repository': REPO, 'names': 'component', 'url': target, 'secret': secret}
    mine = next((c for c in caps if c.get('type') == 'webhook.repository'
                 and (c.get('properties') or {}).get('repository') == REPO), None)
    if mine:
        code, err = nx.call('PUT', f'/service/rest/v1/capabilities/{mine["id"]}',
                            {'type': 'webhook.repository', 'enabled': True, 'properties': props})
    else:
        code, err = nx.call('POST', '/service/rest/v1/capabilities',
                            {'type': 'webhook.repository', 'enabled': True, 'properties': props})
    print(f'  component events on {REPO} -> {target}' if code in (200, 201, 204)
          else f'  could not create it: HTTP {code} {err}. Create it by hand as above.')


if __name__ == '__main__':
    main()
