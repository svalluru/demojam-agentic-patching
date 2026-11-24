#!/usr/bin/env python3
"""Create the AAP objects for the Containers side (the AO workflow "Container Patch" calls them). Idempotent.

    ./aap-setup/create-ctr-objects.py
    ./aap-setup/create-ctr-objects.py --dry-run

  GitLab repo   telco/ctr-automation      the CTR playbooks (aap-setup/playbooks/ctr_*.yml), committed from this
                                          repository, so AAP pulls them from inside the cluster
  credential    CTR GitLab                source control, for the project
  cred. type    Containers                injects CTR_GITLAB_URL/_TOKEN, CTR_OCP_API/_TOKEN, CTR_ACS_URL/_TOKEN,
                                          CTR_NEXUS_URL, CTR_MATTERMOST_WEBHOOK
  credential    Containers                GitLab (CTR_GITLAB_TOKEN), OpenShift (service account ctr-runner,
                                          ctr-setup/ctr-runner.yaml), ACS (ACS_URL/_TOKEN), Nexus (NEXUS_URL)
  inventory     CTR localhost             one host, localhost (the jobs only call APIs)
  project       CTR Automation            telco/ctr-automation
  templates     CTR - Commit, CTR - Build and Scan, CTR - Deploy, CTR - Rollout Health, CTR - Verify (ACS),
                CTR - Rollback, CTR - Notify

Settings from .env: AAP_BASE_URL, AAP_TOKEN, CTR_GITLAB_TOKEN, OCP_API_URL, ACS_URL, ACS_TOKEN, NEXUS_URL, and
optionally CTR_MATTERMOST_WEBHOOK. oc must be logged in to OCP_API_URL (for the ctr-runner token).
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
_spec = importlib.util.spec_from_file_location('v1objects', HERE / 'create-app-patch-objects.py')
_v1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_v1)
Controller, load_env = _v1.Controller, _v1.load_env

TEMPLATES = {
    'CTR - Commit': ('ctr_commit.yml', 'The container fix on branch fix/<run> of the app repo (pom.xml, Containerfile)'),
    'CTR - Build and Scan': ('ctr_build_scan.yml', 'ctr-build: Maven through Nexus, buildah, roxctl image check, cosign sign'),
    'CTR - Deploy': ('ctr_deploy.yml', 'Pin the new digest in GitOps and ask Argo CD to sync'),
    'CTR - Rollout Health': ('ctr_health.yml', 'Wait for the rollout on the new digest, then /health'),
    'CTR - Verify (ACS)': ('ctr_verify.yml', 'ACS: the deployment runs the digest, with the fixed component version'),
    'CTR - Rollback': ('ctr_rollback.yml', 'Put the previous digest back through GitOps'),
    'CTR - Notify': ('ctr_notify.yml', 'The outcome card (Mattermost when configured)'),
}
PLAYBOOK_DIR = 'aap-setup/playbooks'


def gitlab(method: str, path: str, token: str, url: str, body: dict | None = None, ok404: bool = False):
    import ssl
    import urllib.request
    req = urllib.request.Request(f'{url}/api/v4{path}', json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={'PRIVATE-TOKEN': token, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=60) as r:
            return json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e:
        if ok404 and e.code == 404:
            return None
        sys.exit(f'GitLab {method} {path}: HTTP {e.code} {e.read().decode()[:300]}')


def seed_repo(url: str, token: str, dry: bool) -> dict:
    """telco/ctr-automation with the CTR playbooks, committed whenever they differ from this repository."""
    group = gitlab('GET', '/groups/telco', token, url, ok404=True)
    if not group:
        sys.exit('GitLab group telco not found: run ./ctr-setup/deploy.py first')
    proj = gitlab('GET', '/projects/' + urllib.parse.quote('telco/ctr-automation', safe=''), token, url, ok404=True)
    if not proj and not dry:
        proj = gitlab('POST', '/projects', token, url, {'name': 'ctr-automation', 'path': 'ctr-automation',
                                                        'namespace_id': group['id'], 'visibility': 'private'})
        print('  created telco/ctr-automation')
    if not proj:
        return {}
    actions = []
    for f in sorted((ROOT / PLAYBOOK_DIR).glob('ctr_*.yml')):
        path = f'{PLAYBOOK_DIR}/{f.name}'
        cur = gitlab('GET', f"/projects/{proj['id']}/repository/files/{urllib.parse.quote(path, safe='')}?ref=main",
                     token, url, ok404=True)
        text = f.read_text()
        if cur and base64.b64decode(cur['content']).decode() == text:
            continue
        actions.append({'action': 'update' if cur else 'create', 'file_path': path, 'content': text})
    if actions and not dry:
        gitlab('POST', f"/projects/{proj['id']}/repository/commits", token, url,
               {'branch': 'main', 'commit_message': 'CTR playbooks from agentic-patching', 'actions': actions,
                **({} if proj.get('default_branch') else {'start_branch': 'main'})})
    print(f"  telco/ctr-automation: {len(actions)} playbook(s) committed" if actions else '  telco/ctr-automation: up to date')
    return proj


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    load_env(ROOT / '.env')
    env = os.environ.get
    for k in ('AAP_BASE_URL', 'AAP_TOKEN', 'CTR_GITLAB_TOKEN', 'OCP_API_URL', 'ACS_URL', 'ACS_TOKEN', 'NEXUS_URL'):
        if not env(k):
            sys.exit(f'{k} is not set in .env')
    have = subprocess.run(['oc', 'whoami', '--show-server'], capture_output=True, text=True).stdout.strip()
    if have != env('OCP_API_URL'):
        sys.exit(f"oc is on '{have}', .env says '{env('OCP_API_URL')}'")
    # A cluster admin sees the GitLab route and the ctr-runner token; a less privileged login (user1) may not, so the
    # GitLab URL can come from .env, and an unreadable token keeps the one AAP already holds.
    route = subprocess.run(['oc', '-n', 'gitlab', 'get', 'route', '-o', 'jsonpath={.items[0].spec.host}'],
                           capture_output=True, text=True)
    gl_url = ('https://' + route.stdout.strip()) if route.returncode == 0 and route.stdout.strip() else env('CTR_GITLAB_URL', '').rstrip('/')
    if not gl_url:
        sys.exit('cannot read the GitLab route with this oc login: set CTR_GITLAB_URL in .env')
    runner = subprocess.run(['oc', '-n', 'agentic-patching', 'get', 'secret', 'ctr-runner-token', '-o', 'jsonpath={.data.token}'],
                            capture_output=True, text=True)
    if runner.returncode == 0 and runner.stdout:
        ocp_token = base64.b64decode(runner.stdout).decode()
    else:
        ocp_token = '$encrypted$'           # AAP keeps the stored secret
        print('  (ctr-runner token not readable with this login: the Containers credential keeps its current token)')
    api = Controller(env('AAP_BASE_URL'), env('AAP_TOKEN'), env('AAP_CA_BUNDLE') or None)

    def say(t):
        print('  ' + t)

    def upsert(endpoint, name, payload):
        row = api.find(endpoint, name)
        if args.dry_run:
            say(('would update ' if row else 'would create ') + name)
            return row['id'] if row else None
        if row:
            api.call('PATCH', f'{endpoint}{row["id"]}/', payload)
            say(f'updated {name} ({row["id"]})')
            return row['id']
        made = api.call('POST', endpoint, payload)
        say(f'created {name} ({made["id"]})')
        return made['id']

    print('GitLab')
    proj = seed_repo(gl_url, env('CTR_GITLAB_TOKEN'), args.dry_run)
    user = gitlab('GET', '/user', env('CTR_GITLAB_TOKEN'), gl_url)['username']

    print('Organization and execution environment')
    org = (api.find('/organizations/', 'Default') or {}).get('id') or int(env('AAP_DEFAULT_ORGANIZATION_ID', '1'))
    ee = (api.find('/execution_environments/', 'Default execution environment') or {}).get('id')
    say(f'organization {org}, execution environment {ee}')

    print('Credentials')
    scm_type = api.find('/credential_types/', 'Source Control')
    scm_id = upsert('/credentials/', 'CTR GitLab', {
        'name': 'CTR GitLab', 'organization': org, 'credential_type': scm_type['id'],
        'description': 'GitLab (telco group) for the CTR Automation project',
        'inputs': {'username': user, 'password': env('CTR_GITLAB_TOKEN')}})
    type_id = upsert('/credential_types/', 'Containers', {
        'name': 'Containers', 'kind': 'cloud',
        'description': 'GitLab, OpenShift, ACS and Nexus for the Containers (CTR) jobs',
        'inputs': {'fields': [
            {'id': 'gitlab_url', 'label': 'GitLab URL', 'type': 'string'},
            {'id': 'gitlab_token', 'label': 'GitLab token', 'type': 'string', 'secret': True},
            {'id': 'ocp_api', 'label': 'OpenShift API URL', 'type': 'string'},
            {'id': 'ocp_token', 'label': 'OpenShift token (ctr-runner)', 'type': 'string', 'secret': True},
            {'id': 'acs_url', 'label': 'ACS Central URL', 'type': 'string'},
            {'id': 'acs_token', 'label': 'ACS API token', 'type': 'string', 'secret': True},
            {'id': 'nexus_url', 'label': 'Nexus URL', 'type': 'string'},
            {'id': 'mattermost_webhook', 'label': 'Mattermost webhook (optional)', 'type': 'string', 'secret': True}],
            'required': ['gitlab_url', 'gitlab_token', 'ocp_api', 'ocp_token', 'acs_url', 'acs_token', 'nexus_url']},
        'injectors': {'env': {'CTR_GITLAB_URL': '{{ gitlab_url }}', 'CTR_GITLAB_TOKEN': '{{ gitlab_token }}',
                              'CTR_OCP_API': '{{ ocp_api }}', 'CTR_OCP_TOKEN': '{{ ocp_token }}',
                              'CTR_ACS_URL': '{{ acs_url }}', 'CTR_ACS_TOKEN': '{{ acs_token }}',
                              'CTR_NEXUS_URL': '{{ nexus_url }}', 'CTR_MATTERMOST_WEBHOOK': '{{ mattermost_webhook }}'}}})
    cred_id = upsert('/credentials/', 'Containers', {
        'name': 'Containers', 'organization': org, 'credential_type': type_id or 0,
        'inputs': {'gitlab_url': gl_url, 'gitlab_token': env('CTR_GITLAB_TOKEN'), 'ocp_api': env('OCP_API_URL'),
                   'ocp_token': ocp_token, 'acs_url': env('ACS_URL'), 'acs_token': env('ACS_TOKEN'),
                   'nexus_url': env('NEXUS_URL'), 'mattermost_webhook': env('CTR_MATTERMOST_WEBHOOK', '')}})

    print('Inventory')
    inv_id = upsert('/inventories/', 'CTR localhost', {'name': 'CTR localhost', 'organization': org,
                                                       'description': 'The CTR jobs call APIs only'})
    if inv_id and not args.dry_run:
        hosts = api.call('GET', f'/inventories/{inv_id}/hosts/?name=localhost').get('results') or []
        hv = json.dumps({'ansible_connection': 'local', 'ansible_python_interpreter': '{{ ansible_playbook_python }}'})
        if hosts:
            api.call('PATCH', f"/hosts/{hosts[0]['id']}/", {'variables': hv})
        else:
            api.call('POST', f'/inventories/{inv_id}/hosts/', {'name': 'localhost', 'variables': hv})
        say('host localhost')

    print('Project')
    proj_id = upsert('/projects/', 'CTR Automation', {
        'name': 'CTR Automation', 'organization': org, 'scm_type': 'git', 'scm_url': proj.get('http_url_to_repo', ''),
        'scm_branch': 'main', 'credential': scm_id, 'scm_update_on_launch': True,
        'description': 'The Containers playbooks, from GitLab telco/ctr-automation'})
    if proj_id and not args.dry_run:
        api.call('POST', f'/projects/{proj_id}/update/', {})
        for _ in range(90):
            p = api.call('GET', f'/projects/{proj_id}/')
            if p.get('status') in ('successful', 'failed', 'error', 'canceled'):
                break
            time.sleep(2)
        if p.get('status') != 'successful':
            sys.exit(f"CTR Automation sync {p.get('status')}: check that AAP can reach {p.get('scm_url')}")
        say('synced CTR Automation')

    print('Job templates')
    for name, (pb, desc) in TEMPLATES.items():
        jt = upsert('/job_templates/', name, {
            'name': name, 'description': desc, 'job_type': 'run', 'organization': org, 'inventory': inv_id or 0,
            'project': proj_id or 0, 'playbook': f'{PLAYBOOK_DIR}/{pb}', 'ask_variables_on_launch': True,
            'verbosity': 0, **({'execution_environment': ee} if ee else {})})
        if jt and cred_id and not args.dry_run:
            try:
                api.call('POST', f'/job_templates/{jt}/credentials/', {'id': cred_id})
            except SystemExit as exc:
                if 'HTTP 400' not in str(exc):
                    raise
    print('\nNext: DEF_FILE=ao-setup/ctr_workflow.json WF_NAME="Container Patch" ./ao-setup/create-ao-workflow.sh')


if __name__ == '__main__':
    main()
