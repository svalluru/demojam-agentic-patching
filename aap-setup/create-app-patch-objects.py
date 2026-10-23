#!/usr/bin/env python3
"""
Create the AAP objects the application patching job needs, through the controller API. This is all it needs: it does
not create the CVE templates or the generated-playbooks project that create-aap-objects.sh sets up.

    ./create-app-patch-objects.py --dry-run     show what would change
    ./create-app-patch-objects.py               create or update
    ./create-app-patch-objects.py --delete      remove the job template, Lightwell credential and its type

  credential type   GitHub Token                injects GITHUB_TOKEN              (only when the credential below is made)
  credential        github-token                from GIT_HUB_TOKEN; needs Contents read and write to push a branch
  project           DemoJam Agentic Patching    GITHUB_REPO_URL on PROJECT_BRANCH (default main), synced after it is made
  credential type   Lightwell Registry          injects LIGHTWELL_REGISTRY_USER and LIGHTWELL_REGISTRY_TOKEN
  credential        lightwell-registry          a Lightwell registry service account (only when both values are set)
  job template      App Patch - Clone, Update, Build
                                                playbooks/app_clone_update_build.yml, with the credentials below attached

The project, the GitHub token credential and the GitHub Token type are created only when they are missing, and are never
changed or deleted if they already exist (create-aap-objects.sh may own them); a new GIT_HUB_TOKEN does update an existing
github-token. The job template also needs the inventory to run on (Demo Inventory's localhost, the controller's execution
environment, is enough) and its machine credential, which must already exist. The host needs git 2.31 or newer, python3,
curl and tar; the playbook fetches the JDK and Maven it needs (or uses pip for Python projects). The playbook has to be
pushed to the branch the project tracks before the template can be made; the script checks that the project lists it.

Settings are read from the repository's .env (or the environment): AAP_BASE_URL, AAP_TOKEN, BUILD_INVENTORY,
MACHINE_CREDENTIAL, and optionally GIT_HUB_TOKEN, GITHUB_REPO_URL, PROJECT_BRANCH, LIGHTWELL_REGISTRY_USER,
LIGHTWELL_REGISTRY_TOKEN and AAP_CA_BUNDLE for a controller whose certificate comes from a private authority. Objects are
matched by name, so a re-run updates in place. Secrets are sent again on every run because the API never shows them back.
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK = 'aap-setup/playbooks/app_clone_update_build.yml'


def load_env(path):
    if path.exists():
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                v = v.split('  #', 1)[0].strip().strip('"').strip("'")
                if v:
                    os.environ.setdefault(k.strip(), v)


class Controller:
    def __init__(self, base, token, cafile=None):
        self.base = base.rstrip('/')
        self.token = token
        self.ctx = ssl.create_default_context(cafile=cafile)

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise SystemExit(f'{method} {path} -> HTTP {exc.code}: {exc.read().decode("utf-8", "replace")[:300]}')
        except (urllib.error.URLError, OSError) as exc:
            raise SystemExit(f'could not reach {self.base}: {exc}')

    def find(self, endpoint, name):
        found = self.call('GET', f'{endpoint}?name={urllib.parse.quote(name)}')
        return next((r for r in found.get('results', []) if r.get('name') == name), None)


def main():
    ap = argparse.ArgumentParser(description='Create the AAP objects for application patching.')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--delete', action='store_true')
    args = ap.parse_args()
    load_env(ROOT / '.env')
    env = os.environ.get
    base, token = env('AAP_BASE_URL', ''), env('AAP_TOKEN', '')
    if not (base and token):
        sys.exit('AAP_BASE_URL and AAP_TOKEN must be set in .env')
    names = {
        'type': env('LW_TYPE_NAME', 'Lightwell Registry'), 'cred': env('LW_CRED_NAME', 'lightwell-registry'),
        'template': env('APP_JT_NAME', 'App Patch - Clone, Update, Build'), 'project': env('PROJECT_NAME', 'DemoJam Agentic Patching'),
        'github': env('GH_CRED_NAME', 'github-token'), 'inventory': env('BUILD_INVENTORY', ''), 'machine': env('MACHINE_CREDENTIAL', ''),
        'gh_type': env('GH_TYPE_NAME', 'GitHub Token'),
    }
    repo_url, branch = env('GITHUB_REPO_URL', 'https://github.com/svalluru/demojam-agentic-patching'), env('PROJECT_BRANCH', 'main')
    api = Controller(base, token, env('AAP_CA_BUNDLE') or None)

    def say(text):
        print('  ' + text)

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

    if args.delete:
        for endpoint, key in (('/job_templates/', 'template'), ('/credentials/', 'cred'), ('/credential_types/', 'type')):
            row = api.find(endpoint, names[key])
            if row and not args.dry_run:
                api.call('DELETE', f'{endpoint}{row["id"]}/')
            say(('deleted ' if row and not args.dry_run else 'would delete ' if row else 'not present: ') + names[key])
        return

    org = int(env('AAP_DEFAULT_ORGANIZATION_ID', '1'))
    ee = int(env('AAP_DEFAULT_EXECUTION_ENVIRONMENT_ID', '2'))
    print('Credential type and credential')
    type_id = upsert('/credential_types/', names['type'], {
        'name': names['type'], 'description': 'Lightwell registry service account, as LIGHTWELL_REGISTRY_USER / _TOKEN', 'kind': 'cloud',
        'inputs': {'fields': [{'id': 'username', 'label': 'Username', 'type': 'string'},
                              {'id': 'token', 'label': 'Token', 'type': 'string', 'secret': True}], 'required': ['username', 'token']},
        'injectors': {'env': {'LIGHTWELL_REGISTRY_USER': '{{ username }}', 'LIGHTWELL_REGISTRY_TOKEN': '{{ token }}'}}})
    cred_id = None
    if env('LIGHTWELL_REGISTRY_USER') and env('LIGHTWELL_REGISTRY_TOKEN') and (type_id or args.dry_run):
        cred_id = upsert('/credentials/', names['cred'], {
            'name': names['cred'], 'credential_type': type_id or 0, 'organization': org,
            'inputs': {'username': env('LIGHTWELL_REGISTRY_USER'), 'token': env('LIGHTWELL_REGISTRY_TOKEN')}})
    else:
        say('LIGHTWELL_REGISTRY_USER / _TOKEN not set: no credential created, so builds can use Maven Central but not Lightwell builds')

    print('GitHub token')
    gh = api.find('/credentials/', names['github'])
    if gh and not env('GIT_HUB_TOKEN'):
        say(f'{names["github"]} exists, left as it is')
    elif env('GIT_HUB_TOKEN'):
        gh_type = api.find('/credential_types/', names['gh_type'])
        gh_type_id = gh_type['id'] if gh_type else upsert('/credential_types/', names['gh_type'], {
            'name': names['gh_type'], 'description': 'GitHub token exposed to the playbook as GITHUB_TOKEN', 'kind': 'cloud',
            'inputs': {'fields': [{'id': 'github_token', 'label': 'GitHub Token', 'type': 'string', 'secret': True}], 'required': ['github_token']},
            'injectors': {'env': {'GITHUB_TOKEN': '{{ github_token }}'}}})
        upsert('/credentials/', names['github'], {'name': names['github'], 'credential_type': gh_type_id or 0,
                                                  'organization': org, 'inputs': {'github_token': env('GIT_HUB_TOKEN')}})
    else:
        say('GIT_HUB_TOKEN not set and no github-token credential: a public repository can be cloned, but nothing can be pushed')

    print('Project')
    project = api.find('/projects/', names['project'])
    if project:
        say(f'{names["project"]} exists, left as it is (it follows {project.get("scm_url")} on {project.get("scm_branch")})')
    elif args.dry_run:
        say(f'would create {names["project"]} from {repo_url} on {branch}, then sync it')
    else:
        project = api.call('POST', '/projects/', {
            'name': names['project'], 'description': 'Playbooks for the agentic patching demo', 'organization': org, 'scm_type': 'git',
            'scm_url': repo_url, 'scm_branch': branch, 'scm_update_on_launch': True, 'scm_clean': True, 'scm_delete_on_update': False})
        say(f'created {names["project"]} ({project["id"]}) from {repo_url} on {branch}')
        api.call('POST', f'/projects/{project["id"]}/update/', {})
        for _ in range(60):
            project = api.call('GET', f'/projects/{project["id"]}/')
            if project.get('status') in ('successful', 'failed', 'error', 'canceled'):
                break
            time.sleep(2)
        if project.get('status') != 'successful':
            sys.exit(f'the project sync {project.get("status")}: check that {repo_url} has a branch "{branch}" and the controller can reach it')
        say('synced')
    if project:
        listed = api.call('GET', f'/projects/{project["id"]}/playbooks/')
        if PLAYBOOK not in listed:
            sys.exit(f'the project does not list {PLAYBOOK}. Push the playbook (and aap-setup/playbooks/files/) to the branch it follows, '
                     'sync the project, and run this again')

    print('Job template')
    inventory = api.find('/inventories/', names['inventory']) if names['inventory'] else None
    if not inventory:
        sys.exit('set BUILD_INVENTORY to the inventory the job runs on (for example Demo Inventory)')
    if args.dry_run and not project:
        project = {'id': 0}
    jt_id = upsert('/job_templates/', names['template'], {
        'name': names['template'], 'description': 'Clone a repository, apply approved dependency changes, build, optionally push a branch',
        'job_type': 'run', 'organization': org, 'inventory': inventory['id'], 'project': project['id'], 'playbook': PLAYBOOK,
        'execution_environment': ee, 'ask_variables_on_launch': True, 'ask_limit_on_launch': True, 'verbosity': 0})
    wanted = [(names['github'], 'GitHub token'), (names['cred'], 'Lightwell registry'), (names['machine'], 'machine')]
    for name, label in wanted:
        if not name or (label == 'Lightwell registry' and not cred_id):
            continue
        row = api.find('/credentials/', name)
        if not row and args.dry_run and name == names['github'] and env('GIT_HUB_TOKEN'):
            say(f'would attach {name}')
        elif not row:
            say(f'WARNING: no {label} credential named "{name}", so it is not attached')
        elif args.dry_run or not jt_id:
            say(f'would attach {name}')
        else:
            try:
                api.call('POST', f'/job_templates/{jt_id}/credentials/', {'id': row['id']})
                say(f'attached {name}')
            except SystemExit as exc:
                if 'HTTP 400' not in str(exc):
                    raise
                say(f'{name} already attached')
    print('\nThe playbook must be pushed to the branch the project tracks (and the project synced) before a job can run it.')


if __name__ == '__main__':
    main()
