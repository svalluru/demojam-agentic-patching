#!/usr/bin/env python3
"""
Create the AAP objects Applications v2 needs, through the controller API. New objects only: the lab's own projects,
templates and credentials are read, never changed.

    ./aap-setup/create-app-v2-objects.py --dry-run          show what would change
    ./aap-setup/create-app-v2-objects.py                    create or update
    ./aap-setup/create-app-v2-objects.py --deploy-sample    also deploy the BOM's apps to their hosts
    ./aap-setup/create-app-v2-objects.py --seed-repos       also commit each BOM app with a "repo" to the lab Gitea
                                                            (app_source.py), for Rebuild from source
    ./aap-setup/create-app-v2-objects.py --delete           remove what this script created

  project        App Patch v2 - Setup Playbooks     this repository (GITHUB_REPO_URL) on PROJECT_BRANCH_V2, for the
                                                     commit, test-in-a-pod, seed and deploy playbooks
  project        App Patch v2 Playbooks             the Gitea repository GITEA_REPO (default lab-user/app_v2_playbooks),
                                                     with the lab's Gitea source-control credential, synced on launch
  credential     Gitea (App Patch v2)               injects GITEA_URL / GITEA_USERNAME / GITEA_TOKEN for the commit job;
                                                     see "Gitea access" below
  job template   App Patch v2 - Commit to Gitea     aap-setup/playbooks/app_v2_commit.yml on BUILD_INVENTORY (localhost)
  job template   App Patch v2 - Sync and Run        app_v2_run.yml from the Gitea project, on TARGET_INVENTORY with
                                                     MACHINE_CREDENTIAL
  job template   App Patch v2 - Deploy Sample App   aap-setup/playbooks/app_v2_deploy_sample.yml, same inventory

The Sync and Run template needs app_v2_run.yml to exist in the Gitea repository before AAP will accept it, and the
repository starts empty. So the commit template is launched once with init_only=true, which commits just the runner;
then the Gitea project is synced and the template is created.

Gitea access. The lab already reaches Gitea: its project for lightspeed_playbooks has a source-control credential,
and that is reused for the App Patch v2 Playbooks project (attached, not edited). A source-control credential cannot
be attached to a job template, though, and the commit job has to push. So that job gets its own credential of a small
custom type. Its values come from GITEA_USERNAME and GITEA_TOKEN in .env; GITEA_URL defaults to the host of the lab
project's repository. If the lab's Fetch and Commit template carries a credential that already injects GITEA_URL and
GITEA_TOKEN, that one is attached instead and nothing new is needed.

Settings come from the repository's .env: AAP_BASE_URL, AAP_TOKEN, and optionally GITHUB_REPO_URL, PROJECT_BRANCH_V2,
GITEA_REPO, GITEA_URL, GITEA_USERNAME, GITEA_TOKEN, BUILD_INVENTORY (default Demo Inventory), TARGET_INVENTORY
(default lab-inventory), MACHINE_CREDENTIAL (default lab-credential), SAMPLE_HOSTS (default: every server in app-data/bom).
The two setup playbooks must be pushed to PROJECT_BRANCH_V2 first; the script checks the project lists them.
"""
import argparse
import importlib.util
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# Controller and load_env are the v1 script's; one copy of the API client.
_spec = importlib.util.spec_from_file_location('v1objects', HERE / 'create-app-patch-objects.py')
_v1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_v1)
Controller, load_env = _v1.Controller, _v1.load_env

COMMIT_PB = 'aap-setup/playbooks/app_v2_commit.yml'
SAMPLE_PB = 'aap-setup/playbooks/app_v2_deploy_sample.yml'
RUN_PB = 'app_v2_run.yml'
TEST_PB = 'aap-setup/playbooks/app_v2_test_pod.yml'
SEED_PB = 'aap-setup/playbooks/app_v2_seed_repos.yml'
ROLLBACK_PB = 'aap-setup/playbooks/app_v2_rollback.yml'
NOTIFY_PB = 'aap-setup/playbooks/app_v2_notify.yml'
# The class /health probes for each library: one copy, in appv2.py, which the test in a pod uses too.
sys.path.insert(0, str(ROOT))
from appv2 import PROBE_CLASS  # noqa: E402


def sample_apps(hosts=None):
    """Deploy variables for each app in app-data/bom that has servers: its Maven jars, port, hosts and probes.
    SAMPLE_HOSTS, if set, narrows the hosts."""
    out = []
    for f in sorted((ROOT / 'app-data' / 'bom').glob('*.json')):
        bom = json.loads(f.read_text())
        maven = [d for d in bom.get('dependencies', []) if d.get('ecosystem', 'maven') == 'maven']
        names = [s['host'] for s in bom.get('servers', []) if not hosts or s['host'] in hosts]
        if not maven or not names:
            continue
        jars = [{'path': f"{d['group'].replace('.', '/')}/{d['artifact']}/{d['version']}/{d['artifact']}-{d['version']}.jar"}
                for d in maven]
        jars.append({'path': 'org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar'})   # zookeeper and others log through it
        out.append({'app_name': bom['app'], 'app_port': int(urllib.parse.urlparse(bom['health_url']).port or 8080),
                    'target_hosts': ','.join(names), 'jars': jars,
                    'probes': ','.join(f"{d['artifact']}={PROBE_CLASS[d['artifact']]}" for d in maven
                                       if d['artifact'] in PROBE_CLASS)})
    return out

N = {
    'setup_project': 'App Patch v2 - Setup Playbooks',
    'gitea_project': 'App Patch v2 Playbooks',
    'gitea_type': 'Gitea Token (App Patch v2)',
    'gitea_cred': 'Gitea (App Patch v2)',
    'commit_jt': 'App Patch v2 - Commit to Gitea',
    'test_jt': 'App Patch v2 - Test in a Pod',
    'seed_jt': 'App Patch v2 - Seed App Repos',
    'ocp_type': 'OpenShift API (App Patch v2)',
    'ocp_cred': 'OpenShift Pipelines (App Patch v2)',
    'run_jt': 'App Patch v2 - Sync and Run',
    'sample_jt': 'App Patch v2 - Deploy Sample App',
    'rollback_jt': 'App Patch v2 - Rollback',
    'notify_jt': 'App Patch v2 - Notify Mattermost',
}
# The lab's Mattermost credential (mattermost_url, api_chat_token), the one the RHEL CVE workflow's notify template
# uses. Attached to App Patch v2 - Notify Mattermost, never edited.
LAB_MATTERMOST_CRED = 'Mattermost'
LAB_FETCH_JT = 'CVE - Fetch and Commit'


def main():
    ap = argparse.ArgumentParser(description='Create the AAP objects for Applications v2.')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--delete', action='store_true')
    ap.add_argument('--deploy-sample', action='store_true', help="deploy the BOM's apps to their servers and wait")
    ap.add_argument('--seed-repos', action='store_true',
                    help="commit each BOM app's Maven source (app_source.py) to its Gitea repository")
    args = ap.parse_args()
    load_env(ROOT / '.env')
    env = os.environ.get
    if not (env('AAP_BASE_URL') and env('AAP_TOKEN')):
        sys.exit('AAP_BASE_URL and AAP_TOKEN must be set in .env')
    api = Controller(env('AAP_BASE_URL'), env('AAP_TOKEN'), env('AAP_CA_BUNDLE') or None)
    org = int(env('AAP_DEFAULT_ORGANIZATION_ID', '1'))
    ee = int(env('AAP_DEFAULT_EXECUTION_ENVIRONMENT_ID', '2'))
    gitea_repo = env('GITEA_REPO', 'lab-user/app_v2_playbooks')

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

    def attach(jt_id, cred_id, label):
        if args.dry_run or not jt_id or not cred_id:
            say(f'would attach {label}')
            return
        try:
            api.call('POST', f'/job_templates/{jt_id}/credentials/', {'id': cred_id})
            say(f'attached {label}')
        except SystemExit as exc:
            if 'HTTP 400' not in str(exc):
                raise
            say(f'{label} already attached')

    def sync(project_id, label):
        api.call('POST', f'/projects/{project_id}/update/', {})
        for _ in range(90):
            p = api.call('GET', f'/projects/{project_id}/')
            if p.get('status') in ('successful', 'failed', 'error', 'canceled'):
                break
            time.sleep(2)
        if p.get('status') != 'successful':
            sys.exit(f'{label} sync {p.get("status")}: check that the controller can reach {p.get("scm_url")}')
        say(f'synced {label}')

    def launch(jt_id, extra, label):
        job = api.call('POST', f'/job_templates/{jt_id}/launch/', {'extra_vars': extra})
        say(f'launched {label} (job {job["id"]})')
        for _ in range(300):
            j = api.call('GET', f'/jobs/{job["id"]}/')
            if j.get('status') in ('successful', 'failed', 'error', 'canceled'):
                break
            time.sleep(3)
        if j.get('status') != 'successful':
            sys.exit(f'{label} {j.get("status")}: see job {job["id"]} in AAP')
        say(f'{label} successful')

    if args.delete:
        for endpoint, key in (('/job_templates/', 'rollback_jt'), ('/job_templates/', 'notify_jt'), ('/job_templates/', 'seed_jt'), ('/job_templates/', 'sample_jt'), ('/job_templates/', 'run_jt'), ('/job_templates/', 'commit_jt'),
                              ('/job_templates/', 'test_jt'), ('/credentials/', 'ocp_cred'), ('/credential_types/', 'ocp_type'),
                              ('/credentials/', 'gitea_cred'), ('/credential_types/', 'gitea_type'),
                              ('/projects/', 'gitea_project'), ('/projects/', 'setup_project')):
            row = api.find(endpoint, N[key])
            if row and not args.dry_run:
                api.call('DELETE', f'{endpoint}{row["id"]}/')
            say(('deleted ' if row and not args.dry_run else 'would delete ' if row else 'not present: ') + N[key])
        print('The Gitea repository and its commits are left as they are.')
        return

    # ---------------------------------------------------------------- what the lab already has (read only)
    print('Lab objects (read only)')
    lab_scm = next((p for p in api.call('GET', '/projects/?page_size=200').get('results', [])
                    if 'lightspeed_playbooks' in (p.get('scm_url') or '')), None)
    if not lab_scm:
        sys.exit('no lab project on lightspeed_playbooks found; set GITEA_URL and attach a Gitea credential by hand')
    parsed = urllib.parse.urlparse(lab_scm['scm_url'])
    gitea_url = env('GITEA_URL') or f'{parsed.scheme}://{parsed.netloc.split("@")[-1]}'
    say(f'Gitea at {gitea_url} (from project "{lab_scm["name"]}"); its credential: {lab_scm.get("credential") or "none"}')

    lab_fetch = api.find('/job_templates/', LAB_FETCH_JT)
    reuse = None
    if lab_fetch:
        for c in api.call('GET', f'/job_templates/{lab_fetch["id"]}/credentials/').get('results', []):
            ctype = api.call('GET', f'/credential_types/{c["credential_type"]}/')
            injected = set(((ctype.get('injectors') or {}).get('env') or {}).keys())
            say(f'{LAB_FETCH_JT} has "{c["name"]}" ({ctype.get("name")}) injecting {sorted(injected) or "nothing as env"}')
            if {'GITEA_URL', 'GITEA_TOKEN'} <= injected or {'GITEA_URL', 'GITEA_PASSWORD'} <= injected:
                reuse = c
    else:
        say(f'no "{LAB_FETCH_JT}" template found')

    # ---------------------------------------------------------------- projects
    print('Projects')
    repo_url = env('GITHUB_REPO_URL', 'https://github.com/svalluru/demojam-agentic-patching')
    branch = env('PROJECT_BRANCH_V2', 'infra-app-agentic-patching')
    setup_id = upsert('/projects/', N['setup_project'], {
        'name': N['setup_project'], 'description': 'Applications v2 setup playbooks (commit to Gitea, sample app)',
        'organization': org, 'scm_type': 'git', 'scm_url': repo_url, 'scm_branch': branch,
        # Synced at most every 5 minutes: these playbooks change with a push, not per run, and a sync on every
        # launch added to each job's start (the Gitea project below must still sync every time: each run commits).
        'scm_update_on_launch': True, 'scm_update_cache_timeout': 300, 'scm_clean': True})
    gitea_id = upsert('/projects/', N['gitea_project'], {
        'name': N['gitea_project'], 'description': 'Generated Applications v2 playbooks, committed by the workflow',
        'organization': org, 'scm_type': 'git', 'scm_url': f'{gitea_url}/{gitea_repo}.git', 'scm_branch': '',
        'credential': lab_scm.get('credential'), 'scm_update_on_launch': True, 'scm_clean': True})
    if not args.dry_run:
        sync(setup_id, N['setup_project'])
        listed = api.call('GET', f'/projects/{setup_id}/playbooks/')
        missing = [p for p in (COMMIT_PB, SAMPLE_PB, TEST_PB, SEED_PB) if p not in listed]
        if missing:
            sys.exit(f'{N["setup_project"]} does not list {", ".join(missing)}: push them to {branch} and run this again')

    # ---------------------------------------------------------------- Gitea credential for the commit job
    print('Gitea credential for the commit job')
    if reuse:
        gitea_cred_id = reuse['id']
        say(f'reusing the lab credential "{reuse["name"]}"')
    elif env('GITEA_TOKEN') and env('GITEA_USERNAME'):
        type_id = upsert('/credential_types/', N['gitea_type'], {
            'name': N['gitea_type'], 'kind': 'cloud', 'description': 'Gitea URL and token for the App Patch v2 commit job',
            'inputs': {'fields': [{'id': 'url', 'label': 'Gitea URL', 'type': 'string'},
                                  {'id': 'username', 'label': 'Username', 'type': 'string'},
                                  {'id': 'token', 'label': 'Token', 'type': 'string', 'secret': True}],
                       'required': ['url', 'username', 'token']},
            'injectors': {'env': {'GITEA_URL': '{{ url }}', 'GITEA_USERNAME': '{{ username }}', 'GITEA_TOKEN': '{{ token }}'}}})
        gitea_cred_id = upsert('/credentials/', N['gitea_cred'], {
            'name': N['gitea_cred'], 'credential_type': type_id or 0, 'organization': org,
            'inputs': {'url': gitea_url, 'username': env('GITEA_USERNAME'), 'token': env('GITEA_TOKEN')}})
    else:
        sys.exit('The commit job needs to push to Gitea. The lab credential is a source-control one, which AAP will not '
                 'attach to a job template. Add GITEA_USERNAME and GITEA_TOKEN (a Gitea access token with repo write '
                 f'on {gitea_repo}) to .env and run this again.')

    # ---------------------------------------------------------------- templates
    print('Job templates')
    build_inv = api.find('/inventories/', env('BUILD_INVENTORY', 'Demo Inventory'))
    target_inv = api.find('/inventories/', env('TARGET_INVENTORY', 'lab-inventory'))
    machine = api.find('/credentials/', env('MACHINE_CREDENTIAL', 'lab-credential'))
    if not (build_inv and target_inv and machine):
        sys.exit('set BUILD_INVENTORY, TARGET_INVENTORY and MACHINE_CREDENTIAL to objects that exist in AAP')
    common = {'job_type': 'run', 'organization': org, 'execution_environment': ee,
              'ask_variables_on_launch': True, 'verbosity': 0}
    commit_id = upsert('/job_templates/', N['commit_jt'], {
        **common, 'name': N['commit_jt'], 'inventory': build_inv['id'], 'project': setup_id or 0, 'playbook': COMMIT_PB,
        'description': 'Verify a Lightwell build (cosign) and commit a generated playbook to Gitea'})
    attach(commit_id, gitea_cred_id, 'the Gitea credential')
    # The test in a pod: AAP starts the OpenShift Pipelines run with the token pipelines-setup/deploy.sh wrote.
    if env('APPV2_PIPELINE_TOKEN'):
        ocp_type = upsert('/credential_types/', N['ocp_type'], {
            'name': N['ocp_type'], 'kind': 'cloud', 'description': 'OpenShift API token for the App Patch v2 test in a pod',
            'inputs': {'fields': [{'id': 'url', 'label': 'API URL', 'type': 'string'},
                                  {'id': 'namespace', 'label': 'Namespace', 'type': 'string'},
                                  {'id': 'token', 'label': 'Token', 'type': 'string', 'secret': True}],
                       'required': ['url', 'namespace', 'token']},
            'injectors': {'env': {'OCP_API_URL': '{{ url }}', 'OCP_NAMESPACE': '{{ namespace }}', 'OCP_TOKEN': '{{ token }}'}}})
        ocp_cred = upsert('/credentials/', N['ocp_cred'], {
            'name': N['ocp_cred'], 'credential_type': ocp_type or 0, 'organization': org,
            # AAP runs on the same cluster: the in-cluster API address needs no route or external DNS.
            'inputs': {'url': env('APPV2_PIPELINE_API_URL', 'https://kubernetes.default.svc'),
                       'namespace': env('APPV2_PIPELINE_NAMESPACE', 'agentic-patching'),
                       'token': env('APPV2_PIPELINE_TOKEN')}})
        test_id = upsert('/job_templates/', N['test_jt'], {
            **common, 'name': N['test_jt'], 'inventory': build_inv['id'], 'project': setup_id or 0, 'playbook': TEST_PB,
            'description': 'Build the app with the change in OpenShift Pipelines, start it in a pod and check /health'})
        attach(test_id, ocp_cred, 'the OpenShift credential')
        attach(test_id, gitea_cred_id, 'the Gitea credential (for the SBOM)')
    else:
        say(f'no APPV2_PIPELINE_TOKEN: skipping {N["test_jt"]} (run pipelines-setup/deploy.sh first)')
    seed_id = upsert('/job_templates/', N['seed_jt'], {
        **common, 'name': N['seed_jt'], 'inventory': build_inv['id'], 'project': setup_id or 0, 'playbook': SEED_PB,
        'description': "Commit each demo app's Maven source to its Gitea repository (Rebuild from source)"})
    attach(seed_id, gitea_cred_id, 'the Gitea credential')
    sample_id = upsert('/job_templates/', N['sample_jt'], {
        **common, 'name': N['sample_jt'], 'inventory': target_inv['id'], 'project': setup_id or 0, 'playbook': SAMPLE_PB,
        'description': 'Deploy the Applications v2 apps from app-data/bom'})
    attach(sample_id, machine['id'], machine['name'])

    # The workflow's rollback route: puts a failed site back on its original jars (rollback_json from the failed run).
    rollback_id = upsert('/job_templates/', N['rollback_jt'], {
        **common, 'name': N['rollback_jt'], 'inventory': target_inv['id'], 'project': setup_id or 0,
        'playbook': ROLLBACK_PB, 'description': 'Roll a site back to its original jars after a failed App Patch v2 run'})
    attach(rollback_id, machine['id'], machine['name'])
    # Every route ends in a Mattermost card, on the lab's channel, through the lab's credential.
    mm = api.find('/credentials/', env('MATTERMOST_CREDENTIAL', LAB_MATTERMOST_CRED))
    if mm:
        notify_id = upsert('/job_templates/', N['notify_jt'], {
            **common, 'name': N['notify_jt'], 'inventory': build_inv['id'], 'project': setup_id or 0,
            'playbook': NOTIFY_PB, 'description': 'Post an App Patch v2 outcome (patched, rolled back, test failed) to Mattermost'})
        attach(notify_id, mm['id'], f"the lab's {mm['name']} credential (reused, not edited)")
    else:
        say(f'no {LAB_MATTERMOST_CRED!r} credential in AAP: skipping {N["notify_jt"]}; the workflow\'s notify nodes will '
            'fail until it exists (set MATTERMOST_CREDENTIAL to use another)')

    if not args.dry_run:
        listed = api.call('GET', f'/projects/{gitea_id}/playbooks/')
        if RUN_PB not in listed:
            say(f'{gitea_repo} has no {RUN_PB} yet; committing it')
            launch(commit_id, {'init_only': True, 'run_id': 'init', 'gitea_repo': gitea_repo}, 'the runner commit')
        sync(gitea_id, N['gitea_project'])
    upsert('/job_templates/', N['run_jt'], {
        **common, 'name': N['run_jt'], 'inventory': target_inv['id'], 'project': gitea_id or 0, 'playbook': RUN_PB,
        'description': 'Sync the generated playbooks and run the approved one (checked by sha256)'})
    run_row = api.find('/job_templates/', N['run_jt'])
    attach(run_row['id'] if run_row else None, machine['id'], machine['name'])

    if args.seed_repos and not args.dry_run:
        import base64
        import app_source
        print('App source repositories (from app-data/bom)')
        repos = [{'name': bom['repo'].split('/', 1)[-1], 'description': f"{bom['app']} · {bom.get('domain', '')} · Applications v2 demo app",
                  'files': [{'path': path, 'content_b64': base64.b64encode(text.encode()).decode()}
                            for path, text in app_source.render(bom, PROBE_CLASS).items()]}
                 for bom in app_source.repo_apps()]
        launch(seed_id, {'repos': repos}, f"{N['seed_jt']}: {', '.join(r['name'] for r in repos)}")

    if args.deploy_sample and not args.dry_run:
        print('Sample apps (from app-data/bom)')
        narrow = [h for h in env('SAMPLE_HOSTS', '').split(',') if h]
        for app in sample_apps(narrow):
            launch(sample_id, app, f"{N['sample_jt']}: {app['app_name']} on {app['target_hosts']}")

    print('\nNext: DEF_FILE=ao-setup/app_v2_workflow.json WF_NAME="App Patch v2" ./ao-setup/create-ao-workflow.sh')


if __name__ == '__main__':
    main()
