#!/usr/bin/env python3
"""Set up the Containers side on the cluster in OCP_API_URL. Idempotent: each step keeps what is already there.

    ./ctr-setup/deploy.py                 everything below
    ./ctr-setup/deploy.py --no-build      skip the first image builds (repos, namespaces, pipeline, Argo CD only)

1. Namespaces nfvo-lab, nfvo-prod, oss-lab, oss-prod (label env=lab|prod, managed by OpenShift GitOps), allowed to
   pull the app images from agentic-patching's internal registry.
2. Secrets in agentic-patching: ctr-gitlab-auth (git-clone basic auth), ctr-acs (roxctl), ctr-cosign (a key pair,
   generated in the cluster by cosign itself; the private key never leaves it).
3. The ctr-build pipeline (ctr-setup/pipeline.yaml).
4. GitLab group telco: app-workflow-engine and app-inventory-service (rendered from app-data/bom by app_source.py,
   plus a Containerfile on UBI 9.4), and gitops (apps/<cluster>/<namespace>/<app>/: a Deployment, a Service and a
   kustomization that pins the image by digest).
5. The first images: one ctr-build run per app on main (enforce=false: the old libraries fail roxctl on purpose),
   their digests committed to the gitops repo.
6. Argo CD: the gitops repository and one auto-synced Application per app and namespace.

Needs in .env: OCP_API_URL (oc must be logged in to it), CTR_GITLAB_TOKEN, ACS_URL, ACS_TOKEN, NEXUS_URL.
"""
from __future__ import annotations

import argparse
import base64
import json
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app_source  # noqa: E402
import appv2       # noqa: E402

NS = 'agentic-patching'
GROUP = 'telco'
CLUSTER = 'production'            # the ACS cluster name: GitOps paths use it, as ACS reports it
REGISTRY = f'image-registry.openshift-image-registry.svc:5000/{NS}'
UBI = 'registry.access.redhat.com/ubi9/ubi-minimal:9.4'
# app -> (port, {namespace: (env, replicas)})
APPS = {
    'workflow-engine': (8090, {'nfvo-lab': ('lab', 1), 'nfvo-prod': ('prod', 3)}),
    'inventory-service': (8091, {'oss-lab': ('lab', 1), 'oss-prod': ('prod', 2)}),
}


def load_env() -> dict[str, str]:
    env = {}
    for line in (ROOT / '.env').read_text().splitlines():
        line = line.strip()
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            env[k.strip()] = v.split(' #')[0].strip().strip("'\"")
    return env


ENV = load_env()
CTX = ssl.create_default_context()


def step(title: str) -> None:
    print(f'\n=== {title} ===', flush=True)


def oc(*args: str, stdin: str | None = None, check: bool = True) -> str:
    r = subprocess.run(['oc', *args], input=stdin.encode() if stdin is not None else None, capture_output=True)
    if check and r.returncode:
        raise SystemExit(f"oc {' '.join(args)}: {r.stderr.decode().strip()}")
    return r.stdout.decode()


def apply(obj: dict | list) -> None:
    items = obj if isinstance(obj, list) else [obj]
    oc('apply', '-f', '-', stdin=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}))


def exists(kind: str, name: str, ns: str = NS) -> bool:
    return subprocess.run(['oc', '-n', ns, 'get', kind, name], capture_output=True).returncode == 0


# ---------------------------------------------------------------------------- GitLab

GITLAB = 'https://' + oc('-n', 'gitlab', 'get', 'route', '-o', 'jsonpath={.items[0].spec.host}').strip()


def gl(method: str, path: str, body: dict | None = None, ok404: bool = False):
    req = urllib.request.Request(f'{GITLAB}/api/v4{path}', json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={'PRIVATE-TOKEN': ENV['CTR_GITLAB_TOKEN'],
                                                         'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            return json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e:
        if ok404 and e.code == 404:
            return None
        raise SystemExit(f'GitLab {method} {path}: HTTP {e.code} {e.read().decode()[:300]}')


def ensure_group() -> int:
    g = gl('GET', f'/groups/{GROUP}', ok404=True)
    if not g:
        g = gl('POST', '/groups', {'name': GROUP, 'path': GROUP, 'visibility': 'private'})
        print(f'  created group {GROUP}')
    return g['id']


def ensure_project(gid: int, name: str) -> dict:
    p = gl('GET', f"/projects/{urllib.parse.quote(f'{GROUP}/{name}', safe='')}", ok404=True)
    if not p:
        p = gl('POST', '/projects', {'name': name, 'path': name, 'namespace_id': gid, 'visibility': 'private',
                                     'initialize_with_readme': False, 'default_branch': 'main'})
        print(f'  created {GROUP}/{name}')
    return p


def commit(project: dict, files: dict[str, str], message: str, branch: str = 'main') -> bool:
    """One commit with every file that differs (create or update). Returns whether anything changed."""
    pid, actions = project['id'], []
    for path, content in files.items():
        cur = gl('GET', f"/projects/{pid}/repository/files/{urllib.parse.quote(path, safe='')}?ref={branch}", ok404=True)
        if cur and base64.b64decode(cur['content']).decode() == content:
            continue
        actions.append({'action': 'update' if cur else 'create', 'file_path': path, 'content': content})
    if not actions:
        return False
    gl('POST', f'/projects/{pid}/repository/commits', {'branch': branch, 'commit_message': message, 'actions': actions})
    return True


def read_file(project: dict, path: str, branch: str = 'main') -> str:
    cur = gl('GET', f"/projects/{project['id']}/repository/files/{urllib.parse.quote(path, safe='')}?ref={branch}", ok404=True)
    return base64.b64decode(cur['content']).decode() if cur else ''


# Lightwell's public demo repository has only spring-webmvc, spring-expression and spring-core; their rhlw POMs depend
# on the sibling Spring modules at the same rhlw version, which only the full Lightwell repository has. Pinning the
# siblings at the upstream release lets Maven build with the demo repository: the three Lightwell builds come from
# Lightwell, the rest stay upstream.
SIBLING_PINS = {'org.springframework': ['spring-aop', 'spring-beans', 'spring-context', 'spring-web', 'spring-jcl']}


def pin_siblings(pom: str, bom: dict) -> str:
    deps = app_source.maven_deps(bom)
    pins = []
    for group, arts in SIBLING_PINS.items():
        mine = [d for d in deps if d['group'] == group]
        if not mine:
            continue
        version = appv2.upstream(mine[0]['version'])
        pins += [f'      <dependency><groupId>{group}</groupId><artifactId>{a}</artifactId><version>{version}</version></dependency>'
                 for a in arts if a not in {d['artifact'] for d in mine}]
    if not pins or '<dependencyManagement>' in pom:
        return pom
    block = ('  <!-- Spring modules Lightwell\'s demo repository does not have: the upstream release (see ctr-setup/deploy.py). -->\n'
             '  <dependencyManagement>\n    <dependencies>\n' + '\n'.join(pins) + '\n    </dependencies>\n  </dependencyManagement>\n\n')
    return pom.replace('  <dependencies>', block + '  <dependencies>', 1)


def containerfile(app: str) -> str:
    return (f'# {app}: the Containers demo image. The base and the jars are what ACS scans; a fix edits the FROM line\n'
            f'# (a newer UBI) or pom.xml (a Lightwell build), and the image is rebuilt, never patched in place.\n'
            f'FROM {UBI}\n'
            'RUN microdnf install -y --nodocs java-17-openjdk-headless && microdnf clean all\n'
            'COPY target/lib/ /deployments/lib/\n'
            f'COPY target/{app}.jar /deployments/lib/{app}.jar\n'
            'USER 1001\n'
            'ENTRYPOINT ["java", "-cp", "/deployments/lib/*", "HealthServer"]\n')


def gitops_files(app: str, ns: str, env: str, replicas: int, digest: str) -> dict[str, str]:
    port = APPS[app][0]
    bom = json.loads((ROOT / 'app-data' / 'bom' / f'{app}.json').read_text())
    probes = ','.join(f"{d['artifact']}={appv2.PROBE_CLASS[d['artifact']]}" for d in app_source.maven_deps(bom)
                      if d['artifact'] in appv2.PROBE_CLASS)
    base = f'apps/{CLUSTER}/{ns}/{app}'
    dep = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
           'metadata': {'name': app, 'labels': {'app': app, 'env': env}},
           'spec': {'replicas': replicas, 'selector': {'matchLabels': {'app': app}},
                    'strategy': {'rollingUpdate': {'maxUnavailable': 1, 'maxSurge': 1}},
                    'template': {'metadata': {'labels': {'app': app, 'env': env}},
                                 'spec': {'containers': [{
                                     'name': app, 'image': 'APP_IMAGE', 'ports': [{'containerPort': port}],
                                     'env': [{'name': 'PORT', 'value': str(port)}, {'name': 'PROBES', 'value': probes}],
                                     'readinessProbe': {'httpGet': {'path': '/health', 'port': port}, 'periodSeconds': 5},
                                     'resources': {'requests': {'cpu': '20m', 'memory': '96Mi'},
                                                   'limits': {'cpu': '500m', 'memory': '384Mi'}}}]}}}}
    svc = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': app},
           'spec': {'selector': {'app': app}, 'ports': [{'port': port, 'targetPort': port}]}}
    kust = ('apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n'
            'resources:\n  - deployment.json\n  - service.json\n'
            f'images:\n  - name: APP_IMAGE\n    newName: {REGISTRY}/{app}\n    digest: {digest}\n')
    return {f'{base}/deployment.json': json.dumps(dep, indent=2) + '\n',
            f'{base}/service.json': json.dumps(svc, indent=2) + '\n',
            f'{base}/kustomization.yaml': kust}


# ---------------------------------------------------------------------------- steps

def preflight() -> None:
    want, have = ENV.get('OCP_API_URL', ''), oc('whoami', '--show-server', check=False).strip()
    if not want or have != want:
        raise SystemExit(f"oc is on '{have or 'nothing'}', .env says '{want}': log in to the right cluster first")
    for k in ('CTR_GITLAB_TOKEN', 'ACS_URL', 'ACS_TOKEN', 'NEXUS_URL'):
        if not ENV.get(k):
            raise SystemExit(f'{k} is not set in .env')
    print(f'  cluster {have}\n  GitLab {GITLAB}\n  Nexus {ENV["NEXUS_URL"]}')


def namespaces() -> None:
    step('Namespaces')
    for app, (_, sites) in APPS.items():
        for ns, (env, _) in sites.items():
            apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns, 'labels': {
                'env': env, 'app.kubernetes.io/part-of': 'agentic-patching',
                'argocd.argoproj.io/managed-by': 'openshift-gitops'}}})
            apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
                   'metadata': {'name': f'image-puller-{ns}', 'namespace': NS},
                   'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'system:image-puller'},
                   'subjects': [{'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Group', 'name': f'system:serviceaccounts:{ns}'}]})
            print(f'  {ns} ({env})')


def secrets() -> None:
    step('Secrets')
    user = gl('GET', '/user')['username']
    host = GITLAB.split('//', 1)[1]
    apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'ctr-gitlab-auth', 'namespace': NS},
           'stringData': {'.git-credentials': f"https://{user}:{ENV['CTR_GITLAB_TOKEN']}@{host}\n",
                          '.gitconfig': '[credential]\n  helper = store\n'}})
    apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'ctr-acs', 'namespace': NS},
           'stringData': {'endpoint': ENV['ACS_URL'].split('//', 1)[-1].rstrip('/'), 'token': ENV['ACS_TOKEN']}})
    print('  ctr-gitlab-auth, ctr-acs')
    if exists('secret', 'ctr-cosign'):
        print('  kept ctr-cosign')
        return
    # cosign generates the pair and writes it straight into the secret: the private key never leaves the cluster.
    apply([{'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'ctr-keygen', 'namespace': NS}},
           {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'ctr-keygen', 'namespace': NS},
            'rules': [{'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get', 'create']}]},
           {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name': 'ctr-keygen', 'namespace': NS},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'ctr-keygen'},
            'subjects': [{'kind': 'ServiceAccount', 'name': 'ctr-keygen', 'namespace': NS}]}])
    import secrets as pysecrets
    pw = pysecrets.token_urlsafe(24)
    # Saved under its release name: the checksum file refers to it by that name.
    script = ('set -e; V=v2.4.1; cd /tmp; curl -fsSL -o cosign-linux-amd64 https://github.com/sigstore/cosign/releases/download/$V/cosign-linux-amd64; '
              'curl -fsSL -o sums https://github.com/sigstore/cosign/releases/download/$V/cosign_checksums.txt; '
              "grep ' cosign-linux-amd64$' sums | sha256sum -c - && chmod +x cosign-linux-amd64 && "
              f'./cosign-linux-amd64 generate-key-pair k8s://{NS}/ctr-cosign')
    oc('-n', NS, 'delete', 'job', 'ctr-keygen', '--ignore-not-found')
    apply({'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': {'name': 'ctr-keygen', 'namespace': NS},
           'spec': {'backoffLimit': 1, 'template': {'spec': {
               'serviceAccountName': 'ctr-keygen', 'restartPolicy': 'Never',
               'containers': [{'name': 'keygen', 'image': 'registry.access.redhat.com/ubi9/ubi-minimal:latest',
                               'command': ['bash', '-c', script], 'env': [{'name': 'COSIGN_PASSWORD', 'value': pw}]}]}}}})
    oc('-n', NS, 'wait', '--for=condition=complete', 'job/ctr-keygen', '--timeout=300s')
    print('  ctr-cosign generated in the cluster')


def pipeline() -> None:
    step('Pipeline')
    oc('apply', '-f', str(ROOT / 'ctr-setup' / 'pipeline.yaml'))
    print('  ctr-build')


def repos() -> dict[str, dict]:
    step(f'GitLab group {GROUP}')
    gid = ensure_group()
    out = {}
    for app in APPS:
        bom = json.loads((ROOT / 'app-data' / 'bom' / f'{app}.json').read_text())
        files = app_source.render(bom, appv2.PROBE_CLASS)
        files['pom.xml'] = pin_siblings(files['pom.xml'], bom)
        files['Containerfile'] = containerfile(app)
        p = ensure_project(gid, f'app-{app}')
        print(f"  app-{app}: {'committed' if commit(p, files, f'{app}: source from the BOM') else 'up to date'}")
        out[app] = p
    out['gitops'] = ensure_project(gid, 'gitops')
    return out


def build(app: str, project: dict) -> str:
    tag = 'seed-' + time.strftime('%Y%m%d%H%M%S')
    pr = {'apiVersion': 'tekton.dev/v1', 'kind': 'PipelineRun',
          'metadata': {'generateName': f'ctr-build-{app}-', 'namespace': NS, 'labels': {'ctr/app': app, 'ctr/purpose': 'seed'}},
          'spec': {'pipelineRef': {'name': 'ctr-build'},
                   'params': [{'name': 'repo_url', 'value': project['http_url_to_repo']}, {'name': 'revision', 'value': 'main'},
                              {'name': 'app', 'value': app}, {'name': 'tag', 'value': tag},
                              {'name': 'nexus_url', 'value': ENV['NEXUS_URL']}, {'name': 'enforce', 'value': 'false'}],
                   'workspaces': [{'name': 'source', 'volumeClaimTemplate': {'spec': {
                                      'accessModes': ['ReadWriteOnce'], 'storageClassName': 'gp3-csi',
                                      'resources': {'requests': {'storage': '1Gi'}}}}},
                                  {'name': 'git-auth', 'secret': {'secretName': 'ctr-gitlab-auth'}}],
                   'taskRunTemplate': {'serviceAccountName': 'pipeline'}}}
    name = oc('create', '-f', '-', '-o', 'jsonpath={.metadata.name}', stdin=json.dumps(pr)).strip()
    print(f'  {app}: {name} started', flush=True)
    for _ in range(120):
        st = json.loads(oc('-n', NS, 'get', 'pipelinerun', name, '-o', 'json'))
        cond = next((c for c in (st.get('status') or {}).get('conditions') or [] if c['type'] == 'Succeeded'), {})
        if cond.get('status') == 'True':
            res = {r['name']: r['value'] for r in st['status'].get('results') or []}
            print(f"  {app}: built {res['IMAGE_DIGEST'][:19]}… · {res.get('SCAN_SUMMARY', '')}")
            return res['IMAGE_DIGEST']
        if cond.get('status') == 'False':
            raise SystemExit(f"  {app}: {name} failed: {cond.get('message', '')[:300]}  (oc -n {NS} describe pipelinerun {name})")
        time.sleep(10)
    raise SystemExit(f'  {app}: {name} did not finish in 20 minutes')


def gitops(projects: dict, digests: dict[str, str]) -> None:
    step('GitOps repository')
    files = {}
    for app, (_, sites) in APPS.items():
        dig = digests.get(app)
        for ns, (env, replicas) in sites.items():
            path = f'apps/{CLUSTER}/{ns}/{app}/kustomization.yaml'
            if not dig:                                     # keep what the repo already pins
                cur = read_file(projects['gitops'], path)
                dig = next((l.split(':', 1)[1].strip() for l in cur.splitlines() if l.strip().startswith('digest:')), '')
            if dig:
                files.update(gitops_files(app, ns, env, replicas, dig))
    files['README.md'] = ('# gitops\n\nWhat runs where: apps/<cluster>/<namespace>/<app>/, each pinning its image by digest. '
                          'Argo CD (openshift-gitops) syncs every path. The agentic-patching console changes only the '
                          'digest lines, through the AAP job "CTR - Deploy".\n')
    print(f"  {'committed' if commit(projects['gitops'], files, 'Containers: deployments pinned by digest') else 'up to date'}")


def argocd(projects: dict) -> None:
    step('Argo CD')
    url = projects['gitops']['http_url_to_repo']
    user = gl('GET', '/user')['username']
    apply({'apiVersion': 'v1', 'kind': 'Secret',
           'metadata': {'name': 'ctr-gitops-repo', 'namespace': 'openshift-gitops',
                        'labels': {'argocd.argoproj.io/secret-type': 'repository'}},
           'stringData': {'type': 'git', 'url': url, 'username': user, 'password': ENV['CTR_GITLAB_TOKEN']}})
    for app, (_, sites) in APPS.items():
        for ns in sites:
            apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                   'metadata': {'name': f'ctr-{ns}-{app}', 'namespace': 'openshift-gitops',
                                'labels': {'app.kubernetes.io/part-of': 'agentic-patching'}},
                   'spec': {'project': 'default',
                            'source': {'repoURL': url, 'targetRevision': 'main', 'path': f'apps/{CLUSTER}/{ns}/{app}'},
                            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': ns},
                            'syncPolicy': {'automated': {'prune': True, 'selfHeal': True}}}})
            print(f'  ctr-{ns}-{app}')


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--no-build', action='store_true')
    args = ap.parse_args()
    step('Preflight')
    preflight()
    namespaces()
    secrets()
    pipeline()
    projects = repos()
    digests = {}
    if not args.no_build:
        step('First images (enforce=false: the old libraries are what ACS should find)')
        for app in APPS:
            digests[app] = build(app, projects[app])
    gitops(projects, digests)
    argocd(projects)
    print('\nNext: check the deployments in nfvo-lab, nfvo-prod, oss-lab, oss-prod, then let ACS scan them.')


if __name__ == '__main__':
    main()
