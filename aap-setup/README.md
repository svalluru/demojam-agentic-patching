# aap-setup

The AAP side of the CVE remediation flow: fetch a remediation playbook from
Red Hat Insights and commit it to GitHub.

Standalone on purpose. Nothing here depends on the console or on Ansible
Orchestrator, so it can be proven on its own before being wired into the live
flow.

```
aap-setup/
  create-aap-objects.sh                      create / update the AAP objects
  run-test.sh                                launch one job and show the result
  playbooks/cve_fetch_and_commit.yml         the playbook AAP runs
  test-workflow/
    fetch_and_commit_test_workflow.json      minimal AO workflow for testing
```

## What it does

```
AAP job template "CVE - Fetch and Commit"
  |
  |  1. service-account token from sso.redhat.com
  |  2. resolve <host> to its inventory uuid     Insights vulnerability API
  |  3. generate a remediation playbook          Insights remediations API
  |  4. widen "hosts:" to all                    targeting belongs to AAP
  |  5. commit                                   GitHub Contents API
  v
github.com/svalluru/demojam-agentic-patching
  branch generated-playbooks
  generated_playbooks/remediation-<CVE>-<host>.yml
```

Artifacts published for the orchestrator: `playbook_filename`, `playbook_path`,
`system_uuid`, `github_branch`, `committed`.

## Setup

Needs in `.env` at the repository root:

| variable | used for |
|---|---|
| `AAP_BASE_URL`, `AAP_TOKEN` | creating the objects |
| `GIT_HUB_TOKEN` | the credential AAP injects as `GITHUB_TOKEN` |
| `LIGHTSPEED_CLIENT_ID`, `LIGHTSPEED_CLIENT_SECRET` | the Insights service account |
| `AAP_DEFAULT_ORGANIZATION_ID`, `_INVENTORY_ID`, `_EXECUTION_ENVIRONMENT_ID` | defaults 1, 1, 2 |

The GitHub token must be a fine-grained PAT with **Contents: Read and write**
on the repository.

```bash
./aap-setup/create-aap-objects.sh --dry-run   # show what would change
./aap-setup/create-aap-objects.sh             # create / update
./aap-setup/create-aap-objects.sh --delete    # remove it all again
```

Idempotent — objects are matched by name and updated in place, so re-running is
safe. Secrets are re-pushed every run because the API never discloses them to
compare against.

It creates six things in organization `Default`:

| kind | name | notes |
|---|---|---|
| credential type | `GitHub Token` | injects `GITHUB_TOKEN` |
| credential type | `Insights Lightspeed` | injects `LIGHTSPEED_CLIENT_ID` / `_SECRET` |
| credential | `github-token` | |
| credential | `insights-lightspeed` | |
| project | `DemoJam Agentic Patching` | this repo, `main`, update-on-launch |
| job template | `CVE - Fetch and Commit` | both credentials attached |

**The playbook must be pushed to `main` before running this** — AAP clones the
project from GitHub, so an unpushed local edit is invisible to it. That is also
why `scm_update_on_launch` is on: without it a job silently runs whatever was
cloned last.

## Testing

```bash
./aap-setup/run-test.sh CVE-2026-88812 rdu-z16-l13
```

Launches the job template, waits, prints the playbook output and the artifacts.
Exits non-zero if the job failed.

For an end-to-end test through Ansible Orchestrator, import
`test-workflow/fetch_and_commit_test_workflow.json` and trigger it with
`{"cve_id": "...", "host": "..."}`. It runs the one node and stops.

## Decisions worth knowing

**Custom credential types, not Source Control.** AAP only exposes a credential
to a playbook as an environment variable if its type declares an injector. The
built-in Source Control type lets AAP *clone* a repository and hands the
playbook nothing. This playbook authenticates to the GitHub API itself, so it
needs a type that injects.

**REST, not MCP.** The earlier Gitea playbook reached Insights through an MCP
server at `bastion:8001`. Calling the REST API with the service account the
console already uses means the execution environment needs egress to
`console.redhat.com` and `api.github.com` and nothing else — no route into the
lab, one less thing to be down.

**A separate branch.** Generated playbooks land on `generated-playbooks`, never
on `main`, so machine commits never touch the branch holding the application
code.

**One file per CVE per host.** The orchestrator dispatches a separate execution
for every host. A per-CVE filename would have those executions overwrite each
other, and the losing host would then deploy a playbook generated for a
different machine.

**Create versus update.** GitHub uses `PUT` for both, and an update must carry
the blob sha of what it replaces. The script probes the path first; a 404 on
that probe is how it tells the two cases apart.

## Not done yet

- Not wired into the live console flow. The AO workflow still points its
  `Fetch from Lightspeed & Commit to Gitea` node at the Gitea playbook.
- `ao-setup/playbooks/cve_sync_and_deploy.yml` still expects a `lab-credential`
  that does not exist in this AAP, and the `CVE - Sync and Deploy Remediation`
  job template has not been created.
- `ao-setup/playbooks/cve_fetch_and_commit.yml` (the Gitea original) is left
  untouched for reference.
