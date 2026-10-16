# aap-setup

The AAP side of the CVE remediation flow: fetch a remediation playbook from
Red Hat Insights, make it runnable, run it, and check it worked.

Standalone on purpose. Nothing here depends on the console or on Ansible
Orchestrator, so each piece can be proven on its own before being wired into
the live flow.

```
aap-setup/
  create-aap-objects.sh                      create / update the AAP objects
  create-ao-workflow.sh                      create / publish the AO workflow
  run-test.sh                                launch one job and show the result
  playbooks/
    cve_fetch_and_commit.yml                 Insights -> GitHub
    cve_sync_and_deploy.yml                  sync, then build a per-host template
    cve_verify_patch.yml                     ask the host whether the CVE is gone
  test-workflow/
    cve_fetch_and_commit_workflow.json       minimal AO workflow for testing
```

## The three steps

**1. `CVE - Fetch and Commit`**

```
  1. service-account token from sso.redhat.com
  2. resolve <host> to its uuid                 Insights inventory API
  3. confirm the CVE applies to it              Insights vulnerability API
  4. generate a remediation playbook            Insights remediations API
  5. widen "hosts:" to all                      targeting belongs to AAP
  6. commit, skipping if unchanged              GitHub Contents API
      -> generated_playbooks/remediation-<CVE>-<host>.yml
         on branch generated-playbooks
```

Steps 2 and 3 are asked host-first on purpose. Asking CVE-first —
"which systems does this CVE affect, and is mine among them?" — does not
survive a real estate: one CVE reported 13,538 affected systems, which is 136
sequential pages, and the gateway 504s long before the host turns up. Both
calls here are indexed by host and return in well under a second.

Artifacts: `playbook_filename`, `playbook_path`, `system_uuid`,
`github_branch`, `committed`, `changed`, `action`, `commit_sha`.

**2. `CVE - Sync and Deploy Remediation`**

Syncs the project tracking `generated-playbooks` so the file committed
moments ago is on disk, then creates a per-CVE-per-host job template pointing
at it. Creates it; does not launch it — launching is the orchestrator's next
node, and keeping the thing that changes a machine as its own step is the
point.

Artifacts: `template_name`, `template_id`, `playbook_used`, `status`.

**3. `CVE - Verify Patch`**

Runs `dnf updateinfo list --cve <id>` on the host and reports whether any
advisory is still outstanding. A remediation job reporting "successful" means
Ansible's tasks exited 0, which came apart from reality in both directions
during this project: a dnf transaction can succeed with the advisory still
pending, and a correctly patched host reported failed because
`insights-client`'s registration check exited 1 on the final play.

Never fails the run on an unpatched result — whether "still vulnerable"
should stop a workflow is the orchestrator's call, and it gets `patched` to
make it.

Artifacts: `patched`, `verified_cve`, `verified_host`,
`outstanding_advisories`, `dnf_rc`.

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

It creates these in organization `Default`:

| kind | name | notes |
|---|---|---|
| credential type | `GitHub Token` | injects `GITHUB_TOKEN` |
| credential type | `Insights Lightspeed` | injects `LIGHTSPEED_CLIENT_ID` / `_SECRET` |
| credential | `github-token` | |
| credential | `insights-lightspeed` | |
| project | `DemoJam Agentic Patching` | this repo, `main`, update-on-launch |
| project | `Lightspeed-Playbooks` | this repo, `generated-playbooks` |
| job template | `CVE - Fetch and Commit` | both credentials attached |
| job template | `CVE - Sync and Deploy Remediation` | AAP credential attached |

Two projects because they track different branches: the playbooks live on
`main`, the playbooks they *generate* land on `generated-playbooks`.

Every name is overridable, which matters when the controller already has
objects of the same name that belong to someone else. The lab controller we
used had its own `CVE - Fetch and Commit` pointing at a different Insights
org through an MCP server, so ours were created alongside it:

```bash
JT_NAME="DJ - CVE Fetch and Commit" \
DEPLOY_JT_NAME="DJ - CVE Sync and Deploy" \
GEN_PROJECT_NAME="DJ - Generated Playbooks" \
PROJECT_NAME="DJ - Agentic Patching" \
TARGET_INVENTORY="ec2-inventory" MACHINE_CREDENTIAL="ec2-demojam" \
AAP_CRED_NAME="AAP" \
  ./aap-setup/create-aap-objects.sh --dry-run
```

`TARGET_INVENTORY` and `MACHINE_CREDENTIAL` name where a remediation will
actually run. Both must already exist — this script will not invent an
inventory or an SSH credential. See
[../docs/EC2_TARGET_HOST.md](../docs/EC2_TARGET_HOST.md) for building a host
that live mode can use.

`CVE - Verify Patch` is not created by the script yet; add it as a job
template running `aap-setup/playbooks/cve_verify_patch.yml` with the machine
credential attached and `ask_limit_on_launch` enabled.

**The playbooks must be pushed to `main` before running this** — AAP clones the
project from GitHub, so an unpushed local edit is invisible to it. That is also
why `scm_update_on_launch` is on: without it a job silently runs whatever was
cloned last.

## Testing

```bash
./aap-setup/run-test.sh CVE-2026-88812 rdu-z16-l13
```

Launches the job template, waits, prints the playbook output and the artifacts.
Exits non-zero if the job failed. Set `JT_NAME` if you renamed the template.

For an end-to-end test through Ansible Orchestrator:

```bash
./aap-setup/create-ao-workflow.sh                            # create + publish
./aap-setup/create-ao-workflow.sh --run CVE-2026-88812 demojam-rhel-01
./aap-setup/create-ao-workflow.sh --delete
```

One node — trigger, fetch and commit, stop. It reuses the main workflow's AAP
integration and credential ids, so importing it needs no further wiring.

AO reports the execution, not the commit: a completed execution lists zero
activities in that view, so confirm the result from GitHub rather than from
the workflow's own report.

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

**Unchanged content is not committed.** Insights regenerates the same playbook
for the same CVE and host, and GitHub accepts a commit that changes no files —
so the branch filled with empty commits while the file list never moved, and a
successful run looked like it had done nothing. The content is compared first
and the step reports `action: unchanged` instead.

## Things that bit us

**`insights-client` fails the remediation on a patched host.** Its final play
runs `insights-client`, which performs a registration check against a legacy
endpoint, gets a false negative, and exits 1 — so the job reports failed on a
machine it correctly patched. Set `legacy_upload=False` in
`/etc/insights-client/insights-client.conf` on the target host.

**Insights is slow the first time it is asked about a CVE.** Responses are
computed on demand and cached: ~30s cold, sub-second after, and the cold one
often exceeds the gateway's own 30s limit and returns 504. The console retries
gateway errors; warming a CVE before a demo makes it visibly faster.

**The AAP host name must equal the Insights display name**, because the
console passes that name through as the job's `limit`, while `ansible_host`
carries the address that actually resolves.

## Not done yet

- `CVE - Verify Patch` is created by hand, not by `create-aap-objects.sh`.
- `ao-setup/playbooks/` (the Gitea originals, reaching Insights through MCP)
  are left untouched for reference. They query a different Insights
  organisation and cannot see hosts registered in ours.
