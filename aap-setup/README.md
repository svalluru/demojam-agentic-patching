# AAP: the one object that is ours

The competition workflow calls three job templates. Two belong to the lab and
one to us:

| Template | Owner | What it does |
|---|---|---|
| `CVE - Fetch and Commit` | **lab** | asks Lightspeed MCP for a remediation playbook, commits it to Gitea |
| `CVE - Sync and Deploy Remediation` | **lab** | syncs `Lightspeed-Playbooks`, creates a per-host template for that playbook |
| `CVE - Verify Patch` | **us** | checks on the host whether the CVE is actually gone |

This directory creates the third and touches nothing else.

```bash
./aap-setup/create-verify-template.sh --dry-run   # show what it would do
./aap-setup/create-verify-template.sh             # create or update
./aap-setup/create-verify-template.sh --delete
```

`setup.sh` runs it in its AAP stage.

## Why it will not touch the lab's objects

The script this replaced matched AAP objects by name and **updated** whatever
it found — and its default names were the lab's own: `Lightspeed-Playbooks`,
`CVE - Fetch and Commit`, `CVE - Sync and Deploy Remediation`. `setup.sh` ran
it. On this lab, that would have repointed the lab's Gitea project at a GitHub
branch and swapped its fetch template for a different playbook, breaking the
workflow it was meant to be setting up.

So the new script carries an explicit list of names it refuses to write to,
and checks it before doing anything:

```
$ JT_NAME="CVE - Fetch and Commit" ./aap-setup/create-verify-template.sh
ERROR: 'CVE - Fetch and Commit' is a lab object — refusing to write to it
```

## What it creates

| | |
|---|---|
| project `DJ - Agentic Patching` | this repo, on **the branch you run it from** |
| template `CVE - Verify Patch` | `aap-setup/playbooks/cve_verify_patch.yml`, on `lab-inventory` with `lab-credential` |

The project tracks your current branch on purpose, so the controller runs the
verify playbook as this checkout has it rather than as some other branch
does. Override with `BRANCH=…`, and the inventory and credential with
`TARGET_INVENTORY=` and `MACHINE_CREDENTIAL=`.

## The verify step

Runs `dnf updateinfo list --cve <id>` on the host and reports whether any
advisory is still outstanding — the same command the README suggests running
by hand.

A remediation job reporting "successful" means Ansible's tasks exited 0, and
that came apart from reality in both directions during this project: a dnf
transaction can succeed with the advisory still pending, and a correctly
patched host reported failed because `insights-client`'s registration check
exited 1 on the final play. So the answer is read from the machine.

It never fails the run on an unpatched result. Whether "still vulnerable"
should stop a workflow is the orchestrator's call, and it gets `patched` to
make it.

Artifacts: `patched`, `verified_cve`, `verified_host`,
`outstanding_advisories`, `dnf_rc`.

**It is scoped to `target_host`.** It used to run `hosts: all`, which on a
one-host inventory looks identical and on the lab's three-host one is not:
`set_stats` aggregated three verdicts into one artifact, `verified_host`
came back `node1node2node3`, and `patched` was true + false + false summed to
1 — truthy for the wrong reason.

## Things that bit us

**`insights-client` fails the remediation on a patched host.** Its final play
runs `insights-client`, which performs a registration check against a legacy
endpoint, gets a false negative, and exits 1. Set `legacy_upload=False` in
`/etc/insights-client/insights-client.conf` on the target.

**Insights is slow the first time it is asked about a CVE** — measured at
20s cold from the lab bastion against 0.2s warm, and the lab's MCP client
gives up at about twenty. That is the intermittent fetch failure. The console
warms the CVE during assessment to spend that time while the plan is being
read.

## Application patching (dependency scanner)

`playbooks/app_clone_update_build.yml` is the job behind **Approve and run** in the dependency scanner (`lightwell/`) — the press after **Plan a fix**, which only previews the change list and launches nothing. It runs on a host of the job template's inventory: clones a repository at the scanned commit, applies a list of dependency version changes, builds the result (`mvn verify`, or `pip install` for a requirements file), and optionally commits and pushes a branch. The scanner works out the change list; the playbook applies it as written and reports the diff and build result back as the job's artifacts. The editing is done by `playbooks/files/apply_dependency_changes.py`, which also reports any change it could not make and why.

The JDK follows the repository. `playbooks/files/detect_java.py` reads every `pom.xml` (compiler release/source/target, `java.version`, the enforcer's `requireJavaVersion`, a Spring Boot parent) and version pins (`.java-version`, `.sdkmanrc`, `.tool-versions`), takes the highest requirement, and rounds up to 8, 11, 17 or 21; GitHub Actions and Dockerfile hints count only when nothing else says, and the default is 17. The job uses an installed JDK under `/usr/lib/jvm` when there is one of that version, and otherwise downloads a Temurin JDK (checked against the published sha256) and Maven 3.9.9 (checked against the sha512 on Maven Central) into `/tmp/app-patch-tools`, which needs no root and works in the controller's own execution environment. It then needs outbound access to `api.adoptium.net` and Maven Central. The person can override the detected version on the page; the result states the version used and why.

```bash
./aap-setup/create-app-patch-objects.py --dry-run
BUILD_INVENTORY="Demo Inventory" MACHINE_CREDENTIAL="Demo Credential" ./aap-setup/create-app-patch-objects.py
```

It creates the credential type `Lightwell Registry` and a credential from `LIGHTWELL_REGISTRY_USER` and `LIGHTWELL_REGISTRY_TOKEN`, then the job template `App Patch - Clone, Update, Build` with the GitHub token, Lightwell registry and machine credentials attached. It is all application patching needs and is independent of the CVE templates. If they are missing it also creates the `GitHub Token` credential type and `github-token` credential (from `GIT_HUB_TOKEN`, which needs Contents read and write to push a branch) and the project `DemoJam Agentic Patching`, following `GITHUB_REPO_URL` on `PROJECT_BRANCH` (default `main`), then syncs it. An existing project is left as it is, and the script stops with a clear message if the project does not list the playbook. The inventory and machine credential must already exist, and the playbook must be pushed to the branch the project tracks. `--delete` removes only the job template, the Lightwell credential and its type. The host needs git 2.31 or newer, python3, curl and tar; the JDK and Maven are fetched as described above (or pip is used for a requirements file). The controller's execution environment meets this, so a build host is optional. There is no option to skip certificate checks; for a controller with a private certificate authority set `AAP_CA_BUNDLE` to its bundle.

The playbook was run here against a local host and a local git repository (clone, edit, build, commit, push to a branch). It has not been run on a real controller, and the Lightwell registry settings have not been exercised against the live registry.

