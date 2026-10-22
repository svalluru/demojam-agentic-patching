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
