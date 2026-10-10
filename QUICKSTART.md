# Quickstart — running the console in fallback mode

This gets the Agentic Patching Console running on your laptop in about a
minute, with **no cluster access, no credentials and no network calls**. Every
value it shows comes from a file in the repo.

Use this to see what the system does and how the flow hangs together. It is not
connected to anything, so you cannot break anything with it.

## Before you start

| Need | Check with | Notes |
|---|---|---|
| Python 3.10 or newer | `python3 --version` | tested on 3.11 and 3.13 |
| `git`, `curl`, `lsof` | `git --version` | `lsof` ships with macOS and most Linux |

There are **no pip packages to install.** The whole thing is Python standard
library. If you find yourself running `pip install`, something has gone wrong —
tell Sai.

Ports **8787** and **8788** need to be free. The start script will stop
anything it finds already listening on them.

## Steps

```bash
git clone <REPO-URL>
cd demojam-agentic-patching
./demo.sh
```

Then open <http://127.0.0.1:8788>.

That is the whole setup. Do **not** create a `.env` — fallback mode does not
read one, and it is not needed unless you are connecting to the real cluster.

Press `Ctrl-C` in the terminal to stop. It shuts down both processes.

## Checking it worked

You should see a **red banner across the top of the page**:

> OFFLINE — Fallback mode. Every value on this page is a stored default. No
> cluster is being contacted and nothing will be patched.

If that banner is missing, stop and re-read the terminal output — you may have
started it in live mode by mistake.

Below it, the CVE list should show exactly **two** CVEs. If you see hundreds,
you are pointed at the real Red Hat Insights, not the fallback data.

## Walking through the flow

The two CVEs are chosen to show the two different paths the system can take.
Try both.

**1 — A CVE that needs human approval**

1. Hit **Assess** on the **CVE-2024-3094** row (CVSS 10.0, 5 affected hosts).
   You get a patch plan: a risk score per host, that host's past patch
   history, the maintenance window, and a verdict. All five hosts score above
   the review threshold, so the verdict is *manual review required*.
2. Click **Send 5 for approval**. The button says that, and not "patch",
   because on this path it patches nothing — each host gets its own workflow
   run and every one of them stops at the approval gate.
3. Click **Approve** (or **Reject**) on each row. The row's progress bar fills
   as the workflow works through its nodes behind the gate — the count beside
   it is nodes finished, not elapsed time, so a bar that stops moving means the
   run stopped moving. It reaches 7/7 and the outcome flips to *Patched*.

Watch the left column as you go. It fills in with where the run is in one word,
a count of hosts gated and patched, and **Where this came from** — one row per
backend step saying what actually answered it. Offline every row reads `STORED`,
because every row is a stored default. Live, a step that fell back to
`fallbacks.py` turns red there and says `FALLBACK`.

**2 — A CVE that patches unattended**

Repeat with **CVE-2024-1086** (CVSS 7.8, 2 affected hosts). Both hosts score
below the threshold, so there is no approval gate anywhere downstream of them.
The button reads **Patch 2 hosts** and stays red, because that press is the
only human check these hosts get — nothing stops to ask again.

On the left, **Patch history** reads `NOT NEEDED` rather than `STORED` on this
one. No host needed review, so nothing ever asked the RAG store — and a step
that was never called is not a step that succeeded.

**3 — What the run saved**

With either walkthrough still on screen, click **Calculate ROI**. It takes this
run's own numbers — how many hosts, how many stopped for a person, how long
each one took — and costs the same work out by hand.

Read the red banner at the top of that page before the big numbers. Offline the
timings come from `DEMO_LATENCY` rather than from patching anything, so the
speed figures are illustrative; the labour and cost comparison does not depend
on them.

The manual side is not measured either and never can be from here — the manual
run never happened, so there is no clock to read it off. So the first card on
the page is **Disagree with it**: a slider for every assumption behind the
comparison. If you think 15 minutes of change prep per host is generous, drag
it down and watch the whole page follow. Nothing is saved and nobody else's
view changes; use the gear panel if you want a value to stick.

Below that, *How wrong could this be* tells you how far those assumptions have
to move before the conclusion flips, *Time to remediation* checks the run
against a 48 hour deadline, and *Across every run so far* runs the same
arithmetic over everything in the run store rather than this one CVE — so it
grows as you work through both walkthroughs.

**4 — The run history**

Click **Patch runs** at the top of the right-hand panel to see everything from
both walkthroughs, newest first.

## What is real and what is not

Worth being clear about, because the console deliberately looks like the real
thing once you are past the banner.

| | |
|---|---|
| Real | The agent logic, the control flow, the approval gate, the risk threshold and routing rules, the patch plan format, the workflow step sequence |
| Not real | The CVEs, the hostnames, the risk scores, the patch history text, the workflow executions, the manual baseline the ROI page compares against |

**Nothing is patched and no host exists.** The workflow runs are resolved
inside this process. They do not appear in Ansible Orchestrator and never
touch a machine.

The run history is stored in `runs/simulated.json`. Delete that file to reset
to a clean slate:

```bash
rm -f runs/simulated.json
```

## If something goes wrong

**`Python 3.10+ required`** — you have an older interpreter first on your
`PATH`. Install a newer one, or run `python3.11 --version` to find one you
already have.

**`error: 'lsof' is required`** — on a minimal Linux image, install it
(`sudo dnf install lsof` / `sudo apt install lsof`).

**Page loads but the CVE list is empty** — the backend did not start. Look at
`/tmp/demo-backend.log`.

**Port already in use** — the script stops anything on 8787/8788 before
starting, but if that fails:

```bash
lsof -i :8787 -i :8788      # find it
kill <pid>
```

**Anything else** — the two logs are `/tmp/demo-backend.log` and
`/tmp/demo-frontend.log`. Send those along with what you clicked.

## Connecting to the real thing

Only once you have cluster credentials and the backing services are up:

```bash
cp .env.example .env     # then fill it in
./demo.sh --live
```

In live mode the red banner disappears. In its place, any individual step
that could not reach its backend is called out in the patch plan itself,
naming the service and how to fix it — so you always know which numbers on the
page are measured and which are substituted.

See [README.md](README.md) for the architecture and the full set of switches.
