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

The CVE list should show exactly **two** CVEs. If you see hundreds, you are
pointed at the real Red Hat Insights, not the fallback data.

**The page will not tell you it is offline.** That is deliberate: the console
presents one face, and every value renders the same whether it was measured or
stood in for. To check which mode you are actually in, read the `mode :` line
the start script printed in your terminal, or open `/api/mode` in a browser
tab. The **Agent trace** in the left-hand panel also names each service that
did not answer, as the run happens.

If you would rather the page did say so — the banner, the degraded panel, the
`SIMULATED` chips — open the **gear** and turn on **Label substituted values**,
or start with `LABEL_SOURCES=1 ./demo.sh`.

## Walking through the flow

The two CVEs are chosen to show the two different paths the system can take.
Try both.

If you are going to show this to somebody rather than just read it, open the
**book icon** at the top right first. That is the run of show — what to click,
what to say, what you will be asked, and what not to claim. `Esc` closes it and
it does not disturb a run, so you can reopen it mid-demo.

If anyone is reading this off a projector, open the **gear** next to it and set
**Text size** to Large. It applies immediately, it is remembered in your
browser, and it changes nothing on the server or for anyone else.

**1 — A CVE that needs human approval**

1. Hit **Assess** on the **CVE-2024-3094** row (CVSS 10.0, 5 affected hosts).
   You get a patch plan: a risk score per host, that host's past patch
   history, the maintenance window, and a verdict. All five hosts score above
   the review threshold, so the verdict is *manual review required*.
2. Click **Send 5 for approval**. The button says that, and not "patch",
   because on this path it patches nothing — each host gets its own workflow
   run and every one of them stops at the approval gate.
   Wandering off to **Patch runs** or the CVE list at this point does not lose
   the plan. A red **Patch plan: CVE-…** button appears at the top of the right
   panel, and that CVE's row offers **Resume** instead of **Assess** — either
   one puts you back where you were, dispatch button and all.
3. Click **Approve** (or **Reject**) on each row. The row's progress bar fills
   as the workflow works through its nodes behind the gate — the count beside
   it is nodes finished, not elapsed time, so a bar that stops moving means the
   run stopped moving. It reaches 7/7 and the outcome flips to *Patched*.

Watch the left column as you go. **Agent architecture** is the whole system as
a diagram — the Supervisor, the two agents it drives, the services behind them,
and the two agents that are not built yet. It starts all grey. Each box goes
black the first time something calls it, and the hop happening right now is
drawn solid with the dashes flowing in the direction of the call, so you can
watch the conversation rather than read it. **Agent trace** below it is the
same events as a list, numbered, with the seconds between them.

**2 — A CVE that patches unattended**

Repeat with **CVE-2024-1086** (CVSS 7.8, 2 affected hosts). Both hosts score
below the threshold, so there is no approval gate anywhere downstream of them.
The button reads **Patch 2 hosts** and stays red, because that press is the
only human check these hosts get — nothing stops to ask again.

Watch the diagram on this one: **RAG STORE** stays grey the whole way through.
No host needed review, so nothing ever asked it — and a box that was never
called is not a box that answered.

**3 — What the run saved**

With either walkthrough still on screen, click **Calculate ROI**. It takes this
run's own numbers — how many hosts, how many stopped for a person, how long
each one took — and costs the same work out by hand.

Know before you read the big numbers: offline, the timings come from
`DEMO_LATENCY` rather than from patching anything, so the speed figures are
illustrative. The page will not say so unless `LABEL_SOURCES=1` — say it out
loud instead. The labour and cost comparison does not depend on those timings.

The manual side is not measured either and never can be from here — the manual
run never happened, so there is no clock to read it off. So the first card on
the page is **Assumptions**: a slider for every assumption behind the
comparison. If you think 15 minutes of change prep per host is generous, drag
it down and watch the whole page follow. Nothing is saved and nobody else's
view changes; use the gear panel if you want a value to stick.

Below that, *How wrong could this be* tells you how far those assumptions have
to move before the conclusion flips, *Time to remediation* checks the run
against a 48 hour deadline, and *Across every run so far* runs the same
arithmetic over everything in the run store rather than this one CVE — so it
grows as you work through both walkthroughs.

Three cards near the bottom are the ones to show a customer, and they are the
only part of the page that is neither measured here nor assumed here. Eight
published figures from the 2026 Verizon DBIR, Mandiant M-Trends, IBM's Cost of
a Data Breach and CISA's remediation directive, each numbered to a full
citation.

**Scroll to them slowly** — the bars sweep and the dots fill as they come into
view, and arriving mid-animation is the whole effect.

*What this is up against* is the black one, and it is black on purpose: it is
the only card on the page whose numbers are not ours. It draws the remediation
clock to scale — 43 days industry median, your own baseline, the CISA deadline,
and this run, whose bar is literally too small to draw — and then the day-7
ceiling as a hundred dots, 65 of them red. Let people count the dots.

*Measured, not modelled* is the rest of the record, and it checks the sliders
against it: the page scores its own manual baseline against the published
median and says which way it is wrong. At the defaults it says it is
understating its own saving by 14×, which is a better thing to be able to say
than a bigger number. Drag **Manual time-to-remediation** to 1032 h and the
whole page is running on Verizon's figure rather than ours.

*How the industry sees this* puts the approval-gate design next to what
analysts expect, and prints the case against agentic projects as plainly as the
case for them. If somebody is going to raise that objection, raise it first.

**4 — The run history**

Click **Patch runs** at the top of the right-hand panel to see everything from
both walkthroughs, newest first.

## What is real and what is not

Worth being clear about, because the console deliberately looks like the real
thing and, by default, says nothing on the page to the contrary.

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

Live mode needs the backing services and a target host, which is a bigger job
than this guide. `./setup.sh` does the deployable part:

```bash
cp .env.example .env     # fill it in; quote any value containing a space
./setup.sh --check       # preflight — says what is missing, changes nothing
./setup.sh               # OpenShift, AAP, AO, console settings, smoke test
./demo.sh --live
```

Start with `--check`. The one thing it cannot do for you is the target host:
live mode needs a machine registered in the same Insights organisation as
your credentials **and** reachable over SSH from AAP, and most hosts are only
one of those. `./discover-hosts.py` says whether the lab's hosts qualify and
prints the uuid to put in `HOSTS_FILTER`.

If `.env` does not exist, `./demo.sh --live` creates one from `.env.example`
and then **refuses to start**, naming the keys that matter. That is on
purpose: live mode has no fallback, so a blank key is not a step that
degrades, it is a run that cannot finish. Fill it in and start again.
`.env` is gitignored; never commit it.

This is the opposite of fallback mode, where a missing key costs you that one
step and nothing else. Do not carry the habit across.

**Turn source labelling on when you do this.** Either set `LABEL_SOURCES=1`
before `./demo.sh --live`, or flip **Label substituted values** in the gear
panel. With it on, any step that could not reach its backend is called out in
the patch plan itself, naming the service and how to fix it, that service's box
in the architecture diagram turns red, and simulated rows are chipped
`SIMULATED` — so you always know which numbers are measured and which are
substituted. With it off you are reading an unmarked mix of the two, which is
fine for a demo and not fine for a patch plan someone is about to approve.

Without it, the record is still in `/tmp/demo-backend.log` and the **Agent
trace** panel. It is just not on the page.

See [README.md](README.md) for the architecture and the full set of switches.
