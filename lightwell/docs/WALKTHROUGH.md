![OpenShift ≥%204.19](https://img.shields.io/badge/Red%20Hat%20OpenShift_≥_4.19-blue?style=flat-square&logo=redhatopenshift&logoColor=white)
![Document Version: 1.0](https://img.shields.io/badge/Document%20Version-1.0-informational?style=flat-square&logo=files&logoColor=white)
![Author: Sunil Samuel](https://img.shields.io/badge/Author-Sunil%20Samuel-informational?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZmZmZiI+PGNpcmNsZSBjeD0iMTIiIGN5PSI3IiByPSI0Ii8+PHBhdGggZD0iTTQgMjF2LTFjMC00LjQyIDMuNTgtOCA4LThzOCAzLjU4IDggOHYxSDR6Ii8+PC9zdmc+&logoColor=white)

# Lightwell dependency scanner: how it works and how to run it

This walks through what was built, where the vulnerability data comes from, how a scan flows from a GitHub repository to a list of issues, and how to start, check and stop everything. It is written to be shown to someone, so the last section is a short demo script.

## What this is

Two programs. They share no code, no state and no data. The console's server loads the scanner and serves it under `/lightwell/`, so with `./demo.sh` both are opened from one address and the console header has an **Infrastructure / Application** toggle that switches between them.

| Program | What it is | Port | Where it lives |
|---------|-----------|------|----------------|
| Patching console | The existing agentic OS-patching demo. Picks a CVE, scores risk, asks for approval, patches hosts through Ansible | 8788 (UI), 8787 (API) | Repository root |
| Lightwell scanner | New. Takes GitHub repositories, finds vulnerable dependencies, shows whether Lightwell has a fix | 8788, at `/lightwell/` (8790 only when run on its own) | `lightwell/` |

The scanner tells you what is wrong and what could fix it. From a finished scan, **Plan a fix** on a repository card works out which dependency versions would change and where each fix comes from — Lightwell builds, a nearby Lightwell build, or OSV upgrades, as you choose. That is a preview: nothing is cloned and nothing is built. **Approve and run**, inside the panel, dispatches the AAP job that clones the repository, applies exactly that list and builds it; pushing the branch is a further press again. See the Remediation section of the README.

## Where the CVEs come from

There are two different sources, because the two programs look at different layers.

| Layer | Program | CVE source | What it finds |
|-------|---------|-----------|---------------|
| Operating system (RHEL packages on hosts) | Patching console | Red Hat Insights (Red Hat's vulnerability service) | CVEs that affect hosts registered with Insights |
| Application dependencies (Java, Python and npm libraries inside an app) | Lightwell scanner | OSV.dev | Known vulnerabilities in the exact library versions a repository uses |

**OSV.dev** is an open, free vulnerability database run for the open source community (osv.dev, API at api.osv.dev). It collects advisories from many upstream databases, including the GitHub Advisory Database (ids that start with `GHSA-`) and the PyPI advisory database (`PYSEC-`). The CVE number is carried on each advisory as an alias. It needs no account or key.

Two things are worth saying out loud when you present this:
- **Lightwell is not where the vulnerabilities come from.** Lightwell does not find vulnerabilities. It supplies fixes: remediated builds of specific library versions. The scanner asks OSV what is wrong, then asks whether Lightwell has a build that addresses it.
- **The Lightwell answer in demo mode is sample data.** It is a small hand-written file. The findings panel says so in a note above the results, and the header badge says so in its tooltip. In live mode without credentials the scanner says "not checked". With a Red Hat console service account (in a group with the Repositories viewer role) in `lightwell/.env`, it asks the real Lightwell Network API instead.

## How a scan works

```
  You type GitHub repositories (owner/repo, or a full URL)
        |
        v
  1. GITHUB       Resolve the default branch and one commit, list every file in one call.
        |         Keep only dependency manifests. Fetch each one.
        v
  2. PARSE        Read the manifests. Each dependency becomes a package URL with an exact
        |         version, for example pkg:pypi/django@2.2.0.
        |         Anything without a resolvable version is set aside and reported, not guessed.
        v
  3. OSV.DEV      Ask which advisories affect each package version (one batch call),
        |         then fetch each advisory once for its details.
        v
  4. ANALYSE      Score severity, work out which fixed version applies to the installed one,
        |         and the lowest version that clears every advisory on that package.
        v
  5. LIGHTWELL    For each vulnerable package version: is there a Lightwell build of exactly
        |         this version, and which of the advisories does it address?
        |         (sample data in demo mode, "not checked" in live mode)
        v
  6. RESULT       Saved as JSON under lightwell/data/. Shown on the page, available as JSON
                  and as a CSV download.
```

### Step 1: GitHub

For each repository the scanner makes three API calls (repository, commit, file tree), then fetches each manifest. Without a token, manifests come from `raw.githubusercontent.com`, which does not count against GitHub's limit of 60 API calls an hour. That is roughly 20 repositories an hour. With a `GITHUB_TOKEN` the limit is much higher and private repositories can be read.

Files it recognises: `pom.xml`, `build.gradle`, `build.gradle.kts`, `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`. Folders such as `node_modules`, `target` and `venv` are skipped. A URL ending in `/tree/branch/folder` limits the scan to that folder.

### Step 2: parse

Each ecosystem has its own rules:
- **Maven (`pom.xml`):** reads the direct dependencies and resolves `${property}` versions and versions set in the same file's dependency management. Versions that come from a parent POM or a BOM cannot be resolved without Maven, so they are reported as "not checked" with that reason.
- **Python:** pinned `==` versions and lock files give exact versions. Ranges such as `requests>=2.0` could be any version, so they are not checked.
- **npm:** `package-lock.json` gives exact versions. `package.json` alone usually gives ranges.

### Step 3 and 4: OSV and analysis

The scanner sends every distinct (ecosystem, package, version) to OSV in one batch call. OSV answers with advisory ids only, so each advisory is then fetched once for its summary, severity, aliases and affected version ranges.

- **Severity** comes from the CVSS v3 vector, scored with the standard formula, or from the database's own label (critical, high, moderate, low) when there is no usable vector. Some advisories carry no severity of their own, so it is borrowed from a linked GitHub advisory and marked as borrowed.
- **Fixed version:** each advisory lists the versions that fix it. The scanner picks the fix that sits on the same release line as the installed version, which is usually the smallest safe jump.
- **Version that clears all:** the highest of those per-advisory fixes. It is a ceiling, and it can cross a major version, so treat it as information, not advice.

### Step 5: Lightwell coverage

| Status | Meaning |
|--------|---------|
| Remediated | A Lightwell build of this exact version exists |
| Pre-disclosure | A build exists but is embargoed and members only |
| Nearest build (`other_version`) | Set by the scan when a result would be Not covered but Lightwell does carry a remediated build of a different version of the package. The page shows it as "Nearest build: 2.24.3". Using it means changing versions. It is not coverage, and the build must be checked against your advisories before use. The nearest version is in `lightwell_nearest_version` in the CSV |
| Not covered | No build of this exact version |
| Not checked | Could not be determined (live mode without credentials, or the service refused or failed) |

A build is credited with fixing an advisory only if it lists that advisory. Partial cover is shown as partial, for example "addresses 5 of 12". A build that does not say what it fixes is not counted.

## Starting everything

Run these from the repository root. Requirements: Python 3.10 or newer, `curl`. Nothing to install.

### 1. The Lightwell scanner

```bash
cd lightwell
./start.sh            # demo mode: recorded data, no network at all
./start.sh --live     # live mode: real GitHub and OSV.dev calls
```

It runs in the foreground and logs to the terminal. Open <http://127.0.0.1:8790>. If you start the console with `./demo.sh` instead, the scanner is part of it and is at <http://127.0.0.1:8788/lightwell/>, with no extra port or process.

To run it in the background instead:

```bash
nohup ./start.sh > /tmp/lightwell.log 2>&1 &
```

| Mode | Network | Repositories it accepts | Lightwell column |
|------|---------|--------------------------|------------------|
| Demo | None. Nothing is dialled | Only the recorded ones (the page lists them as chips) | Sample data, labelled |
| Live | GitHub and OSV.dev | Any public repository, or private ones with a token | "Not checked" |

Optional settings go in `lightwell/.env` (copy `lightwell/.env.example`). It is ignored by git. The one worth knowing is `GITHUB_TOKEN`, for private repositories and a higher rate limit. Other variables: `LIGHTWELL_MODE`, `LIGHTWELL_HOST` (default 127.0.0.1), `LIGHTWELL_PORT` (default 8790).

### 2. The patching console

From the repository root:

```bash
./demo.sh             # demo mode: staged data, nothing is patched
```

Open <http://127.0.0.1:8788>. It starts a backend on port 8787 and the page on port 8788. Pick a CVE, assess it, dispatch the plan, then approve. In demo mode no host is touched.

**Windows checkout caveat.** If the checkout has Windows line endings, `./demo.sh` fails with `bash\r: No such file or directory`. That is a local git setting, not a bug, and it also affects `./agentic-patching.py`. Either convert the files (`git config core.autocrlf input` and re-checkout, or `dos2unix`), or start the two processes by hand, which needs no file changes:

```bash
MODE=demo BACKEND_PORT=8787 FRONTEND_PORT=8788 python3 agentic-patching.py serve &
cd frontend
MODE=demo BACKEND_PORT=8787 FRONTEND_PORT=8788 \
  CVE_CONSOLE_BACKEND=http://127.0.0.1:8787 python3 server.py &
```

Live mode (`./demo.sh --live`) needs a filled-in `.env` with real Insights, risk model, RAG and Automation Orchestrator settings. See the main README.

## Checking that it is running

```bash
curl -s localhost:8790/healthz        # {"ok": true}
curl -s localhost:8790/v1/mode        # mode, recorded repositories, which Lightwell source is in use
curl -s localhost:8788/api/mode       # the patching console's mode
ss -ltn | grep -E ':878[78]|:8790'    # which of the three ports are listening
```

## Stopping everything

If you started a program in the foreground, press Ctrl-C in its terminal. The scanner prints `stopped`. `demo.sh` stops both of its processes and prints that it stopped.

If you started them in the background, stop them by port:

```bash
# Lightwell scanner
kill $(lsof -ti :8790)

# patching console (backend and frontend)
kill $(lsof -ti :8787) $(lsof -ti :8788)
```

Confirm nothing is left:

```bash
ss -ltn | grep -E ':878[78]|:8790' || echo "all stopped"
```

To clear the scanner's saved results and repository list, delete the folder `lightwell/data/`. Nothing else keeps state. Recorded demo data lives in `lightwell/demo/` and is not touched by stopping or clearing.

## Using it

1. Open <http://127.0.0.1:8790>. The header says which mode you are in and carries a **Lightwell data** badge; hover it to read where that data came from.
2. Tick the applications to patch in the **Deployed applications inventory** on the left. Each is listed by application name with its owner and host underneath; **Select all** takes the lot. The inventory is a shortlist Lightwell has builds for, then the rest of the repositories a demo scan can answer for, then anything previously saved. In live mode only the shortlist and your saved list appear.
3. Press **Scan**. Each repository shows its progress, then its results. Run from the console rather than on its own, the scan also appears as a bar under the header toggle, in the place the patch run's own stages take on the Infrastructure side. Eight stages: the four steps of the scan — Fetch, Manifests, OSV.dev, Lightwell — and then the four of remediating one of the repositories it found — Plan, Approval, Build, Push. Build is the AAP job (clone, apply the versions, build and verify) and stops at the build host; Push is the separate press that puts the branch somewhere a person can see it. The scan half is one bar for the whole scan, so a step is done when every repository is past it. The remediation half is one repository at a time, so it follows whichever repository you pressed **Plan a fix** on and reads as pending until you press it somewhere.
4. The summary shows repositories scanned, components checked, vulnerable components, and counts by severity, then the Lightwell coverage tiles.
5. Click a package row to open its advisories. Each shows the CVE and GitHub advisory ids (linked to osv.dev), severity and score, the versions that fix it, and a "Fixed by Lightwell build" tag where the build addresses it.
6. Use the filters to narrow by severity, by package name, or by Lightwell coverage.
7. **Download CSV** exports every finding.
8. "Components not checked" and the yellow notes under each repository explain what the scanner could not evaluate and why.

Scans can also be started from the command line:

```bash
curl -s -X POST localhost:8790/v1/scans -d '{"repos":["appsecco/dvja"]}'   # returns {"id": ...}
curl -s localhost:8790/v1/scans/<id>                                       # the results
```

## The recorded demo data

Demo mode serves six recorded repositories (five public, one constructed), so it works with no network.

| Repository | What it shows |
|-----------|---------------|
| `demojam/lightwell-coverage-demo` | **Constructed**, not a real repository. Pins versions the Lightwell Network patches so every coverage outcome appears: 11 of 13 components have a Lightwell build, which addresses 33 of 104 issues |
| `appsecco/dvja` | Java: old Log4j, Struts, MySQL driver. 33 advisories. Lightwell covers none of these versions |
| `adeyosemanputra/pygoat` | Python: pinned requirements and hundreds of advisories |
| `we45/Vulnerable-Flask-App` | Python: a smaller pinned example |
| `fportantier/vulpy` | Python with nothing pinned: shows what cannot be checked |
| `sunil-samuel/Image-Processor` | A repository with no manifest at all. Its requirements were reconstructed from the README's install commands and the scan says so. Only the one pinned package can be checked |

To record more, run `python3 record_demo.py owner/repo` (public repositories only, needs network), or see the "Recording demo data" section of `lightwell/README.md`.

## What was built, and what was left alone

**Added (all under `lightwell/`, nothing else):**
- `scanner/`: manifest parsers, GitHub client, OSV client, Lightwell coverage, scan assembly
- `server.py`: the API and page on port 8790
- `ui/index.html`: the page
- `demo/`: recorded repositories, recorded OSV answers, the sample Lightwell catalog
- `tests/`: 54 tests, no network, run with `python3 -m unittest discover -s tests -t .` from `lightwell/`
- `record_demo.py`, `start.sh`, `.env.example`, `.gitignore`, `README.md`, this document

**Deliberately not changed:** every file that was already in the repository. This was checked, not assumed. Before any work, every existing file was hashed and git's HEAD and index were recorded. After each step they were compared again. The result each time: all existing files byte-identical, HEAD and index unchanged, and the only new entries are under `lightwell/`.

## Limits to state honestly

- **Maven shows direct dependencies only.** A `pom.xml` does not contain the dependency tree, so indirect dependencies are not listed. Versions left to a parent POM or an imported BOM are looked up in live mode (from the repository, then Maven Central), and left as "not checked" with a reason when a parent cannot be reached. Demo mode does not resolve them.
- **Ranges are looked up at their lowest version.** In live mode a range such as `>=2.0` or `^1.2` is checked at the lowest version it allows, and the page marks it as a range. The installed version may be newer, so this can overstate the exposure. A range with no lower bound is not checked. Demo mode does not do this.
- **It reports known advisories.** It does not analyse your code and cannot say whether a vulnerable function is actually reachable.
- **Demo coverage is a sample.** Demo mode answers from a snapshot of Lightwell API lookups, so it will drift from the real catalog. Live mode with credentials asks the Lightwell Network API, and without credentials it says "not checked". Run `curl -s localhost:8790/v1/lightwell/status` (or `./preflight.py`) to check the credentials, and spot-check a package you know Lightwell patches.
- **Counts change over time.** OSV keeps adding advisories, so a live scan next month may differ from the recorded demo data.
- **No authentication.** The scanner listens on 127.0.0.1 only. Do not expose it on a network as it is.

## A five-minute demo script

Before going on stage run `./preflight.py` (add `--scan appsecco/dvja` for a full rehearsal). If it reports a failure on the live checks, start the scanner in demo mode with `./start.sh` and use the recorded repositories below.

1. **Set the scene (30 seconds).** Two programs: the patching console handles the operating system, the scanner handles the application's libraries. Different layers, different CVE sources.
2. **Show where CVEs come from (30 seconds).** Open the scanner. Point at the header: demo mode, sample Lightwell coverage. Say that the CVEs come from OSV.dev, an open database, and that Lightwell supplies fixes, not findings.
3. **Scan a Java app (1 minute).** Tick `appsecco/dvja` in the inventory, press Scan. Open struts2-core. Show the critical advisories, the fixed versions, and the Lightwell column saying "Not covered". Say that this is the real answer: Lightwell patches specific versions, and these are not among them.
4. **Show Lightwell coverage (1 minute).** Tick `demojam/lightwell-coverage-demo` in the inventory and scan. Point at postgresql ("addresses 4 of 4"), then jackson-databind ("addresses 5 of 12", with the "Fixed by Lightwell build" tag on five advisories only). Say that a build is credited only with the advisories Lightwell lists for it, and that snakeyaml shows a build with "not itemised". Say that this repository is constructed from versions Lightwell patches, and the page says so.
5. **Show the honesty (1 minute).** Tick `sunil-samuel/Image-Processor` and scan. Point at "11 components not checked" and the yellow note that the manifest was reconstructed. Say that the scanner prefers saying "not checked" to guessing.
6. **Show the other side (1 minute).** Open the patching console. Assess CVE-2024-3094, send it for approval, approve. Say that this is the operating system layer, and that remediation for the application layer, using the scanner's findings, is the next step.
7. **Close the loop (1 minute).** Go back to `demojam/lightwell-coverage-demo` and point at the bar "What it takes to clear the issues": most issues are fixed by a Lightwell build with the version unchanged, and some of those have no fixed version in OSV.dev at all. Press Download plan and open the file: the entries to paste, the Lightwell repository setup, and the draft pull request. Say that the pull request is text, nothing is pushed. Then say what comes next: carrying it out through Ansible and a real pull request.
