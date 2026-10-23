![OpenShift ≥%204.19](https://img.shields.io/badge/Red%20Hat%20OpenShift_≥_4.19-blue?style=flat-square&logo=redhatopenshift&logoColor=white)
![Document Version: 1.0](https://img.shields.io/badge/Document%20Version-1.0-informational?style=flat-square&logo=files&logoColor=white)
![Author: Sunil Samuel](https://img.shields.io/badge/Author-Sunil%20Samuel-informational?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZmZmZiI+PGNpcmNsZSBjeD0iMTIiIGN5PSI3IiByPSI0Ii8+PHBhdGggZD0iTTQgMjF2LTFjMC00LjQyIDMuNTgtOCA4LThzOCAzLjU4IDggOHYxSDR6Ii8+PC9zdmc+&logoColor=white)

# Lightwell: dependency issue scanner

Point it at GitHub or GitLab repositories and it tells you which of their dependencies have known vulnerabilities, how bad each one is, and which version fixes it. Alongside each finding it shows whether Lightwell has a remediated build of that exact version, and which of the advisories that build addresses. In demo mode that answer comes from a small hand-written sample, clearly labelled. From a finished scan it can also carry out a remediation: clone the repository, change the versions you approve, build it, and push a branch, as an AAP job (see Remediation below).

For the full picture (where the CVEs come from, the scan flow, starting and stopping everything, and a demo script) see [docs/WALKTHROUGH.md](docs/WALKTHROUGH.md).

It lives in its own folder and shares no code or state with the patching console. The console's server loads it and serves it as the **Application Patching** page at `/lightwell/` on the console's own port, in the same process, so `./demo.sh` is all that is needed and there is one address to open. It also runs on its own, as below, which is only needed when working on it.

## Run it

```bash
cd lightwell
./start.sh            # demo mode, http://127.0.0.1:8790 (inside the console: http://127.0.0.1:8788/lightwell/)
./start.sh --live     # real GitHub / GitLab and OSV.dev calls
```

Standard library only, Python 3.10 or newer (3.11+ also reads `pyproject.toml` and `poetry.lock`). Nothing to install.

**Demo mode** replays recorded scans of six repositories (five public, one constructed) and opens no network connection. It serves only those six, and says so if you ask for anything else.

| Recorded repository | Why it is there |
|---|---|
| `demojam/lightwell-coverage-demo` | **Constructed**, not a real repository (source in `samples/lightwell-coverage-demo/`). Its versions are ones the Lightwell Network patches, chosen to show every coverage outcome: fully covered, partly covered, covered but not itemised, and not covered |
| `appsecco/dvja` | Maven, old Log4j, Struts and MySQL driver. Nothing in it is covered by Lightwell |
| `adeyosemanputra/pygoat` | Python, pinned requirements, hundreds of advisories |
| `we45/Vulnerable-Flask-App` | Python, a smaller pinned example |
| `fportantier/vulpy` | Python with nothing pinned, to show what is not checked |
| `sunil-samuel/Image-Processor` | Python app with no manifest at all. **Hand-reconstructed**: its requirements file was written from the README's `pip install` commands, and the scan says so. Only `transformers` is pinned there, so only it is checked |
| `JoyChou93/java-sec-code` | A real Spring app with 53 pinned components. **Four of them have Lightwell builds** (xstream 1.4.20, commons-beanutils 1.9.4, commons-net 3.6, httpclient 4.5.12), which resolve 3 of its 158 issues. Partial coverage on a real project |
| `snyk-labs/java-goof` | A real, deliberately vulnerable Java app. One covered component (junit 4.12, a test dependency), resolving 1 of 107 issues |
| `gitlab.com/pdftk-java/pdftk` | GitLab. One covered component, junit 4.12 in the test scope, resolving its one issue |
| `gitlab.com/gitlab-org/security-products/tests/java-maven` | GitLab, a Maven project. Nothing in it is covered |
| `gitlab.com/gitlab-org/security-products/tests/python-poetry` | GitLab, a Poetry project with a lock file. Nothing in it is covered |

**Live mode** reads any public GitHub repository or gitlab.com project. Set `GITHUB_TOKEN` in `lightwell/.env` (copy `.env.example`) to scan private repositories and to lift GitHub's limit of 60 API calls an hour, which is about 20 repositories. A fine-grained token with read-only Contents and Metadata access is enough. If a call fails, live mode says which service failed and why. It never falls back to recorded data.

## What it does

1. Resolves the repository to its default branch and one commit, and lists the files in a single call.
2. Reads the dependency manifests it recognises: `pom.xml`, `build.gradle(.kts)`, `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`. Vendored and build folders are skipped. A `/tree/branch/folder` URL limits the scan to that folder.
3. Turns each dependency into a package URL (PURL) with its exact version.
4. Asks OSV.dev, in one batch, which advisories affect each version, then fetches each advisory once.
5. Reports, per vulnerable package: every advisory with its CVE and GHSA ids, severity and score, the versions that fix it, the fix that applies to the installed version, and the lowest version that clears all of that package's advisories.

Severity comes from the CVSS v3 vector when there is one (scored here with the standard formula), otherwise from the advisory database's own label. Some advisories carry no severity of their own, so it is borrowed from a linked GitHub advisory and marked as such.

## Lightwell coverage

Lightwell does not find vulnerabilities. Its fixes are remediated builds of specific library versions, delivered through repositories on packages.redhat.com. Red Hat's Lightwell Network documentation also describes an API, served from console.redhat.com, for listing packages and checking CVE remediation status. In live mode with credentials this scanner calls it. So the coverage check does not detect anything. It takes what OSV.dev found and asks, for each vulnerable package version: is there a Lightwell build of exactly this version, is it embargoed, and which of these advisories does it address?

| Status | Meaning |
|---|---|
| Remediated | A build of this exact version exists |
| Pre-disclosure | A build exists but is embargoed and members only |
| Nearest build (`other_version`) | Set by the scan when a result would be Not covered but Lightwell does carry a remediated build of a different version of the package. The page shows it as "Nearest build: 2.24.3". Using it means changing versions. It is not coverage, and the build must be checked against your advisories before use. The nearest version is in `lightwell_nearest_version` in the CSV |
| Not covered | No build of this exact version |
| Not checked | Coverage could not be determined |

A build is credited with fixing an advisory only when it lists that CVE or advisory id. A build that does not itemise what it fixes shows "not itemised" and is not counted as fixing anything. Partial cover is shown as partial, for example "addresses 3 of 8".

### Lightwell detail

For every component Lightwell remediates, expanding its row shows a "Lightwell detail" panel built from more of the Lightwell Network API:

| Shown | Comes from |
|---|---|
| The build, when it was built, and the repository it lives in (with the URL to install from) | `/package_versions`, `/repositories` |
| Repository size and the Lightwell features it declares (for example 2,749 builds and 272 advisories in the Java remediated repository) | `/repositories` |
| Every build of that version with its date, and a flag when a newer build than the one matched is listed | `/repositories/{uuid}/maven_packages/{group}/{name}/{version}` |
| Author, license and project URL, only when Lightwell has a value | the same, and the Python equivalent |
| Python distribution files with type, size and sha256 | `/repositories/{uuid}/python_packages/{name}/{version}` |
| Each Lightwell advisory for that version: its own severity next to OSV's, fixed-in build, dates, its text, and its references | `/advisories` |
| Advisories Lightwell lists for that version that OSV did not flag | `/advisories`, compared with the OSV findings |

Notes on how it behaves:

- **It never changes the coverage answer.** The detail lookups are extra. If one fails or is refused, the component still shows as remediated with the same build and the credentials are not marked as refused. The detail is just left out.
- **A cap.** At most 120 extra lookups per scan. Past that, the panel says detail was skipped. Repository facts are fetched once per repository.
- **The build date is the build's own date** from the build list. The package list's `created_at` is when the row was listed, which can be much later, and is shown separately as "listed".
- **A newer build can exist than the one matched.** For `spring-core 5.3.18` the build list goes up to `rhlw-00010` while the package list we match against stops at `rhlw-00006`. The panel flags it. Coverage is still credited to the build found in the package list, so some advisories show "newer than the build matched". Whether the newest build should be the one credited is an open question.
- **References are plain text.** The ones seen so far point at Red Hat's internal Jira, which a customer may not be able to open, so they are not links. Author email addresses are not kept.
- **Demo mode** shows the same panel from a snapshot of these lookups stored in the sample catalog, labelled as a snapshot.

### Lightwell catalog

Three more things come from the same Lightwell calls, with no extra requests per component:

| Shown | Comes from |
|---|---|
| **What Lightwell holds for the package**, covered or not: the remediated builds and the validated versions, the nearest remediated version above the installed one, whether the exact installed version is validated, and "Lightwell does not carry this package" when there are no rows at all | the `/package_versions` list already fetched for each vulnerable package |
| **A catalog panel** in the summary: how many vulnerable packages Lightwell carries at some version, how many have a validated build of the exact version, how many are not covered but have a remediated version elsewhere, and a table of the Lightwell repositories (tier, type, builds, packages, advisories) | the package lists above, and one cached `/repositories` call |
| **Lead time** per advisory: days from the advisory being published to the date of the build that fixes it (the build's own date from the build list), and the median across the scan | `/advisories` and the build list, both already fetched |

Validated repositories list no advisories. They are a catalog tier, not a CVE fix, so a validated build is shown for information and is never counted as coverage. Lists are capped at 12 versions per tier, nearest the installed version first, with the totals shown. A negative lead time means the build is dated before the advisory. The `/repositories/{uuid}/maven_packages/{group}/{name}` version-list endpoint returns the same versions as `/package_versions`, so it is not called. The catalog call is optional: if it fails the panel is left out and nothing else changes.

**Demo mode** reads `demo/lightwell_catalog.json`: sixteen entries that mirror live Lightwell Network API lookups. Eleven are for the versions pinned in the constructed `demojam/lightwell-coverage-demo` repository and five are every covered version found in the three real repositories above (`java-sec-code`, `java-goof`, `pdftk-java`). It is a snapshot, **not** Lightwell's catalog, and it is labelled "sample" in the page header, the summary, the API (`sample: true`) and the CSV (`sample_coverage`). Any version not listed shows as not covered, which is also what the live API says for every other pinned component in the recorded repositories (checked for the three real repositories when the entries were added: their other 81 pinned Java and Python components, none covered). The live catalog changes, so the numbers will drift. No predisclosure example is included, because the account used to build this could not see a predisclosure repository. Because the entries are real catalog facts, check that publishing them is acceptable before this folder is made public. It also holds a `packages` table (what Lightwell held for the 74 vulnerable packages across the recorded repositories, from live lookups) and the `repositories` list for the catalog panel, so the catalog view works offline too.

**Live mode without credentials** reports "not checked" for every component, and says why. Without credentials a real check is not possible. It needs a Red Hat console service account in a user access group with the Repositories viewer role. The API specification is public (`https://console.redhat.com/api/lightwell/v0.1/openapi.json`) and its `package_versions` endpoint accepts `resolves_cve` and `vulnerable_to_cve` filters, which is the lookup the coverage check needs. A guess presented as an answer is worse than a plain "not checked".

**Live mode with credentials** asks the Lightwell Network API (`https://console.redhat.com/api/lightwell/v0.1`). Put `LIGHTWELL_CLIENT_ID` and `LIGHTWELL_CLIENT_SECRET` in `lightwell/.env`. For each vulnerable package version the scanner:

1. fetches a bearer token for the service account from Red Hat SSO (cached until shortly before it expires, about 15 minutes);
2. lists that package's builds through `GET /package_versions`, keeping only the exact group and name, and builds whose version is the installed one plus `.rhlw-N`;
3. calls a build in a `-nXXXX` version or a predisclosure repository "pre-disclosure", and otherwise "remediated", choosing the newest build;
4. for each CVE found, asks `package_versions?resolves_cve=...` to see whether that build resolves it (up to 40 per component), and credits the build with only those.

Check the credentials before scanning: `curl -s localhost:8790/v1/lightwell/status`. It gets a token, makes one call, and reports how many repositories the account can see. It never shows the secret. A refused token, a missing Repositories viewer role or a missing membership are each reported in plain words, and the scan then stops asking rather than repeating the failure. `LIGHTWELL_API_DEMO=true` asks for the API's demo repositories instead of production ones.

**This provider has been run against the live service, but its tests have not.** The tests use responses shaped like the published OpenAPI specification, and the sample catalog used in demo mode is a snapshot of live answers. The specification leaves three things open: whether the `name` filter is case sensitive, how a Maven name appears in the `name` and `group` fields, and how a predisclosure repository is named. A wrong answer on any of them shows up as "Not covered" for something that is covered, so spot-check a package you know Lightwell patches before trusting the numbers.

## The page

The page follows the look of the patching console in `../frontend`: the same colours, type scale, header, panels and controls. Text size (Small, Medium, Large) is under the Aa button and is kept in the browser only. It is one column below 860 px wide and keeps tables scrollable inside their panels.

The left panel lists the files the scanner reads (with which ecosystems Lightwell has builds for), and after a scan, the files it actually read in each repository: path, type, component count, how many of those components are vulnerable, any note about the file, and files that were skipped or could not be fetched.

While a scan runs, each repository has its own section with a turning gear, four steps (fetch repository, read manifests, query OSV.dev, check Lightwell coverage) with their status, a count and a timer, and an activity log. The coverage step counts through the vulnerable components. The OSV.dev step is one batch call, so it shows a spinning gear without a percentage. Lightwell's package-detail calls happen inside the coverage step and are not a separate step.

### Dependency entries

Expanding a package shows a copy-ready entry for each kind of manifest that declares it (up to three), in the form that file uses:

| Declared in | Entry |
|---|---|
| `pom.xml` | a `<dependency>` block (groupId, artifactId, version) |
| `build.gradle`, `build.gradle.kts` | `implementation 'g:a:v'` or `implementation("g:a:v")`, `testImplementation` for test scope |
| `requirements*.txt` | `name==version` |
| `pyproject.toml` | both common forms, captioned: a `[project]` `dependencies` list, and `[tool.poetry.dependencies]` (the parser does not record which one the file uses) |
| `Pipfile.lock`, `poetry.lock`, `package-lock.json` | the command that changes it (`pipenv install`, `poetry add`, `npm install`), plus an `overrides` entry for an indirect npm dependency, because lock files are generated |
| `package.json` | an entry under `dependencies` or `devDependencies` |

The version depends on the row. For a package Lightwell covers it is the Lightwell build (for example `4.12.0.rhlw-00002`, or `0.5.5+rhlw.1` for Python, the string the live API returns), with a collapsed block for the Lightwell repository taken from the Lightwell Network configuration guide: `settings.xml` for Maven, a `repositories` block and `gradle.properties` for Gradle, `.netrc` and an index line for pip, and `poetry source add` or `pipenv install --index` for Poetry and Pipenv. Credentials are placeholders. For a package it does not cover, the version is the lowest one that clears every OSV.dev advisory, plus the closest Lightwell build at another version when there is one, labelled as unverified against your advisories. npm packages only get the upgrade, because Lightwell's repositories cover Java and Python. The page keeps only whether a dependency was test or dev scope, so Maven and Gradle entries add test scope for those and no other scope. The entries are built in the page from data it already has.

### What it takes to clear the issues

The summary has a bar that sorts every issue into one of three groups: fixed by a Lightwell build with the version unchanged, fixed by upgrading, or no fix available. An issue counts as fixed by Lightwell only when the build's advisory list names it, so a covered component whose advisories are not itemised is counted under upgrading or no fix, and the panel says how many components that applies to. The sentence under the bar also says how many of the Lightwell fixes are for issues OSV.dev lists no fixed version for. Without a coverage check the bar shows the OSV.dev view alone.

### Remediation plan

Each repository, and the summary for all of them, has a Download plan button. It writes a markdown file from data the page already holds: a summary, one entry per component to change (the Lightwell build when one covers it, otherwise the OSV.dev upgrade) in the form each manifest uses, the Lightwell repository setup for the ecosystems involved, a list of components that cannot be fixed from here, and a draft pull request with a branch name, a one-line commit message and a description. The pull request is text only. Nothing is pushed, opened or committed, and the page has no GitHub write access.

### Version ranges

A dependency declared as a range (`>=2.0`, `~=2.0`, `^1.2.3`, `~1.2`, `1.x`, `[1.0,2.0)`, `1.+`) has no single version. With `RESOLVE_RANGES=on` (the default in live mode, off in demo mode) the scanner looks up the lowest version the range allows, asks OSV.dev and Lightwell about that version, and labels the result:

| Syntax | Examples | Looked up |
|---|---|---|
| Maven, Gradle | `[1.0,2.0)`, `(1.0,2.0)`, `[1.0,)`, `1.+` | `1.0`, `1.0` (just above), `1.0`, `1` |
| requirements, `[project]` | `>=2.0`, `~=2.0`, `==2.*`, `>=1.0,<2.0` | `2.0`, `2.0`, `2`, `1.0` |
| `[tool.poetry]` | `^1.2.3`, `~1.2`, `1.*`, `^1.0 \|\| ^2.0` | `1.2.3`, `1.2`, `1`, `1.0` |
| package.json | `^1.2.3`, `~1.2`, `1.x`, `>=1.0.0 <2.0.0`, `1.2.3 - 2.3.4` | `1.2.3`, `1.2.0`, `1.0.0`, `1.0.0`, `1.2.3` |

If a range has several lower bounds the highest is used, and for `||` alternatives the lowest. An exclusive bound (`>1.0`) uses the bound itself and the page says "just above". A range with no lower bound (`<2.0`, `*`, `latest`, `!=1.5`, a URL) has nothing to look up and stays "not checked". Lock files and exact pins are never treated as ranges, and an exact pin anywhere in the repository for the same version means that version is not shown as range-derived.

**This can overstate the exposure.** The lowest version is the oldest one the range permits. The version actually installed is usually newer, so some of what is found may not affect the real build. The page marks these rows with a "range" tag whose tooltip names the declared range, says so in the row's details and in the summary, and the CSV has a `declared_range` column. A lock file or a pip freeze is the accurate source.

### Parent POMs and BOMs

A module's `pom.xml` usually does not carry the version of a dependency: it comes from the parent POM or from a BOM imported into `dependencyManagement`. The scanner follows that chain, the way Maven builds the effective POM. `RESOLVE_POMS` sets how far it looks:

| `RESOLVE_POMS` | What is read | Default |
|---|---|---|
| `all` | the parents and BOMs in the same repository, then published ones fetched from Maven Central | live mode |
| `repo` | only those in the same repository, nothing is fetched | |
| `off` | each `pom.xml` alone, as before | demo mode |

- **Order.** Where several places set one version, the pom's own `dependencyManagement` wins, then its imported BOMs (the first import wins), then what its parent manages. A child's property overrides the parent's, as in Maven. A BOM that imports other BOMs, or has a parent, is followed to a depth of 8.
- **Where it looks first.** A parent is looked for in the repository by its `relativePath`, then by its coordinates, and fetched only if it is not there. A BOM is looked for by its coordinates first.
- **What is fetched.** Only published POMs, from one fixed host: Maven Central, or the mirror in `MAVEN_REPO_URL`, which only the person running the server can set. The group, artifact and version are checked to be plain text before they go into a URL, so a scanned file cannot point the server at another address. At most 60 POMs per scan, 1 MB each, and 90 seconds, then it stops fetching and says so. Each published POM is cached for the life of the server, because a published POM never changes, and so is a 404.
- **What it says.** Each pom gets a note listing the parents and BOMs it was resolved through and whether they came from the repository or Maven Central. A parent or BOM that cannot be found, read or fetched is named in a note, and its dependencies stay "not checked". A failure there never stops the scan.
- **Demo mode** keeps `off` so its recorded OSV and Lightwell answers still match the versions they were recorded for. Turning it on there changes which versions are found, and those versions would have no recorded answer.
- **Not covered:** private parents and BOMs that are not on Maven Central (a company repository, or Red Hat's own) stay unresolved unless `MAVEN_REPO_URL` points at a mirror that has them. The mirror's credentials are not supported. Gradle version catalogs and variables are still not resolved.

## What it cannot see

The page and the API both say these out loud, because a partial answer that looks complete is worse than a smaller honest one.

- **Maven: direct dependencies only.** A `pom.xml` does not contain the dependency tree, so indirect dependencies are not listed. A resolved tree or an SBOM would close this gap. Versions that a pom leaves to a parent POM or an imported BOM are looked up (see the next section) in live mode. Where a parent or BOM cannot be reached, the dependency is listed as "not checked" with the reason.
- **Ranges are checked at their lowest version, in live mode only.** `requests>=2.0` is looked up as 2.0 and marked as a range, which can overstate the exposure because the installed version may be newer. A range with no lower bound is listed as not evaluated, and demo mode does not look ranges up at all (see Version ranges). Lock files (`poetry.lock`, `Pipfile.lock`, `package-lock.json`) give exact versions and are read in full.
- **Gradle** is read only where dependencies are written as `group:artifact:version` strings. Version catalogs and variables are not resolved.
- **Known vulnerabilities only.** This reports advisories that exist. It does not analyse your code, and it does not say whether a vulnerable function is actually reachable.
- **The "version that clears all" can be a big jump.** It is the highest of the per-advisory fixes, which can cross a major version. It is a ceiling to reason from, not a recommendation. Picking a safe path is the remediation step.

## API

| Method and path | Purpose |
|---|---|
| `GET /` | The page |
| `GET /healthz` | Liveness |
| `GET /v1/mode` | Mode, supported GitLab hosts, recorded demo repositories, which tokens are set, and which Lightwell coverage source is in use (`sample` or `none`) |
| `GET /v1/repos`, `PUT /v1/repos` | The saved repository list (`{"repos": [...]}`) |
| `POST /v1/scans` | `{"repos": ["owner/repo", ...]}` starts a scan, returns `202 {"id": ..., "reused": n}`. An optional `"reuse": "<scan id>"` carries over that scan's finished results for repositories in the new list, so only the others run (see below). If every repository is carried over, nothing starts and the answer is `200 {"id": null, "reused": n}` |
| `GET /v1/scans` | Recent scans |
| `GET /v1/scans/{id}` | One scan: per repository, its commit, manifests, findings (each with its Lightwell coverage and which advisories that build addresses), notes and anything that could not be checked |
| | While a repository is being scanned its entry also carries `progress`: the state of each step (`fetch`, `parse`, `osv`, `coverage`) with a detail line and, for coverage, a count, an activity log capped at 200 lines, and the server clock (`now`). It is held in memory only and is gone once the repository finishes, so it is never stored with the scan |
| `GET /v1/scans/{id}/findings.csv` | The findings as CSV, cells guarded against spreadsheet formula injection. Includes `host`, `lightwell_build_date`, Lightwell's own `lightwell_severity`, `lightwell_nearest_version` and `lightwell_lead_days` (the longest among the advisories credited to the build) |
| `POST /v1/remediations/preview` | `{"scan": "<id>", "url": "<repository as scanned>", "sources": ["lightwell", "another", "osv"]}` returns the changes that choice would make, the findings left alone with reasons, how many findings each source could fix, and the Lightwell repositories the build needs. No side effects |
| `POST /v1/remediations` | The same body, plus an optional `"push": true`. Starts the run and returns `202 {"id": ...}`. The change list is worked out again on the server from the stored scan, not taken from the request |
| `GET /v1/remediations/{id}` | The run: `state` (`running`, `done`, `failed` or `unknown` when the controller cannot be reached), each stage, the diff, the build output and whether the branch was pushed |

**Carrying over results.** The page sends the id of the scan on screen as `reuse` when you press Scan, so adding a repository to the list runs only the new one. The new scan still holds every repository, in the list's order, with the carried-over ones marked `reused` and `reused_from`, and keeping their original `scanned_at`. Repositories are matched by host, path, branch and folder, so `acme/app` and `https://github.com/acme/app.git` are the same one, while `acme/app/tree/main/svc` is not. A repository that failed last time runs again. An unknown scan id, or one from the other mode (demo or live), is ignored and everything runs. A carried-over result is not re-checked: new commits in the repository, or new Lightwell builds, do not show until you press Rescan all, which sends no `reuse`.

Accepted repository forms: `owner/repo` (GitHub), `https://github.com/owner/repo(.git)` and `.../tree/<branch>/<folder>` for GitHub, and `https://gitlab.com/group/project`, nested groups (`group/subgroup/project`) and `.../-/tree/<branch>/<folder>` for GitLab. Up to 25 repositories per scan.

Only github.com, gitlab.com and the GitLab hosts you list are accepted. This server fetches whatever host a user types, so an open list would let a URL point it at internal addresses. Settings in `lightwell/.env`, all optional:

| Variable | Purpose |
|---|---|
| `GITLAB_TOKEN` | gitlab.com only: private projects and a higher rate limit. Needs `read_api` or `read_repository` |
| `GITLAB_HOSTS` | Self-hosted GitLab hostnames to allow, comma-separated, with a port if it is not 443 |
| `GITLAB_TOKENS` | A token for specific hosts, as comma-separated `host=token` pairs |

A token is sent only to the host it belongs to, only in a request header. `GITLAB_TOKEN` is never sent to a self-hosted host. GitLab reads at most 5,000 tree entries and 60 manifests per project and says so if it hits either. Those limits have not been tried on a very large project. The Lightwell coverage check works the same for both hosts, since it matches the packages OSV flags and does not depend on where the repository lives.

```bash
curl -s -X POST localhost:8790/v1/scans -d '{"repos":["appsecco/dvja"]}'
curl -s localhost:8790/v1/scans/<id> | python3 -m json.tool | less
```

## Safety notes

- It listens on `127.0.0.1` only and has no authentication. Do not expose it on a network as it is.
- `GITHUB_TOKEN` and the GitLab tokens are read from `lightwell/.env` or the environment, are never logged and never appear in an error message. They are not read from the console's `.env`.
- Manifests are untrusted input. `pom.xml` files that declare a DOCTYPE or entity are refused rather than parsed, bodies are capped at 64 KB, repository names are validated against a strict pattern, and scan ids are validated before they touch the filesystem.
- The only data sent outward is repository names (to GitHub or GitLab) and package coordinates (to OSV.dev). Nothing from this machine, and nothing from the rest of this repository, goes anywhere.

## Recording demo data

```bash
python3 record_demo.py owner/repo https://gitlab.com/group/project   # public repositories only
```

This runs the live scanner and writes the fetched manifests to `demo/repos/` and the matching OSV answers to `demo/osv.json`, trimmed to the fields the scanner reads (about 1.3 MB for the repositories above). Everything in `demo/` is committed with the code, so record only public repositories. The advisory text comes from OSV.dev and the databases it aggregates (the GitHub Advisory Database, the PyPI advisory database and others), each under its own license, which is worth a look before this folder is published.

## Before a demo

`./preflight.py` checks the running scanner: that it answers, the mode, the Lightwell credentials (in live mode the scanner makes its usual authenticated call to the Lightwell API, and nothing else is contacted), a warning when there is no GitHub token, in live mode whether the AAP controller accepts the token and knows the job template and build host (read-only calls, nothing is launched; a problem is a warning because detection works without it), and in demo mode that the repositories the demo script uses are recorded. `./preflight.py --scan appsecco/dvja` also runs one scan through the scanner and reports the counts, which saves a result to the history. It exits non-zero when a check fails. If the live checks fail on the day, restart in demo mode with `./start.sh`.

## Layout

```
lightwell/
  start.sh  server.py  record_demo.py  preflight.py
  scanner/    parse.py  repo.py  github.py  gitlab.py  osv.py  lightwell.py  scan.py  http.py  remediate.py  aap.py
  remediation.py                  remediation runs: change list, AAP job or staged demo run
  store.py                        scan results as JSON files under data/ (gitignored)
  ui/index.html                   the page
  demo/                           recorded repositories, OSV answers, and the sample Lightwell catalog
  samples/lightwell-coverage-demo the constructed demo application's pom.xml and requirements.txt
  tests/                          unittest, no network
```

Run the tests with `python3 -m unittest discover -s tests -t .` from this folder. They cover the parsers, the CVSS scoring and version ordering, URL parsing for both hosts, the GitHub, GitLab and OSV clients against faked responses, the Lightwell coverage logic (including a test that fails if the sample catalog and the recorded scans drift apart), the pre-flight checks against a stub, and the HTTP API end to end in demo mode. The page's JavaScript has no automated tests; it was checked by rendering the page in a headless browser.

## Remediation

Each repository card has a **Remediate** button. It clones the repository, changes the dependency versions, builds the result, and can push the branch, all as one job on the AAP controller (`aap-setup/playbooks/app_clone_update_build.yml`). The scanner decides what to change and the job applies exactly that list, so what you approved is what runs.

Pick where a fix may come from, with three checkboxes:

| Choice | Used for | What changes in the project |
|---|---|---|
| Lightwell | A Lightwell build exists for the exact version in use | The version gets the Lightwell build suffix (for example `42.3.3` becomes `42.3.3.rhlw-00006`), and the build is pointed at the Lightwell repository |
| Lightwell with Another Build | Lightwell has no build of that version but has one of a nearby version | The version moves to that Lightwell build. Check that it covers your advisories |
| OSV | OSV.dev lists a fixed version | The version is upgraded to the lowest one that clears every advisory |

An OSV upgrade that moves a component to a new major version (1.x to 3.x) is not applied unless you tick **Allow upgrades across a major version**. It often needs a newer Java or Python and changes APIs the code uses, so the build can fail; the component is listed under "not changed" with the version OSV offered. It does not apply to Lightwell builds.

A component that qualifies for more than one ticked choice uses Lightwell first, then Lightwell with Another Build, then OSV. A component that no ticked choice covers is left alone and listed under "not changed" with the reason, as is anything declared in a file type that is not edited automatically (only `pom.xml` and requirements files are). The page shows the exact list of changes before you approve it. Lightwell alone is ticked to start with, since it changes no upstream versions.

After **Approve and run** the page shows the stages (clone, update the versions, build) with the status of each step inside them, the diff, and the build output. Steps come from the job's events on the controller; a step that fails shows its message, and steps that did not apply to the repository are counted rather than listed. The run stops at "built and verified". **Push branch** is a second, separate approval: it runs the job again with the push step on, and pushes `fix/dependency-vulnerabilities` for review. A pom.xml version held in a property is changed in the property; a version managed by a parent or BOM, or declared as a range, is reported as not applied.

In demo mode nothing is cloned, built or pushed. The run is staged: it steps through the same tasks the playbook runs, in about a minute, and a push ends with the "Pushed to" line a real one shows. The diff is real: the same edit script the job uses is applied to the recorded files. In live mode `AAP_BASE_URL` and `AAP_TOKEN` come from the project's root `.env` (the controller the rest of the demo uses; `lightwell/.env` wins if it sets them too), and the rest can go in `lightwell/.env`:

| Variable | Purpose |
|---|---|
| `AAP_BASE_URL`, `AAP_TOKEN` | The controller's API address (ending in `/api/controller/v2`) and a token that can launch the job template |
| `AAP_APP_TEMPLATE` | The job template name. Default `App Patch - Clone, Update, Build` |
| `AAP_BUILD_HOST` | Optional. Passed as the job's limit to pick one host of the build inventory |
| `AAP_CA_BUNDLE` | Optional. A CA bundle to trust, for a controller whose certificate comes from a private authority |

The AAP side is set up with `aap-setup/create-app-patch-objects.py` (see `aap-setup/README.md`). The job host needs git 2.31 or newer, python3, curl and tar, and outbound access to Maven Central and `api.adoptium.net`; it works out the Java version the repository needs, fetches that JDK and Maven when the host lacks them, and says which version it used on the page. The **Java for the build** menu overrides the detection (8, 11, 17 or 21). The controller's execution environment is enough, so a separate build host is optional. Credentials reach the job as environment variables from AAP credentials and are never written to disk; the GitHub token is sent as a one-command header, so it is not stored in the clone.

Things to know:

- Runs are kept in memory only. A restart forgets them; the pushed branch is the lasting record.
- The live job has been tested here on a local host against a local repository (clone, edit, build, commit, push). It has not been run against a real controller or against the live Lightwell registry, so check a first run by hand.
- The build uses whatever the project builds with by default (`mvn verify`, or `pip install -r requirements.txt`). A project that needs other steps needs the playbook adjusted.

## What comes next

Remediation now covers Maven and Python projects and stops at a branch. Next is opening the pull request from that branch, and a policy change or an escalation for what no source can fix.
