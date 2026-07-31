# Zagware Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fzagware%2Fzagware--scanner-2496ED?logo=docker&logoColor=white)](https://github.com/orgs/zagware/packages/container/package/zagware-scanner)
[![Platforms](https://img.shields.io/badge/CI-GitHub%20%7C%20GitLab%20%7C%20Bitbucket%20%7C%20Azure%20DevOps-555)](https://github.com/zagware/zagware-scanner)

**Catch security issues before they reach your main branch.**

Zagware Scanner runs on every pull request and posts a focused comment showing only the security
findings *introduced by that PR* — not the hundreds that may already exist in the codebase.
Your team sees exactly what they need to act on, nothing more.

Three scan engines, one container:

| Engine | What it scans | Detects |
|---|---|---|
| **[KICS](https://github.com/Checkmarx/kics)** (Checkmarx, Apache 2.0) | Infrastructure-as-code files (Terraform, Kubernetes, Dockerfile, CloudFormation…) | Misconfigurations, insecure defaults, open ports, missing encryption |
| **[Syft](https://github.com/anchore/syft)** (Anchore, Apache 2.0) | Package manifests and lockfiles — generates the SBOM Grype scans | Software Bill of Materials (SPDX) |
| **[Grype](https://github.com/anchore/grype)** (Anchore, Apache 2.0) | Package manifests and lockfiles (npm, pip, Go, Maven, Gem…) | CVEs, GHSA advisories — with CVSS, EPSS, and KEV catalog status |
| **[betterleaks](https://github.com/betterleaks/betterleaks)** (betterleaks, MIT) | Filesystem contents (working-tree state) | Leaked credentials — API keys, tokens, private keys, and other secret patterns |

---

**Contents**

- [How it works](#how-it-works)
- [Image tags and release channels](#image-tags-and-release-channels)
- [Quick start](#quick-start)
- [PR comment](#pr-comment)
- [Supported IaC formats](#supported-iac-formats-kics)
- [Supported dependency ecosystems](#supported-dependency-ecosystems-syft--grype)
- [Secrets detection](#secrets-detection-betterleaks)
- [Configuration](#configuration)
- [Scan artifacts](#scan-artifacts)
- [How findings are fingerprinted](#how-findings-are-fingerprinted)
- [Pinning to a specific version](#pinning-to-a-specific-version)
- [Supply chain security](#supply-chain-security)
- [Self-hosting](#self-hosting)
- [Frequently asked questions](#frequently-asked-questions)
- [Suppressions](#suppressions)
- [Severity filtering](#severity-filtering)
- [Telemetry](#telemetry)
- [Contributing](#contributing)
- [License](#license)

---

## How it works

1. **Clone** your base branch and the PR branch (using your CI token — no extra credentials needed).
2. **Scan both** — KICS on IaC files, Syft+Grype on package manifests, betterleaks on the working tree — in parallel.
3. **Diff by fingerprint**, not line number. A finding that existed in the base branch is never
   reported as new, even after refactoring or line shifts.
4. **Post the delta** directly as a PR comment, updated in place on every push.

Scan results are optionally uploaded to the [Zagware platform](https://app.zagware.io) for
historical tracking, trend charts, and suppression management.

---

## Image tags and release channels

| Tag | Description |
|---|---|
| `:<version>` | Immutable per release. Pick a tag from the [releases](https://github.com/zagware/zagware-scanner/releases) page. Pin by digest for the strongest guarantee. |
| `:latest` | Newest release. Moves on every tag push. **Not** security-vetted. |
| `:stable` | Promoted from `:latest` after a 14-day cooling period, a clean CVE scan, and a signature-verify check. **Not yet published** — no release has completed a full promotion cycle at time of writing. |
| `:secure` | Identical digest to `:stable`, once `:stable` exists. |

**Recommendation:** once `:stable` exists, pin it (or better, pin by digest — see
[Pinning to a specific version](#pinning-to-a-specific-version)) for production CI. Until then, pin
an exact `:<version>` tag for a reproducible build rather than tracking `:latest`, unless you
specifically want new features immediately and are comfortable with `:latest`'s lack of a
cooling-off period.

### Promotion workflow

1. A new version is tagged → image builds as `:<version>` and `:latest`
2. After 14 days, the promotion workflow verifies the image's cosign signature and scans it for
   CVEs with Grype
3. If the signature is valid and no HIGH/CRITICAL CVEs are found → `:stable` and `:secure` are
   re-tagged to the same digest
4. If CVEs are found → promotion is blocked, a GitHub issue is opened, `:latest` stays
5. A weekly audit workflow re-scans `:stable` for post-promotion CVE disclosures

---

## Quick start

### GitHub Actions

Create `.github/workflows/zagware-scanner.yml`:

```yaml
name: Zagware Security Scanner

on:
  pull_request:
    types: [opened, synchronize, reopened]
  issue_comment:
    types: [created]      # enables /zagware suppress comments

concurrency:
  group: zagware-scanner-${{ github.event.pull_request.number || github.event.issue.number }}
  cancel-in-progress: true

permissions:
  pull-requests: write
  contents: write   # required for /zagware suppress to commit suppressions.yaml

jobs:
  security-scan:
    name: IaC + SCA security scan
    runs-on: ubuntu-latest
    if: >
      github.event_name == 'pull_request' ||
      (github.event_name == 'issue_comment' &&
       github.event.issue.pull_request != null &&
       contains(github.event.comment.body, '/zagware suppress') &&
       contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association))
    steps:
      - name: Resolve PR refs (comment-triggered runs only)
        if: github.event_name == 'issue_comment'
        id: pr
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          PR_JSON=$(gh api "repos/${{ github.repository }}/pulls/${{ github.event.issue.number }}")
          echo "base_ref=$(echo "$PR_JSON" | jq -r .base.ref)" >> "$GITHUB_OUTPUT"
          echo "head_ref=$(echo "$PR_JSON" | jq -r .head.ref)" >> "$GITHUB_OUTPUT"

      - name: Zagware Security Scanner
        uses: docker://ghcr.io/zagware/zagware-scanner:latest
        env:
          GITHUB_TOKEN:           ${{ github.token }}
          PR_NUMBER:              ${{ github.event.pull_request.number || github.event.issue.number }}
          ZAGWARE_BASE_REF:       ${{ steps.pr.outputs.base_ref }}
          ZAGWARE_HEAD_REF:       ${{ steps.pr.outputs.head_ref }}
          ZAGWARE_PLATFORM_URL:   ${{ secrets.ZAGWARE_PLATFORM_URL }}
          ZAGWARE_PLATFORM_TOKEN: ${{ secrets.ZAGWARE_PLATFORM_TOKEN }}

      - name: Upload scan artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zagware-scan-results-pr${{ github.event.pull_request.number || github.event.issue.number }}
          path: zagware-scan-results/
          retention-days: 30
          if-no-files-found: warn
```

> **Security-conscious consumers:** once `:stable` exists (see
> [Image tags and release channels](#image-tags-and-release-channels)), pin it — or better, pin
> `ghcr.io/zagware/zagware-scanner@sha256:<digest>` from the release notes. The `:latest` shown
> above has no cooling-off period or CVE gate.

`GITHUB_TOKEN` is provided automatically by GitHub — no secrets to configure for the scanner itself.
`ZAGWARE_PLATFORM_URL` and `ZAGWARE_PLATFORM_TOKEN` are optional; omit them to run the scanner
standalone (PR comment only, no platform upload).

> **A new secret fails the job by default on public repositories.**
> `ZAGWARE_SECRETS_FAIL_ON_PUBLIC` defaults to `true`, so on a public repo the scanner exits 1 —
> blocking the merge — the first time a PR introduces a new secret, even with `ZAGWARE_FAIL_ON_NEW`
> left at its `false` default. Set `ZAGWARE_SECRETS_FAIL_ON_PUBLIC: "false"` to opt out, or
> `ZAGWARE_SECRETS_ENABLED: "false"` to turn secrets scanning off entirely.

The `issue_comment` trigger and `contents: write` permission are required for the
[interactive suppression](#suppressions) feature (`/zagware suppress <id> <reason>` PR comments).
If you don't need that, you can omit them and keep just the `pull_request` trigger with
`permissions: pull-requests: write`.

#### Organization-wide enforcement via GitHub rulesets (GitHub Team+)

GitHub's closest equivalent to GitLab's Pipeline Execution Policy is an **organization ruleset with
a `workflows` rule** ("require workflows to pass before merging"). A single ruleset in one source
repo requires a workflow file to run and pass against every targeted repo's pull requests — targeted
repos carry **no `.github/workflows/*.yml` of their own** for this to work, so enforcement can't be
silently defeated by deleting or renaming a caller file the way branch-protection-plus-reusable-workflow
setups can.

**vs. GitLab Pipeline Execution Policy** (see the [GitLab CI](#gitlab-ci) section below) — same
shape, different edges:

| | GitHub org ruleset (`workflows` rule) | GitLab Pipeline Execution Policy |
|---|---|---|
| Minimum plan | Team | Ultimate |
| Caller file in target repo | None | None |
| Trigger events supported | `pull_request`, `pull_request_target`, `merge_group` only | Any pipeline trigger the policy's CI file declares |
| Targeting | Repo name/pattern or custom properties, org- or enterprise-scoped | Project/group selectors, group-scoped |
| Evaluate-before-enforce mode | Yes (`enforcement: "evaluate"`) | Yes (shadow mode) |
| Bypass list | Yes, per-actor/role | Yes |
| Cross-org / cross-group source | No — source workflow must be in the same org | No — policy CI file must be in the same group hierarchy |

```bash
# One-time: define a custom property and create the org-level ruleset.
# The helper script lives in the separate zagware/security-workflows repository.
# Download it at a pinned commit, read it, then run it -- never pipe a mutable
# branch ref straight into a shell. Resolve the current commit SHA with:
#   gh api repos/zagware/security-workflows/commits/main --jq .sha
curl -fsSLO https://raw.githubusercontent.com/zagware/security-workflows/<commit-sha>/rulesets/setup-org-level.sh

# Review it before running: it PATCHes your organization's custom-property
# schema and POSTs an organization ruleset using your gh credentials.
less setup-org-level.sh

bash setup-org-level.sh <your-org>

# Opt a repo in (or out) without touching the ruleset itself
gh api orgs/<org>/properties/values -X PATCH \
  -f 'repository_names[]=<repo>' \
  -f 'properties[][property_name]=zagware-scan-scope' \
  -f 'properties[][value]=enabled'
```

> **The setup script is not part of this repository.** It is maintained in
> [`zagware/security-workflows`](https://github.com/zagware/security-workflows) and is therefore
> outside this project's release, signing, and checksum guarantees. That is precisely why the
> snippet above pins a commit SHA and reads the script before executing it, rather than piping
> `main` into `bash`.
>
> **Known defect, verified 2026-07-30 at commit `d4189ff`:** the script sets
> `SRC_REPO="zagware-security-workflows"`, but the repository is named `security-workflows`. Its
> step 2 (`gh api repos/<org>/<SRC_REPO>`) consequently 404s *after* step 1 has already defined the
> `zagware-scan-scope` property, leaving a stray property with no ruleset. Set `SRC_REPO` to your
> own org's source-workflow repository while reviewing the script. The fix belongs in
> `zagware/security-workflows`, not in this repo.

See [`zagware/security-workflows`](https://github.com/zagware/security-workflows) for the reference
source workflow, ready-to-fire ruleset JSON, and setup script — verified live end-to-end against a
repo with zero workflow files of its own (the required check appeared, ran, and passed; confirmed as
an active organization-ruleset-sourced rule via `GET /repos/{owner}/{repo}/rules/branches/{branch}`).

**Constraints, confirmed by testing rather than assumed:**

| | |
|---|---|
| **Plan** | Organization rulesets need **GitHub Team or higher** — a Free/Pro org gets `403 Upgrade to GitHub Team` on `POST /orgs/{org}/rulesets`, full stop. There's no repository-level substitute for the `workflows` rule specifically: `repos/{owner}/{repo}/rulesets` structurally rejects that rule type on **any** plan (GitHub's own docs confirm it's org/enterprise-only), so this isn't a matter of upgrading a single repo. |
| **Trigger events** | Only `pull_request`, `pull_request_target`, and `merge_group` are recognized as required-check-producing events for a ruleset workflow — no `push`, no `schedule`. Merge-gating works; periodic/default-branch drift scans need a separate mechanism (e.g. a `schedule`-triggered workflow committed directly in each repo, or the App-based out-of-band scanning described below). |
| **Source repo scope** | The ruleset's referenced workflow must live in a repo in the **same organization** — an org can't point at a workflow in a different org. Multi-org customers need one source repo + one ruleset per org. |
| **Fails closed on disabled Actions** | If GitHub Actions is disabled on a targeted repo, the required check never produces a result and the PR is **permanently unmergeable** until Actions is re-enabled or the repo is dropped from the ruleset's scope. Expect this to surface as a support ticket the first time it happens. |
| **Forks** | A forked repo does not inherit the parent's ruleset. Only relevant if a customer runs an internal-fork contribution model. |
| **Allowed-actions policy** | Orgs running "allow select actions only" need `zagware/*` explicitly allowlisted, since the workflow resolves `uses: docker://ghcr.io/zagware/zagware-scanner:latest` as an action reference. If that's not viable, self-host the equivalent step as a pinned, checksum-verified binary download instead of a Marketplace/registry action reference. |
| **`/zagware suppress` + required workflows** | The suppress flow pushes a commit back to the PR branch using `GITHUB_TOKEN`. GitHub's anti-recursion protection means a `GITHUB_TOKEN`-authored push never re-triggers `pull_request: synchronize`, so under this enforcement path the new commit's required check never gets created and the PR stays blocked. Fixable with a non-`GITHUB_TOKEN` push identity (e.g. a GitHub App installation token) — a platform-side automation concern, not something this standalone scanner solves on its own. |

No org-level ruleset access, or don't want the plan requirement? A `workflow_call` reusable workflow
plus a thin per-repo caller file gets you centralized scan *logic* (bump the image tag or an env var
once, every caller picks it up) on any plan — see `zagware/security-workflows`'s README for the exact
caller snippet. The tradeoff versus the ruleset route: every target repo needs that caller file, and
enforcement silently stops if it's deleted, renamed, or its job name drifts from what's marked
"required" in branch protection.

---

### GitLab CI

**One-time setup:** GitLab's built-in `CI_JOB_TOKEN` cannot post merge request notes — you need a
dedicated access token. Create a project or group access token with `api` scope and add it as a
masked CI/CD variable named `GITLAB_TOKEN`.

Add to `.gitlab-ci.yml`:

```yaml
zagware-scanner:
  stage: test
  image: ghcr.io/zagware/zagware-scanner:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    ZAGWARE_PLATFORM_URL:   $ZAGWARE_PLATFORM_URL
    ZAGWARE_PLATFORM_TOKEN: $ZAGWARE_PLATFORM_TOKEN
  script:
    - zagware-scan
  artifacts:
    name: zagware-scan-results-mr$CI_MERGE_REQUEST_IID
    paths:
      - zagware-scan-results/
    expire_in: 30 days
    when: always
  allow_failure: true
```

> **Security-conscious consumers:** once `:stable` exists (see
> [Image tags and release channels](#image-tags-and-release-channels)), pin it — or better, pin
> `ghcr.io/zagware/zagware-scanner@sha256:<digest>` from the release notes. The `:latest` shown
> above has no cooling-off period or CVE gate.

> **To block merges on new findings:** remove `allow_failure: true` or set `ZAGWARE_FAIL_ON_NEW: "true"`.

#### Group-wide enforcement via Pipeline Execution Policy (GitLab Ultimate)

Two files are involved: (1) a **CI template project** in the group, holding a `zagware-scanner.yml`
file with the same `zagware-scanner:` job body shown above; (2) a **policy** committed to your
group's security policy project (`.gitlab/security-policies/policy.yml`) that references it via
`content.include`, so every project in the group gets the scanner injected without touching
individual `.gitlab-ci.yml` files. Set `GITLAB_TOKEN` once at the group level.

See [`examples/gitlab-pipeline-execution-policy.yml`](examples/gitlab-pipeline-execution-policy.yml)
for the complete policy YAML (file (2) above); it references `examples/gitlab-ci.yml`'s job as
file (1).

---

### Bitbucket Pipelines

Required repository variables: `BITBUCKET_API_TOKEN` (Atlassian API token with Bitbucket read/write
scopes) and `ATLASSIAN_EMAIL`.

Optional: `BITBUCKET_GIT_USER` — the git username paired with your Atlassian API token in the clone
URL. It defaults to `<workspace>-admin`, which is a workspace convention rather than a guarantee.
Set it explicitly if the very first clone fails with a git authentication error.

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Zagware Security Scanner (IaC + SCA)
          image: ghcr.io/zagware/zagware-scanner:latest
          script:
            - zagware-scan
          artifacts:
            - zagware-scan-results/**
```

> **Security-conscious consumers:** once `:stable` exists (see
> [Image tags and release channels](#image-tags-and-release-channels)), pin it — or better, pin
> `ghcr.io/zagware/zagware-scanner@sha256:<digest>` from the release notes. The `:latest` shown
> above has no cooling-off period or CVE gate.

---

### Azure DevOps

**Setup:** usually none beyond the YAML below. `$(System.AccessToken)` is available to any step that
explicitly maps it via `env:` (as shown), and on most organizations the default **Project Collection
Build Service** identity can already read and post pull request comments — no manual permission grant
needed. If the scan step fails posting the comment (`401`/`403` in the log), grant the Build Service
identity **Contribute to pull requests** on the repository (Project settings → Repositories → your repo
→ Security). If `$(System.AccessToken)` itself comes through empty, enable **Allow scripts to access the
OAuth token** (Pipeline → Edit → Triggers → YAML → Additional options) — only seen on pipelines migrated
from the classic editor.

```yaml
trigger: none
pr:
  branches:
    include: ['*']

pool:
  vmImage: ubuntu-latest

steps:
  - script: |
      docker run --rm \
        -e SYSTEM_ACCESSTOKEN \
        -e SYSTEM_TEAMFOUNDATIONCOLLECTIONURI \
        -e SYSTEM_TEAMPROJECT \
        -e BUILD_REPOSITORY_ID \
        -e BUILD_REPOSITORY_URI \
        -e BUILD_REPOSITORY_NAME \
        -e BUILD_SOURCEVERSION \
        -e SYSTEM_PULLREQUEST_TARGETBRANCH \
        -e SYSTEM_PULLREQUEST_SOURCEBRANCH \
        -e SYSTEM_PULLREQUEST_PULLREQUESTID \
        -e TF_BUILD \
        -v "$(Build.SourcesDirectory)/zagware-scan-results:/zagware-scan-results" \
        -e ZAGWARE_OUTPUT_DIR=/zagware-scan-results \
        ghcr.io/zagware/zagware-scanner:latest
    displayName: Zagware Security Scanner (IaC + SCA)
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    continueOnError: true   # remove to gate PRs on the scan result

  - task: PublishBuildArtifacts@1
    displayName: Publish scan artifacts
    condition: always()
    inputs:
      pathToPublish: zagware-scan-results
      artifactName: zagware-scan-results-pr$(System.PullRequest.PullRequestId)
```

> **With the Zagware platform:** add these two `-e` flags to the `docker run` command above
> (before the image reference) to enable dashboard upload:
> ```
> -e ZAGWARE_PLATFORM_URL=$(ZAGWARE_PLATFORM_URL) \
> -e ZAGWARE_PLATFORM_TOKEN=$(ZAGWARE_PLATFORM_TOKEN) \
> ```
> Azure DevOps leaves an undefined `$(VAR)` macro **unexpanded as the literal string** rather
> than empty — define both pipeline variables when you add these flags, or the scanner receives
> a garbage URL/token and attempts (and fails) a platform upload on every run.

> **Security-conscious consumers:** once `:stable` exists (see
> [Image tags and release channels](#image-tags-and-release-channels)), pin it — or better, pin
> `ghcr.io/zagware/zagware-scanner@sha256:<digest>` from the release notes. The `:latest` shown
> above has no cooling-off period or CVE gate.

`BUILD_REPOSITORY_NAME` is required for the `repo_base_url` link in platform uploads — without it the
scanner still works, but that link is omitted. `SYSTEM_TEAMPROJECT` and repository names containing
spaces (the Azure DevOps default) are handled automatically; no extra encoding needed.

If the scanner's existing PR comment was authored by a different identity than the current run (e.g. a
manual test, or the pipeline's Build Service account changed), Azure DevOps blocks editing it — only the
original author or a project admin may update a comment. The scanner detects this (`403` on update) and
starts a fresh comment thread instead of failing the build.

---

## PR comment

The scanner posts a single in-place comment per PR. On push, the comment is updated — never duplicated.

```
## 🏗️ Zagware IaC — Infrastructure Misconfigurations

Comparing `main` → `feat/add-storage`

||Base branch|This PR|New|
|---|:---:|:---:|:---:|
|Findings|342|359|17|

⚠️ 17 new IaC finding(s)
🔴 1 CRITICAL  🟠 5 HIGH  🟡 6 MEDIUM  🔵 3 LOW  ⚪ 2 INFO

---

## 📦 Zagware SCA — Dependency Vulnerabilities

||Base|This PR|New|
|---|:---:|:---:|:---:|
|Vulnerabilities|12|18|6|

⚠️ 6 new vulnerability(ies)
🔴 1 CRITICAL  🟠 3 HIGH  🟡 2 MEDIUM

|CVE|Package|Installed|Fix|CVSS|KEV|
|---|---|:---:|:---:|:---:|:---:|
|CVE-2023-1234|lodash (npm)|4.17.20|4.17.21|9.8|No|

---

## 🔑 Zagware Secrets — Leaked Credentials

| | Base | This PR | New |
|---|:---:|:---:|:---:|
| Findings | 2 | 3 | 1 |

> 🌐 **PUBLIC REPOSITORY** — any leaked secret here is immediately exposed to the world. Rotate affected credentials before merging.

> 🔴 **1 new secret(s) introduced by this PR**

| Rule | File | Line | Validation |
|---|---|:---:|:---:|
|`stripe-access-token`|`config/payments.rb`|5|🔴 Valid|

---
<sub>Zagware Scanner &nbsp;·&nbsp; [zagware/zagware-scanner](https://github.com/zagware/zagware-scanner)</sub>
```

If the PR is clean: **✅ No new security findings introduced by this PR.**

---

## Supported IaC formats ([KICS][])

| Platform | File types |
|---|---|
| Terraform | `.tf`, `.tfvars` |
| Kubernetes | YAML manifests |
| Helm | Chart templates |
| Dockerfile | `Dockerfile*` |
| AWS CloudFormation | JSON, YAML templates |
| Azure Resource Manager | ARM JSON templates |
| Ansible | Playbooks and task files |
| OpenAPI / Swagger | API specification files |
| Docker Compose | `docker-compose.yml` |
| GitHub Actions | Workflow files |
| Serverless Framework | `serverless.yml` |
| Pulumi | Infrastructure programs |

KICS auto-detects file types — no configuration needed.

---

## Supported dependency ecosystems ([Syft][] + [Grype][])

| Ecosystem | Detected via |
|---|---|
| Node.js / npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| Go | `go.sum` |
| Ruby | `Gemfile.lock` |
| Java / Maven | `pom.xml`, `build.gradle` |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| .NET | `packages.lock.json` |

SCA scanning is enabled by default when manifest files are detected. Set `ZAGWARE_SCA_ENABLED=false` to disable it.

> **OS packages inside container images are not scanned.** Syft runs in filesystem (`dir:`) mode
> against the repository working tree, so it catalogues manifests and lockfiles committed to the
> repo. It does not build or pull the images your Dockerfiles reference, and a source checkout has
> no installed `apk`/`dpkg`/`rpm` database to catalogue. Scan built images separately — for example
> `grype <image>` in your image-build pipeline.

---

## Secrets detection (betterleaks)

[betterleaks](https://github.com/betterleaks/betterleaks) scans the working-tree contents of both
branches for leaked credentials — API keys, tokens, private keys, and other secret patterns. Unlike
IaC/SCA, betterleaks has no severity taxonomy; instead, findings are prioritized by **repository
visibility** — a secret leaked in a public repo is immediately exposed to the world, so public repos
are always treated as urgent regardless of `ZAGWARE_FAIL_ON_NEW`. See
[`ZAGWARE_SECRETS_FAIL_ON_PUBLIC`](#configuration) below.

Secrets scanning runs against the current filesystem state only (`betterleaks dir` mode), matching
the same shallow-clone/working-tree-diff architecture already used for IaC and SCA — not full git
history. If your secret was introduced and later removed within the PR's history, it won't be
re-flagged once removed from the working tree; use `betterleaks git` locally for full history scans.

Findings never include the raw secret value in the PR comment, platform upload, or scan artifacts —
only the rule id, file path, line number, tags, and validation status (whether betterleaks confirmed
the credential is live). Set `ZAGWARE_SECRETS_ENABLED=false` to disable it.

---

## Configuration

### Scan behaviour

Boolean-shaped variables below share one vocabulary: `true`/`1`/`yes`/`on` for on,
`false`/`0`/`no`/`off`/`disabled` for off (case-insensitive, whitespace-trimmed).
Any other value is rejected with a warning in the scan log and the default is used —
it is never silently misread as the opposite of what you intended.

| Variable | Default | Description |
|---|---|---|
| `ZAGWARE_PLATFORM_URL` | — | Base URL of the Zagware platform, e.g. `https://app.zagware.io`. No trailing slash. Required for dashboard upload. |
| `ZAGWARE_PLATFORM_TOKEN` | — | API token (`gtp_…`) from **Settings → API Tokens**. Required for dashboard upload. |
| `ZAGWARE_MIN_SEVERITY` | all | Minimum severity to report: `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` `TRACE`. Findings below this level are excluded from both scan and PR comment. |
| `ZAGWARE_FAIL_ON_NEW` | `false` | Exit 1 when the PR introduces new findings, blocking the merge. Counts IaC, SCA **and Secrets** findings in one total: IaC/SCA findings count only at or above `ZAGWARE_MIN_SEVERITY`, while new secrets always count — betterleaks has no severity, so `ZAGWARE_MIN_SEVERITY` never filters them. |
| `ZAGWARE_EXCLUDE_PATHS` | `.git` | Comma-separated paths or globs to exclude from IaC scanning. |
| `ZAGWARE_SCA_ENABLED` | `true` | Set `false` to skip Grype dependency scanning entirely. |
| `ZAGWARE_SECRETS_ENABLED` | `true` | Set `false` to skip betterleaks secrets scanning entirely. |
| `ZAGWARE_SECRETS_FAIL_ON_PUBLIC` | `true` | Exit 1 when a new secret is found in a **public** repository, regardless of `ZAGWARE_FAIL_ON_NEW`. Betterleaks has no severity to gate on, so repo visibility is the priority signal instead. |
| `ZAGWARE_OUTPUT_DIR` | `zagware-scan-results` | Directory scan artifacts are written to — see [Scan artifacts](#scan-artifacts). |
| `ZAGWARE_SUPPRESSIONS_FILE` | `.zagware/suppressions.yaml` | Path (relative to the repo root) to the suppressions file. Change this for monorepos that can't use the default location. |
| `ZAGWARE_QUERIES_PATH` | `/opt/iac-rules/assets/queries` | Path to the KICS query rules tree inside the image. Only relevant for [self-hosted](#self-hosting) builds shipping a custom or additional rules bundle. |
| `ZAGWARE_TELEMETRY` | _(on)_ | Set `off` to disable anonymous usage telemetry. See [Telemetry](#telemetry). |
| `ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME` | `false` | Set `true` to send your org/repo name in clear instead of a one-way hash. |
| `ZAGWARE_ASSUME_PRIVATE` | `false` | Set `true` to treat a repository whose visibility cannot be determined as **private**. By default an undeterminable visibility is treated as public, so `ZAGWARE_SECRETS_FAIL_ON_PUBLIC` still fires — a missing API permission must not silently disable that gate. Set this only where visibility can never be resolved, e.g. air-gapped installs. |
| `ZAGWARE_SUPPRESS_ALLOWED_ASSOCIATIONS` | `OWNER,MEMBER,COLLABORATOR` | Comma-separated GitHub author associations permitted to issue `/zagware suppress` commands. Comments from anyone else are ignored. Widening this lets outside contributors suppress findings on their own pull requests. |

### Platform inputs

**GitHub Actions.** The three variables below are GitHub-only — ignored, and unnecessary to set, on
GitLab CI, Bitbucket Pipelines, and Azure DevOps, which resolve base/head refs and the PR number
from their own native CI variables instead.

| Variable | Required? | Description |
|---|---|---|
| `PR_NUMBER` | **Required** | The pull request number, e.g. `${{ github.event.pull_request.number \|\| github.event.issue.number }}`. Missing this raises an uncaught error before the scan can post a comment. |
| `ZAGWARE_BASE_REF` | Only for `issue_comment`-triggered runs | Overrides `GITHUB_BASE_REF`. GitHub Actions reserves `GITHUB_*` names and silently ignores a workflow-declared override for them on `docker://` actions, so a `/zagware suppress` re-run (which is `issue_comment`-triggered, not `pull_request`-triggered) needs this to resolve the base branch. See [`examples/github-actions.yml`](examples/github-actions.yml) for how to compute it via the GitHub API. |
| `ZAGWARE_HEAD_REF` | Only for `issue_comment`-triggered runs | Same reasoning as `ZAGWARE_BASE_REF`, overriding `GITHUB_HEAD_REF` (falls back to `GITHUB_SHA` otherwise). |

**Bitbucket Pipelines.**

| Variable | Required? | Description |
|---|---|---|
| `BITBUCKET_GIT_USER` | Optional | Git username paired with `BITBUCKET_API_TOKEN` in the clone URL. Defaults to `<workspace>-admin` — a workspace convention, not a guarantee. Set it if cloning fails with a git authentication error. |

### Debugging & advanced

| Variable | Default | Description |
|---|---|---|
| `ZAGWARE_DEBUG` | `false` | Set `true` for debug-level log output — the most useful first step when a scan behaves unexpectedly. |
| `ZAGWARE_SCAN_TIMEOUT` | `600` | Seconds allowed for a single KICS invocation, per branch (so a full run allows up to 2×). Raise it for large monorepos — exceeding it is reported as an explicit scanner failure, not as "no findings". |
| `ZAGWARE_SCANNER_BIN` | `/usr/local/bin/kics` | Path to the KICS binary. Override only in a [self-hosted](#self-hosting) build. |
| `ZAGWARE_SYFT_BIN` | `/usr/bin/syft` | Path to the Syft binary (SBOM generation). Override only in a self-hosted build. |
| `ZAGWARE_GRYPE_BIN` | `/usr/bin/grype` | Path to the Grype binary (dependency vulnerabilities). Override only in a self-hosted build. |
| `ZAGWARE_SECRETS_BIN` | `/usr/local/bin/betterleaks` | Path to the betterleaks binary (secrets). Override only in a self-hosted build. |

**Exit codes:** `0` = clean, `1` = a policy gate fired (`ZAGWARE_FAIL_ON_NEW`, public-repo
secrets) or a scan failed, `2` = the scanner itself crashed. `2` is deliberately distinct so a
broken tool is never mistaken for a PR that legitimately has findings.

---
## Scan artifacts

Every run writes eleven files to `zagware-scan-results/` (or `ZAGWARE_OUTPUT_DIR` if set), whether
or not the platform integration is configured:

| File | Contents |
|---|---|
| `iac-base.json` | KICS findings on the base branch |
| `iac-head.json` | KICS findings on the PR branch — `queries[].files[].similarity_id` for suppression ids |
| `iac-new.json` | Net-new IaC findings introduced by this PR — `queries[].files[].similarity_id` for suppression ids |
| `sca-base.json` | Grype findings on the base branch (normalised) |
| `sca-head.json` | Grype findings on the PR branch |
| `sca-new.json` | Net-new SCA findings introduced by this PR — `[].similarity_id` for suppression ids |
| `secrets-base.json` | betterleaks findings on the base branch (rule id, file path, line, tags, validation status — **never** the secret value) |
| `secrets-head.json` | betterleaks findings on the PR branch |
| `secrets-new.json` | Net-new Secrets findings introduced by this PR — `[].similarity_id` for suppression ids |
| `pr-comment.md` | The rendered markdown comment posted to the PR |
| `summary.json` | Metadata (repo, branches, PR number, repo visibility), per-engine base/head/new finding counts, and per-phase timings in seconds. Contains no `similarity_id` — use the `*-new.json` files above for suppression ids. |

Each of the four example CI files ([GitHub Actions](examples/github-actions.yml),
[GitLab CI](examples/gitlab-ci.yml), [Bitbucket Pipelines](examples/bitbucket-pipelines.yml),
[Azure DevOps](examples/azure-pipelines.yml)) uploads this directory as a pipeline artifact.

---


## How findings are fingerprinted

Each IaC finding is identified by a content-based fingerprint (KICS *similarity ID*) derived from
the rule, the resource path, and the file content at the flagged location.

Each SCA finding is fingerprinted as `sha256(cve_id:package_name:package_version)`.

Each Secrets finding is fingerprinted as `sha256(betterleaks_fingerprint)`, where the input is
betterleaks' own `Fingerprint` field (`file_path:rule_id:line`) — hashed rather than shown raw so
the suppress-command id doesn't expose the file path directly, consistent with IaC/SCA.

Both approaches mean:
- Code reformatting or line shifts do not create spurious new findings.
- Fixing a finding removes its fingerprint from the diff, even if similar issues remain elsewhere.
- Moving a vulnerable package to a new manifest file is treated as a new finding.

---

## Pinning to a specific version

Pin by tag for reproducibility. Pin by digest for the strongest guarantee:

```yaml
# GitHub Actions — pin by version tag
uses: docker://ghcr.io/zagware/zagware-scanner:<version>

# GitLab CI / Bitbucket — pin by tag
image: ghcr.io/zagware/zagware-scanner:<version>

# Pin by digest (strongest — immune to tag mutation)
uses: docker://ghcr.io/zagware/zagware-scanner@sha256:<digest>
```

Replace `<version>` with a published release tag from the
[releases](https://github.com/zagware/zagware-scanner/releases) page. The placeholder is
deliberate — a hardcoded version number in this README goes stale on the next release, and a stale
pin in a copy-paste example is worse than no example at all.

Digests are in the [releases](https://github.com/zagware/zagware-scanner/releases) notes
and in the build summary of each [publish workflow run](https://github.com/zagware/zagware-scanner/actions).

---

## Supply chain security

Every release of `ghcr.io/zagware/zagware-scanner` is built with a verifiable supply chain:

### What we do

| Layer | How |
|---|---|
| **KICS binary** | SHA256 checksum hardcoded in the Dockerfile and verified at build time. GPG signature is intentionally NOT used — downloading the signing key from the same endpoint as the binary provides no independent trust (both could be swapped together) |
| **Syft binary** | SHA256 checksum verified at build time; cosign signature on checksums verified in CI before build |
| **Grype binary** | SHA256 checksum verified at build time; cosign signature on checksums verified in CI before build |
| **betterleaks binary** | SHA256 checksum hardcoded in the Dockerfile and verified at build time; cosign sigstore-bundle signature verified in CI before build |
| **Our image** | Signed with cosign (keyless, GitHub OIDC → sigstore Rekor transparency log) |
| **SBOM** | SPDX SBOM generated at build time and attached as an OCI attestation |
| **Provenance** | SLSA v1.0 Build **Level 2** provenance attestation (`actions/attest-build-provenance`) — links the image digest to this source commit and workflow run; verifiable with `gh attestation verify` |

### Why this matters (TeamPCP context)

In March–April 2026, the TeamPCP campaign compromised KICS GitHub Actions (March 23),
KICS Docker Hub images (April 22), and downstream packages using stolen tokens.

Our mitigations:
- We build from **source-controlled release tarballs on GitHub**, not Docker Hub
- KICS 2.1.20 was published March 3, 2026 — before the compromise windows
- Every binary is **content-addressed by SHA256 checksum** pinned in the Dockerfile.
  A tag being moved or a release artifact being swapped will break the build with
  a clear checksum mismatch error — not a silent supply chain compromise
- The cosign signatures for Syft and Grype are verified in CI **before the Docker
  build starts**, ensuring the checksums file itself was produced by a legitimate
  GitHub Actions run in the anchore org

### Verify the image you're running

```bash
# Verify the image signature (anchored identity to prevent substring matches).
# Substitute :stable/:secure or your pinned :<version> once you're using one --
# :latest is shown here since it's the only channel published so far.
cosign verify ghcr.io/zagware/zagware-scanner:latest \
  --certificate-identity-regexp "^https://github.com/zagware/zagware-scanner/.+$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify the SLSA provenance
gh attestation verify oci://ghcr.io/zagware/zagware-scanner:latest \
  --repo zagware/zagware-scanner

# Inspect the SBOM (SPDX format). BuildKit attaches it as an OCI referrer
# attestation inside the image index -- not as the cosign sha256-<digest>.att
# sidecar tag -- so retrieve it with imagetools, not `cosign download attestation`.
docker buildx imagetools inspect ghcr.io/zagware/zagware-scanner:latest \
  --format '{{ json .SBOM.SPDX }}' | jq -r '.packages[].name'
```

---

## Self-hosting

```bash
git clone https://github.com/zagware/zagware-scanner.git
cd zagware-scanner
docker build -t your-registry/zagware-scanner:latest .
docker push your-registry/zagware-scanner:latest
```

Then substitute `your-registry/zagware-scanner:latest` wherever this documentation references
`ghcr.io/zagware/zagware-scanner:latest`.

The image requires internet access at build time to download KICS, Syft, Grype, and betterleaks
from their public GitHub releases. At scan time, it only needs access to clone your repository
and post the PR comment.

**Note:** Self-hosted builds verify binary SHA256 checksums but do NOT verify the upstream
cosign signatures on Syft/Grype `checksums.txt` (that step runs in our publish CI only).
If you need that guarantee, run the `cosign verify-blob` steps from
`.github/workflows/publish.yml` manually before building.

---

## Frequently asked questions

**Does the scanner send my code anywhere?**
No. It runs entirely within your CI environment. It clones your repo with your CI token, scans
locally, and posts results via your CI platform's API. No code, file contents, or file paths
ever leave your infrastructure. The scanner does send anonymous usage telemetry (which CI
platform, scan durations, bucketed finding counts) — see [Telemetry](#telemetry) for the exact
field list and how to disable it.

**What if I already have thousands of existing findings?**
That's exactly the scenario this tool is built for. Existing findings are ignored. You only see
what the PR under review introduces.

**Can I disable SCA without disabling IaC?**
Yes — set `ZAGWARE_SCA_ENABLED=false` in the environment.

**Can I disable secrets scanning without disabling IaC/SCA?**
Yes — set `ZAGWARE_SECRETS_ENABLED=false` in the environment.

**Can I use it without the Zagware platform?**
Yes. The scanner posts PR comments standalone. `ZAGWARE_PLATFORM_URL` and `ZAGWARE_PLATFORM_TOKEN`
are optional — omit them and the scanner works without any platform account.

**What permissions does it need?**

| Platform | What's needed |
|---|---|
| GitHub Actions | `permissions: pull-requests: write`; add `contents: write` and the `issue_comment: [created]` trigger for [`/zagware suppress`](#suppressions). `PR_NUMBER` must be passed to the step. `GITHUB_TOKEN` is automatic. |
| GitLab CI | `GITLAB_TOKEN` with `api` scope |
| Bitbucket | `BITBUCKET_API_TOKEN` (Atlassian API token) + `ATLASSIAN_EMAIL`; optionally `BITBUCKET_GIT_USER` (defaults to `<workspace>-admin`) if cloning fails to authenticate |
| Azure DevOps | Build Service: Contribute to pull requests + OAuth token access |

---
## Suppressions

Suppress false positives or accepted-risk findings so they don't reappear as "new" on every PR.

### The easy way — comment on the PR

Every scan comment includes a **📋 Suppress findings** section listing each new finding with a
short id. To suppress one, copy the command shown and post it as a PR comment:

```
/zagware suppress 96e6e0d1 false positive — test resource, not production
```

You only need the first 6+ characters of the id — the scanner resolves it against the current
scan's findings. On GitHub, this requires the `issue_comment` trigger and `contents: write`
permission shown in the [Quick start](#github-actions) snippet above, and only PR
authors/collaborators (not external contributors) can trigger a suppression.

> **Currently GitHub-only.** GitLab, Bitbucket, and Azure DevOps don't yet support reading PR
> comments back into the scanner — use the manual file method below on those platforms.

What happens: the scanner re-runs (same PR, comment-triggered), resolves the id, writes it to
`.zagware/suppressions.yaml` on the PR branch, commits and pushes, then **continues the same run**
with the suppression applied — the updated comment shows the finding suppressed and a
confirmation banner (`✅ 1 finding(s) suppressed …`) immediately, no need to wait for a second run.

### The manual way — edit the file directly

Create or edit `.zagware/suppressions.yaml` in your repository:

```yaml
# .zagware/suppressions.yaml
- id: abc123def456...      # similarity_id from the scan results (full or 6+ char prefix)
  reason: "False positive — test resource, not production"

- id: def789abc012...
  reason: "Accepted risk — mitigated by network policy"
```

The easiest source is the **📋 Suppress findings** section of the scan comment itself — it lists a
copy-pasteable id for every current finding on every platform, not just GitHub (only the
`/zagware suppress` PR-comment shortcut is GitHub-only; the ids themselves are always there).
Failing that, find the full `similarity_id` in the scan artifacts (see [Scan artifacts](#scan-artifacts)):

1. **IaC** — `iac-head.json` → `queries[].files[].similarity_id`
2. **SCA** — `sca-new.json` → `[].similarity_id`
3. **Secrets** — `secrets-new.json` → `[].similarity_id`
4. **Platform** — the findings detail view on `app.zagware.io`

For SCA findings, the `similarity_id` is `sha256(cve_id:package_name:package_version)`. For Secrets
findings, the `similarity_id` is `sha256(betterleaks_fingerprint)`, where the fingerprint itself is
betterleaks' `file_path:rule_id:line`.

### How suppressions work

- The scanner reads `.zagware/suppressions.yaml` from the **PR branch** (not main)
- Suppressed findings are excluded from the "new findings" diff — they won't appear in the PR comment
- Suppressed IaC/SCA/Secrets findings are still uploaded to the platform's scan history (for audit trail) but marked as suppressed
- The suppression count is logged in the scan output

### Suppression audit trail

When `ZAGWARE_PLATFORM_URL`/`ZAGWARE_PLATFORM_TOKEN` are configured, every scan uploads the
**full current set of active suppressions** for the repo to the platform — a durable, queryable
record of who suppressed what, when, and why, independent of the git history in
`.zagware/suppressions.yaml`. This is for compliance auditing and to spot which IaC/SCA/Secrets rules get
suppressed so often across repos that the underlying policy may need tightening.

Each record captures: repo, PR number, category (`iac`/`sca`/`secrets`), the finding (name + file), the
reason, and **who added it**:

- Suppressed via a `/zagware suppress` PR comment → exact attribution: the commenter's git
  platform username and the comment timestamp.
- Suppressed by hand-editing `.zagware/suppressions.yaml` directly (no PR comment) → best-effort
  attribution via `git blame` on the file. Less precise (the scanner clones shallow, so blame is
  bounded to the checked-out commit), and marked as such (`added_via: file` vs `pr_comment`) so
  the lower confidence is visible.

Removing an entry from `.zagware/suppressions.yaml` is picked up on the next scan — the platform
marks that record as no longer active rather than deleting its history.

Like scan result uploads, this is non-fatal and best-effort: a failed upload never affects the PR
comment, the exit code, or the scan result.

---

## Severity filtering

Control which severity levels the scanner reports and acts on:

```yaml
env:
  ZAGWARE_MIN_SEVERITY: HIGH    # Only report HIGH and above (IaC + SCA)
  ZAGWARE_FAIL_ON_NEW: "true"   # Break CI if new findings at or above the threshold
```

| `ZAGWARE_MIN_SEVERITY` | IaC findings shown | SCA findings shown |
|---|---|---|
| _(unset)_ | All (CRITICAL, HIGH, MEDIUM, LOW, INFO, TRACE) | All (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE, UNKNOWN) |
| `CRITICAL` | CRITICAL only | CRITICAL, UNKNOWN |
| `HIGH` | CRITICAL, HIGH | CRITICAL, HIGH, UNKNOWN |
| `MEDIUM` | CRITICAL, HIGH, MEDIUM | CRITICAL, HIGH, MEDIUM, UNKNOWN |
| `LOW` | CRITICAL, HIGH, MEDIUM, LOW | CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE, UNKNOWN |
| `INFO` | CRITICAL, HIGH, MEDIUM, LOW, INFO | All (Grype has no INFO/TRACE tier — same as `LOW`) |
| `TRACE` | All (CRITICAL, HIGH, MEDIUM, LOW, INFO, TRACE) | All (same as `LOW`/`INFO`) |

`UNKNOWN` (a real Grype severity value, not just a missing-key default) is never excluded by
any threshold — a CVE Grype couldn't classify is always shown, since hiding it could hide
something critical.

When `ZAGWARE_FAIL_ON_NEW=true`, the scanner exits 1 (breaking CI) if the PR introduces any **new**
finding. This applies to IaC, SCA **and Secrets** findings — all three share one new-findings total.
IaC and SCA findings count only at or above the configured threshold; secrets are counted regardless
of `ZAGWARE_MIN_SEVERITY`, since betterleaks findings have no severity to compare against.
Existing findings on the base branch are ignored — only net-new findings gate the merge.

Secrets findings are unaffected by `ZAGWARE_MIN_SEVERITY` (betterleaks has no severity taxonomy) —
see [`ZAGWARE_SECRETS_FAIL_ON_PUBLIC`](#configuration) for the equivalent gate on secrets.

---

## Telemetry

The scanner sends anonymous usage telemetry to Zagware (via PostHog) so we can see which CI
platforms are actually used, how IaC vs SCA scanning are exercised, and general usage volume.
**No code, file paths, finding descriptions, CVE/package details, branch names, commit SHAs, or
credentials are ever sent.** Full transparency below — this is exactly what leaves your CI runner.

### What is sent

| Field | Example | Notes |
|---|---|---|
| `platform` | `"github"` | Which CI provider (github / gitlab / bitbucket / azure_devops) |
| `repo_id`, `org_id` | `"cea56b328a1226dd"` | SHA-256 hash (16 chars) of your repo/org — **not** the plaintext name (see opt-in below) |
| `is_pr` | `true` | Whether this run scanned a PR/MR |
| `sca_enabled`, `secrets_enabled`, `iac_scanned`, `sca_scanned`, `secrets_scanned` | `true` | Which scan types ran |
| `has_platform_integration` | `false` | Whether `ZAGWARE_PLATFORM_URL`/`TOKEN` are configured (not their values) |
| `min_severity_filter`, `fail_on_new` | `"HIGH"`, `false` | Your configured thresholds |
| `duration_seconds` | `93.9` | Total scan time |
| `iac_new_findings_bucket`, `sca_new_findings_bucket`, `secrets_new_findings_bucket` | `"1-5"` | **Bucketed**, not exact — `0`, `1-5`, `6-20`, `21+`. We deliberately never transmit a precise vulnerability count tied to your org, only a coarse usage signal |
| `suppressions_used` | `true` | Whether `.zagware/suppressions.yaml` had any entries |
| `exit_code` | `0` | 0 or 1 |
| `scanner_version` | `"2.8.2"` | For understanding rollout/adoption of new releases |

### What is never sent

File contents · file paths · finding descriptions · CVE IDs · package names/versions ·
branch names · commit SHAs · CI tokens/secrets.

IP-based geolocation is disabled by sending PostHog's documented
`$geoip_disable: true` property, and no `$ip` value is sent. (Earlier releases sent `$ip: 0`,
which does **not** work — PostHog's GeoIP plugin treats `0` as falsy, discards it, and falls back
to the connecting IP. If you ran a version before this fix, assume the runner's public IP was
captured and geolocated.)

### Identity: pseudonymous by default

`repo_id`/`org_id` are an unsalted SHA-256 hash of your platform + repo/org name, stable across
runs so PostHog can group "same repo scanned N times".

> **This is a pseudonym, not anonymity.** The input space (`owner/repo` strings) is small, public
> and fully enumerable, so for a **public** repository anyone holding the hash — including
> Zagware — can recover the original name from a precomputed table. It reduces casual exposure;
> it does not prevent identification. Salting per-install would break the cross-run grouping the
> field exists for, and a CI container has nowhere durable to keep a salt, so we describe the
> property accurately instead of overclaiming it.

If that is not acceptable for your repo, set `ZAGWARE_TELEMETRY: "off"` — nothing is sent at all.
If you're comfortable with Zagware seeing the plaintext name (e.g. for support purposes, or if
you already share it via the platform integration), set
`ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME=true`.

### Disabling

```yaml
env:
  ZAGWARE_TELEMETRY: "off"
```

Telemetry is best-effort and fail-silent: it runs on a background thread with a 3-second network
timeout, never raises, never retries, and never blocks or slows down your pipeline — even if the
PostHog endpoint is completely unreachable, the scan result and exit code are unaffected.

---


## Contributing

Issues and pull requests are welcome. The scanner logic lives in
[`src/scanner.py`](src/scanner.py) — a single-file Python script with no external dependencies.
KICS, Syft, Grype, and betterleaks are bundled in the Docker image.

Please open an issue before starting significant work so we can discuss approach.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text. Third-party components bundled in
the Docker image (KICS, Syft, Grype, betterleaks, and the Debian base image) are listed with their
own vendors, licenses, and pinned versions in [NOTICE](NOTICE).

Copyright 2026 Zagware Ltd.

<!-- Collapsed reference links, used in the two headings above. An inline
     link written directly inside a heading corrupts its anchor slug for
     every tool that does not strip link markup; the collapsed `[Name][]`
     form renders identically and keeps `#supported-iac-formats-kics` and
     `#supported-dependency-ecosystems-syft--grype` resolvable. -->
[KICS]: https://kics.io
[Syft]: https://github.com/anchore/syft
[Grype]: https://github.com/anchore/grype
