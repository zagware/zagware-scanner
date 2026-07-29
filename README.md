# Zagware Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fzagware%2Fzagware--scanner-2496ED?logo=docker&logoColor=white)](https://github.com/zagware/zagware-scanner/pkgs/container/zagware-scanner)
[![Platforms](https://img.shields.io/badge/CI-GitHub%20%7C%20GitLab%20%7C%20Bitbucket%20%7C%20Azure%20DevOps-555)](https://github.com/zagware/zagware-scanner)

**Catch security issues before they reach your main branch.**

Zagware Scanner runs on every pull request and posts a focused comment showing only the security
findings *introduced by that PR* — not the hundreds that may already exist in the codebase.
Your team sees exactly what they need to act on, nothing more.

Three scan engines, one container:

| Engine | What it scans | Detects |
|---|---|---|
| **KICS** (Checkmarx) | Infrastructure-as-code files (Terraform, Kubernetes, Dockerfile, CloudFormation…) | Misconfigurations, insecure defaults, open ports, missing encryption |
| **Grype** (Anchore) | Package manifests and lockfiles (npm, pip, Go, Maven, Gem…) | CVEs, GHSA advisories — with CVSS, EPSS, and KEV catalog status |
| **betterleaks** | Filesystem contents (working-tree state) | Leaked credentials — API keys, tokens, private keys, and other secret patterns |

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
```

`GITHUB_TOKEN` is provided automatically by GitHub — no secrets to configure for the scanner itself.
`ZAGWARE_PLATFORM_URL` and `ZAGWARE_PLATFORM_TOKEN` are optional; omit them to run the scanner
standalone (PR comment only, no platform upload).

The `issue_comment` trigger and `contents: write` permission are required for the
[interactive suppression](#suppressions) feature (`/zagware suppress <id> <reason>` PR comments).
If you don't need that, you can omit them and keep just the `pull_request` trigger with
`permissions: pull-requests: write`.

---

### GitLab CI

**One-time setup:** GitLab's built-in `CI_JOB_TOKEN` cannot post merge request notes — you need a
dedicated access token. Create a project or group access token with `api` scope and add it as a
masked CI/CD variable named `GITLAB_TOKEN`.

Add to `.gitlab-ci.yml`:

```yaml
zagware-scanner:
  image: ghcr.io/zagware/zagware-scanner:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    ZAGWARE_PLATFORM_URL:   https://app.zagware.io
    ZAGWARE_PLATFORM_TOKEN: $ZAGWARE_PLATFORM_TOKEN
  script:
    - zagware-scan
  allow_failure: true
```

> **To block merges on new findings:** remove `allow_failure: true` or set `ZAGWARE_FAIL_ON_NEW: "true"`.

#### Group-wide enforcement via Pipeline Execution Policy (GitLab Ultimate)

Create a CI template project in your group with a `zagware-scanner.yml` file, then reference it
from a Pipeline Execution Policy so every project in the group gets the scanner injected without
touching individual CI files. Set `GITLAB_TOKEN` once at the group level.

See the [full policy setup guide](examples/gitlab-ci.yml) for the complete YAML.

---

### Bitbucket Pipelines

Required repository variables: `BITBUCKET_API_TOKEN` (Atlassian API token with Bitbucket read/write
scopes) and `ATLASSIAN_EMAIL`.

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Zagware Security Scanner
          image: ghcr.io/zagware/zagware-scanner:latest
          script:
            - zagware-scan
```

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
        -e ZAGWARE_PLATFORM_URL=https://app.zagware.io \
        -e ZAGWARE_PLATFORM_TOKEN=$(ZAGWARE_PLATFORM_TOKEN) \
        ghcr.io/zagware/zagware-scanner:latest
    displayName: Zagware Security Scanner
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    continueOnError: true
```

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

## Supported IaC formats (KICS)

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

## Supported dependency ecosystems (Grype)

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
| OS packages | Alpine (`apk`), Debian/Ubuntu (`dpkg`), RHEL/CentOS (`rpm`) in Dockerfiles |

SCA scanning is enabled by default when manifest files are detected. Set `ZAGWARE_SCA_ENABLED=false` to disable it.

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

| Variable | Default | Description |
|---|---|---|
| `ZAGWARE_PLATFORM_URL` | — | Base URL of the Zagware platform, e.g. `https://app.zagware.io`. No trailing slash. Required for dashboard upload. |
| `ZAGWARE_PLATFORM_TOKEN` | — | API token (`gtp_…`) from **Settings → API Tokens**. Required for dashboard upload. |
| `ZAGWARE_MIN_SEVERITY` | all | Minimum severity to report: `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO`. Findings below this level are excluded from both scan and PR comment. |
| `ZAGWARE_FAIL_ON_NEW` | `false` | Exit 1 when new findings are found at or above `ZAGWARE_MIN_SEVERITY`. Blocks the merge when set to `true`. |
| `ZAGWARE_EXCLUDE_PATHS` | `.git` | Comma-separated paths or globs to exclude from IaC scanning. |
| `ZAGWARE_SCA_ENABLED` | `true` | Set `false` to skip Grype dependency scanning entirely. |
| `ZAGWARE_SECRETS_ENABLED` | `true` | Set `false` to skip betterleaks secrets scanning entirely. |
| `ZAGWARE_SECRETS_FAIL_ON_PUBLIC` | `true` | Exit 1 when a new secret is found in a **public** repository, regardless of `ZAGWARE_FAIL_ON_NEW`. Betterleaks has no severity to gate on, so repo visibility is the priority signal instead. |
| `ZAGWARE_TELEMETRY` | _(on)_ | Set `off` to disable anonymous usage telemetry. See [Telemetry](#telemetry). |
| `ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME` | `false` | Set `true` to send your org/repo name in clear instead of a one-way hash. |

---

## How findings are fingerprinted

Each IaC finding is identified by a content-based fingerprint (KICS *similarity ID*) derived from
the rule, the resource path, and the file content at the flagged location.

Each SCA finding is fingerprinted as `sha256(cve_id:package_name:package_version)`.

Each Secrets finding is fingerprinted by betterleaks itself (`file_path:rule_id:line`), read from
the report's `Fingerprint` field — never derived from the secret value.

Both approaches mean:
- Code reformatting or line shifts do not create spurious new findings.
- Fixing a finding removes its fingerprint from the diff, even if similar issues remain elsewhere.
- Moving a vulnerable package to a new manifest file is treated as a new finding.

---

## Pinning to a specific version

Pin by tag for reproducibility. Pin by digest for the strongest guarantee:

```yaml
# GitHub Actions — pin by version tag
uses: docker://ghcr.io/zagware/zagware-scanner:2.0.5

# GitLab CI / Bitbucket — pin by tag
image: ghcr.io/zagware/zagware-scanner:2.0.5

# Pin by digest (strongest — immune to tag mutation)
uses: docker://ghcr.io/zagware/zagware-scanner@sha256:<digest>
```

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
| **Provenance** | SLSA Build Level 3 provenance attestation — links the image digest to this exact source commit and workflow run |

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
# Verify the image signature (anchored identity to prevent substring matches)
cosign verify ghcr.io/zagware/zagware-scanner:latest \
  --certificate-identity-regexp "^https://github.com/zagware/zagware-scanner/.+$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify the SLSA provenance
gh attestation verify oci://ghcr.io/zagware/zagware-scanner:latest \
  --repo zagware/zagware-scanner

# Inspect the SBOM (SPDX format)
cosign download attestation ghcr.io/zagware/zagware-scanner:latest \
  | jq -r '.payload' | base64 -d | jq .predicate.packages[].name
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
| GitHub Actions | `permissions: pull-requests: write` (GITHUB_TOKEN is automatic) |
| GitLab CI | `GITLAB_TOKEN` with `api` scope |
| Bitbucket | `BITBUCKET_API_TOKEN` (Atlassian API token) + `ATLASSIAN_EMAIL` |
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

Find the full `similarity_id` in:

1. **Scan artifacts** — `zagware-scan-results/summary.json` (downloaded from the pipeline run)
2. **Platform** — the findings detail view on `app.zagware.io`
3. **Raw KICS JSON** — `zagware-scan-results/iac-head.json` → `queries[].files[].similarity_id`

For SCA findings, the `similarity_id` is `sha256(cve_id:package_name:package_version)`. For Secrets
findings, the `similarity_id` is betterleaks' own `Fingerprint` (`file_path:rule_id:line`).

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
---|---|---|
| _(unset)_ | All (HIGH, MEDIUM, LOW, INFO) | All (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE) |
| `HIGH` | HIGH only | CRITICAL, HIGH |
| `MEDIUM` | HIGH, MEDIUM | CRITICAL, HIGH, MEDIUM |
| `LOW` | HIGH, MEDIUM, LOW | CRITICAL, HIGH, MEDIUM, LOW |

When `ZAGWARE_FAIL_ON_NEW=true`, the scanner exits 1 (breaking CI) if any **new** finding at or
above the configured threshold is introduced by the PR. This applies to both IaC and SCA findings.
Existing findings on the base branch are ignored — only net-new findings gate the merge.

Secrets findings are unaffected by `ZAGWARE_MIN_SEVERITY` (betterleaks has no severity taxonomy) —
see [`ZAGWARE_SECRETS_FAIL_ON_PUBLIC`](#configuration) for the equivalent gate on secrets.

---

## Image tags and release channels

| Tag | Description |
---|---|
| `:<version>` (e.g. `:2.2.0`) | Immutable per release. Pin by digest for the strongest guarantee. |
| `:latest` | Newest release. Moves on every tag push. **Not** security-vetted. |
| `:stable` | Promoted from `:latest` after a 14-day cooling period + clean CVE scan. Moves only on promotion. |
| `:secure` | Identical digest to `:stable`. Explicitly marks the security-audited image. |

**Recommendation:** Pin `:stable` (or `:secure`) by digest for production CI. Use `:latest` for
experimentation and getting the newest scanner features.

### Promotion workflow

1. A new version is tagged → image builds as `:<version>` and `:latest`
2. After 14 days, the promotion workflow runs Grype + Trivy against the `:latest` digest
3. If no HIGH/CRITICAL CVEs are found → `:stable` and `:secure` are re-tagged to the same digest
4. If CVEs are found → promotion is blocked, a GitHub issue is opened, `:latest` stays
5. A weekly audit workflow re-scans `:stable` for post-promotion CVE disclosures

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
| `scanner_version` | `"2.8.0"` | For understanding rollout/adoption of new releases |

### What is never sent

File contents · file paths · finding descriptions · CVE IDs · package names/versions ·
branch names · commit SHAs · CI tokens/secrets · IP-based geolocation (`$ip: 0` is set explicitly
to disable PostHog's IP capture).

### Identity: hashed by default

`repo_id`/`org_id` are a one-way SHA-256 hash of your platform + repo/org name — stable across
runs (so PostHog can group "same repo scanned N times") but **not reversible** to your actual
repo/org name by Zagware or anyone with PostHog access. If you're comfortable with Zagware seeing
the plaintext name (e.g. for support purposes, or if you already share it via the platform
integration), set `ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME=true`.

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

Apache License 2.0 — see [LICENSE](LICENSE) for the full text.

Copyright 2026 Zagware Ltd.
