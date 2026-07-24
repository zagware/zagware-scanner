# Zagware Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-davymcaleer99%2Fzagware--scanner-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/davymcaleer99/zagware-scanner)
[![Platforms](https://img.shields.io/badge/CI-GitHub%20%7C%20GitLab%20%7C%20Bitbucket%20%7C%20Azure%20DevOps-555)](https://github.com/zagware/zagware-scanner)

**Catch security issues before they reach your main branch.**

Zagware Scanner runs on every pull request and posts a focused comment showing only the security
findings *introduced by that PR* — not the hundreds that may already exist in the codebase.
Your team sees exactly what they need to act on, nothing more.

Two scan engines, one container:

| Engine | What it scans | Detects |
|---|---|---|
| **KICS** (Checkmarx) | Infrastructure-as-code files (Terraform, Kubernetes, Dockerfile, CloudFormation…) | Misconfigurations, insecure defaults, open ports, missing encryption |
| **Grype** (Anchore) | Package manifests and lockfiles (npm, pip, Go, Maven, Gem…) | CVEs, GHSA advisories — with CVSS, EPSS, and KEV catalog status |

---

## How it works

1. **Clone** your base branch and the PR branch (using your CI token — no extra credentials needed).
2. **Scan both** — KICS on IaC files, Syft+Grype on package manifests — in parallel.
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

concurrency:
  group: zagware-scanner-${{ github.ref }}
  cancel-in-progress: true

permissions:
  pull-requests: write

jobs:
  security-scan:
    name: IaC + SCA security scan
    runs-on: ubuntu-latest
    steps:
      - name: Zagware Security Scanner
        uses: docker://davymcaleer99/zagware-scanner:latest
        env:
          GITHUB_TOKEN:           ${{ github.token }}
          PR_NUMBER:              ${{ github.event.pull_request.number }}
          ZAGWARE_PLATFORM_URL:   ${{ secrets.ZAGWARE_PLATFORM_URL }}
          ZAGWARE_PLATFORM_TOKEN: ${{ secrets.ZAGWARE_PLATFORM_TOKEN }}
```

`GITHUB_TOKEN` is provided automatically by GitHub — no secrets to configure for the scanner itself.
`ZAGWARE_PLATFORM_URL` and `ZAGWARE_PLATFORM_TOKEN` are optional; omit them to run the scanner
standalone (PR comment only, no platform upload).

---

### GitLab CI

**One-time setup:** GitLab's built-in `CI_JOB_TOKEN` cannot post merge request notes — you need a
dedicated access token. Create a project or group access token with `api` scope and add it as a
masked CI/CD variable named `GITLAB_TOKEN`.

Add to `.gitlab-ci.yml`:

```yaml
zagware-scanner:
  image: davymcaleer99/zagware-scanner:latest
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
          image: davymcaleer99/zagware-scanner:latest
          script:
            - zagware-scan
```

---

### Azure DevOps

**One-time setup:**
1. Enable **Allow scripts to access the OAuth token** (Pipeline → Edit → Triggers → YAML → Additional options).
2. Grant the Build Service identity **Contribute to pull requests** on the repository.

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
        -e BUILD_SOURCEVERSION \
        -e SYSTEM_PULLREQUEST_TARGETBRANCH \
        -e SYSTEM_PULLREQUEST_SOURCEBRANCH \
        -e SYSTEM_PULLREQUEST_PULLREQUESTID \
        -e TF_BUILD \
        -e ZAGWARE_PLATFORM_URL=https://app.zagware.io \
        -e ZAGWARE_PLATFORM_TOKEN=$(ZAGWARE_PLATFORM_TOKEN) \
        davymcaleer99/zagware-scanner:latest
    displayName: Zagware Security Scanner
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    continueOnError: true
```

---

## PR comment

The scanner posts a single in-place comment per PR. On push, the comment is updated — never duplicated.

```
## Zagware IaC Scanner

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

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ZAGWARE_PLATFORM_URL` | — | Base URL of the Zagware platform, e.g. `https://app.zagware.io`. No trailing slash. Required for dashboard upload. |
| `ZAGWARE_PLATFORM_TOKEN` | — | API token (`gtp_…`) from **Settings → API Tokens**. Required for dashboard upload. |
| `ZAGWARE_MIN_SEVERITY` | all | Minimum severity to report: `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO`. Findings below this level are excluded from both scan and PR comment. |
| `ZAGWARE_FAIL_ON_NEW` | `false` | Exit 1 when new findings are found at or above `ZAGWARE_MIN_SEVERITY`. Blocks the merge when set to `true`. |
| `ZAGWARE_EXCLUDE_PATHS` | `.git` | Comma-separated paths or globs to exclude from IaC scanning. |
| `ZAGWARE_SCA_ENABLED` | `true` | Set `false` to skip Grype dependency scanning entirely. |

---

## How findings are fingerprinted

Each IaC finding is identified by a content-based fingerprint (KICS *similarity ID*) derived from
the rule, the resource path, and the file content at the flagged location.

Each SCA finding is fingerprinted as `sha256(cve_id:package_name:package_version)`.

Both approaches mean:
- Code reformatting or line shifts do not create spurious new findings.
- Fixing a finding removes its fingerprint from the diff, even if similar issues remain elsewhere.
- Moving a vulnerable package to a new manifest file is treated as a new finding.

---

## Pinning to a specific version

```yaml
# GitHub Actions — pin by version tag
uses: docker://davymcaleer99/zagware-scanner:2.0.0

# GitLab CI / Bitbucket
image: davymcaleer99/zagware-scanner:2.0.0
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
`davymcaleer99/zagware-scanner:latest`.

The image requires internet access at build time to download KICS, Syft, and Grype from their
public GitHub releases. At scan time, it only needs access to clone your repository and post
the PR comment.

---

## Frequently asked questions

**Does the scanner send my code anywhere?**
No. It runs entirely within your CI environment. It clones your repo with your CI token, scans
locally, and posts results via your CI platform's API. No code leaves your infrastructure.

**What if I already have thousands of existing findings?**
That's exactly the scenario this tool is built for. Existing findings are ignored. You only see
what the PR under review introduces.

**Can I disable SCA without disabling IaC?**
Yes — set `ZAGWARE_SCA_ENABLED=false` in the environment.

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

## Contributing

Issues and pull requests are welcome. The scanner logic lives in
[`src/scanner.py`](src/scanner.py) — a single-file Python script with no external dependencies.
KICS, Syft, and Grype are bundled in the Docker image.

Please open an issue before starting significant work so we can discuss approach.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text.

Copyright 2024 Zagware Ltd.
