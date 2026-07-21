# Zagware IaC Scanner

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-davymcaleer99%2Fzagware--iac--scan-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/davymcaleer99/zagware-iac-scan)
[![Platforms](https://img.shields.io/badge/CI-GitHub%20%7C%20GitLab%20%7C%20Bitbucket%20%7C%20Azure%20DevOps-555)](https://github.com/zagware/iac-scanner)

**Catch infrastructure security issues before they reach your main branch.**

Zagware IaC Scanner runs on every pull request and posts a focused comment showing only the security findings *introduced by that PR* — not the hundreds that may already exist in the codebase. Your team sees exactly what they need to act on, nothing more.

---

## How it works

Most IaC scanners run against the full codebase and produce a wall of findings, the majority of which are pre-existing and outside the scope of the current PR. Zagware IaC Scanner takes a different approach:

1. **Scans your base branch** (e.g. `main`) and records a fingerprint for every finding.
2. **Scans the PR branch** and records its findings.
3. **Diffs by content fingerprint** — not by line number, so code reformatting or shifting lines around never creates false positives.
4. **Posts the delta** directly as a comment on the PR, updated on every push.

The result is a signal-to-noise ratio that makes security findings actually actionable.

---

## Quick start

Pick your CI platform below. No scripts, no extra files, no configuration beyond what's shown.

### GitHub Actions

Create `.github/workflows/zagware-iac-scan.yml` in your repository:

```yaml
name: Zagware IaC Scanner

on:
  pull_request:
    types: [opened, synchronize, reopened]

concurrency:
  group: zagware-iac-${{ github.ref }}
  cancel-in-progress: true

permissions:
  pull-requests: write

jobs:
  iac-scan:
    name: IaC security scan
    runs-on: ubuntu-latest
    steps:
      - name: Zagware IaC Scanner
        uses: docker://davymcaleer99/zagware-iac-scan:latest
        env:
          GITHUB_TOKEN: ${{ github.token }}
          PR_NUMBER:    ${{ github.event.pull_request.number }}
```

That's the entire file. `GITHUB_TOKEN` is provided automatically by GitHub — no secrets to configure.

---

### GitLab CI

**One-time setup:** GitLab's built-in `CI_JOB_TOKEN` does not have permission to post merge request notes — this is a [GitLab platform limitation](https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html). You need to create a dedicated access token and add it as a CI/CD variable once per project (or once at the group level to cover all projects).

**Step 1 — Create an access token with `api` scope:**

*Project-level* (Settings → Access Tokens → Add new token → role: Developer, scope: `api`):
```
Settings → Access Tokens → Add new token
Role: Developer   Scope: api ✅   Copy the generated token
```
*Group-level* (covers all projects in the group): Settings → Access Tokens → same steps.

**Step 2 — Add it as a masked CI/CD variable:**
```
Settings → CI/CD → Variables → Add variable
Key:    GITLAB_TOKEN
Value:  <your token>
Mask:   ✅  (hides it from job logs)
```

**Step 3 — Add the job to your `.gitlab-ci.yml`:**

```yaml
zagware-iac-scan:
  stage: test
  image: davymcaleer99/zagware-iac-scan:latest
  script:
    - /usr/local/bin/zagware-scan
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: true
```

All other required variables (`CI_JOB_TOKEN`, `CI_PROJECT_PATH`, `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `CI_SERVER_URL`) are injected automatically by GitLab for merge request pipelines.

> **New GitLab.com accounts:** GitLab.com requires identity verification before running CI/CD pipelines. If your pipelines trigger but no jobs appear, visit **https://gitlab.com/-/profile/identity_verification** to complete verification (credit card hold or mobile number — one-time only).

> **To block merges on new findings:** remove `allow_failure: true`.

---

### GitLab — group-wide enforcement (Pipeline Execution Policy)

If you have a **GitLab Ultimate** license, you can enforce the scanner across every repository in a group without touching individual project CI files. A [Pipeline Execution Policy](https://docs.gitlab.com/user/application_security/policies/pipeline_execution_policies/) injects the scanner job into every MR pipeline automatically — new repos pick it up the moment they are created in the group.

**Prerequisites:**
- GitLab Ultimate license (or trial)
- Owner role on the group
- `GITLAB_TOKEN` with `api` scope (same token as the per-project setup above)

#### Step 1 — Set a group-level CI/CD variable

This covers every project in the group with a single entry.

```
Group → Settings → CI/CD → Variables → Add variable
Key:    GITLAB_TOKEN
Value:  <your group or personal access token with api scope>
Mask:   ✅
```

#### Step 2 — Create a shared CI template project

Create a **private** project in the group (e.g. `your-group/ci-templates`) and add the file `zagware-iac-scan.yml`:

```yaml
# zagware-iac-scan.yml
# Referenced by the pipeline execution policy — do not add this file
# to individual projects; the policy injects it automatically.

zagware-iac-scan:
  stage: .pipeline-policy-pre
  image: davymcaleer99/zagware-iac-scan:1.0.4
  script:
    - /usr/local/bin/zagware-scan
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: true
```

> **Stage note:** use `stage: .pipeline-policy-pre`. This is a reserved GitLab stage that runs before all project jobs and is always available regardless of what stages a project defines. Using `stage: .pre` alone causes the policy to be silently treated as empty and the job is never injected.

#### Step 3 — Allow the template project to be read by pipelines

For each project in the group that will run the policy (and for the security policy project you create in Step 4), add `ci-templates` to their CI job token allowlist:

```
ci-templates → Settings → CI/CD → Job token permissions → Allowlist
Add: <each project that needs to include from ci-templates>
```

Alternatively, add `ci-templates` as a *target* on the allowlist of each source project:

```
infra-project → Settings → CI/CD → Job token permissions → This project's allowlist
Add target: your-group/ci-templates
```

#### Step 4 — Create and link a security policy project

GitLab requires a dedicated project to store security policies. You can create and link it in one step using the GraphQL API:

```graphql
mutation {
  securityPolicyProjectCreate(input: { fullPath: "your-group" }) {
    project { id fullPath }
    errors
  }
}
```

Run this at **https://gitlab.com/-/graphql-explorer** (authenticated). GitLab creates a project named `your-group-security-policy-project` and links it to the group automatically.

#### Step 5 — Add the policy YAML

In the newly created security policy project, push `.gitlab/security-policies/policy.yml` via a merge request (the `main` branch is protected — direct push is not allowed):

```yaml
---
pipeline_execution_policy:
  - name: Zagware IaC Scanner
    description: >-
      Inject IaC security scanning into every MR pipeline across
      the group. No per-project configuration required.
    enabled: true
    pipeline_config_strategy: inject_policy
    content:
      include:
        - project: your-group/ci-templates
          file: zagware-iac-scan.yml
```

Once the MR is merged, GitLab propagates the policy to all projects in the group. Every subsequent MR pipeline in any group project will have `zagware-iac-scan` injected and run automatically.

#### What each project's `.gitlab-ci.yml` looks like

Nothing scanner-related is needed. Projects keep their own CI as normal:

```yaml
stages:
  - build
  - test

my-build-job:
  stage: build
  script: make build
```

The scanner runs alongside `my-build-job` without any reference to it in the project.

#### Excluding or limiting scope

By default the policy applies to every project in the group. Use `policy_scope` in the policy YAML to restrict it.

**Exclude specific projects** (blocklist — everything scanned except the listed repos):

```yaml
---
pipeline_execution_policy:
  - name: Zagware IaC Scanner
    enabled: true
    pipeline_config_strategy: inject_policy
    content:
      include:
        - project: your-group/ci-templates
          file: zagware-iac-scan.yml
    policy_scope:
      projects:
        excluding:
          - id: 12345678   # legacy-monolith — not yet IaC
          - id: 87654321   # design-assets — no infrastructure code
```

Find a project's numeric ID in **Settings → General → Project ID**, or in the URL bar when you open the project on GitLab.

**Scan only specific projects** (allowlist — nothing scanned unless explicitly listed):

```yaml
    policy_scope:
      projects:
        including:
          - id: 12345678
          - id: 23456789
```

**Exclude all archived projects** (useful when a group contains many frozen repos):

```yaml
    policy_scope:
      projects:
        excluding:
          - type: archived
```

**Scope to a subgroup** (scan production infra repos but leave sandbox alone):

```yaml
    policy_scope:
      groups:
        including:
          - id: 98765432   # your-group/production subgroup ID
```

> **Note:** an empty `including: []` does **not** mean "no projects" — GitLab treats it as if the field were absent, so the policy still applies everywhere. To disable the policy without deleting it, set `enabled: false`.

#### Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| Scanner job never appears in pipelines | `inject_ci` strategy used — it is deprecated and silently broken | Change to `pipeline_config_strategy: inject_policy` |
| Policy shows as active in API but no jobs injected | Job uses `stage: .pre` only — GitLab treats `.pre`-only policy pipelines as empty | Use `stage: .pipeline-policy-pre` |
| `include: project:` silently fails | CI job token scope restrictions prevent cross-project reads | Add `ci-templates` to the allowlist of each source project (Settings → CI/CD → Job token permissions) |
| Policy YAML ignored (0 active policies) | Invalid `content` format — only `content.include.project:` is accepted | Do not use `content: \|` string blocks or inline job keys directly under `content:` |

> **To block merges on new findings:** remove `allow_failure: true` from the template job, or set `ZAGWARE_FAIL_ON_NEW: "true"` as a group CI/CD variable.

### Bitbucket Pipelines

**One-time setup — two repository variables required:**

Bitbucket's auto-injected `BITBUCKET_TOKEN` is an OAuth token scoped only for the current pipeline step and cannot authenticate against the Bitbucket REST API for writing PR comments. You need an Atlassian API token for comment posting.

**Step 1 — Create an Atlassian API token with Bitbucket scopes:**

Go to **https://id.atlassian.com/manage-profile/security/api-tokens** → Create API token → under *Product access*, select **Bitbucket** and enable at minimum:
- Repositories: **Read** + **Write**
- Pull Requests: **Read** + **Write**
- Pipelines: **Read** + **Write**

**Step 2 — Add two repository variables:**

Go to **Repository settings → Pipelines → Repository variables** and add:

| Key | Value | Secured |
|---|---|:---:|
| `BITBUCKET_API_TOKEN` | Your Atlassian API token | ✅ |
| `ATLASSIAN_EMAIL` | Your Atlassian account email | ❌ |

**Step 3 — Add to your `bitbucket-pipelines.yml`:**

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Zagware IaC Scanner
          image: davymcaleer99/zagware-iac-scan:latest
          script:
            - /usr/local/bin/zagware-scan
```

> **Pipelines must be enabled** on the repository (Repository settings → Pipelines → Settings → Enable Pipelines). Bitbucket requires **Two-step verification** on your Atlassian account before pipelines can be enabled in a workspace.

> **To block merges on new findings:** set the `ZAGWARE_FAIL_ON_NEW` repository variable to `"true"` and remove `allow_failure` (not needed — the step will exit with a non-zero code).
---

### Azure DevOps

**One-time setup:**
1. In your pipeline settings, enable **Allow scripts to access the OAuth token** (Pipeline → Edit → Triggers → YAML → Additional options).
2. Grant the build service identity **Contribute to pull requests** permission on the repository (Project settings → Repositories → Security).

Add the following to your `azure-pipelines.yml`:

```yaml
trigger: none

pr:
  branches:
    include:
      - '*'

jobs:
  - job: ZagwareIaCScan
    displayName: IaC security scan
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
            davymcaleer99/zagware-iac-scan:latest
        displayName: Zagware IaC Scanner
        env:
          SYSTEM_ACCESSTOKEN: $(System.AccessToken)
        continueOnError: true
```

> **To block merges on new findings:** remove `continueOnError: true`.

---

## PR comment

When new findings are detected, the scanner posts a comment like this:

```
## Zagware IaC Scanner

Comparing `main` → `feat/add-storage`

|               | Base branch | This PR | New |
|---------------|:-----------:|:-------:|:---:|
| Findings      |     342     |   359   | 17  |

⚠️ 17 new finding(s) introduced by this PR
🟠 5 HIGH · 🟡 6 MEDIUM · 🔵 2 LOW · ⚪ 4 INFO
```

Each severity group is collapsible and includes:

| Field | Description |
|---|---|
| **File** | Repository-relative path (e.g. `terraform/main.tf`) |
| **Line** | Line number of the finding |
| **Resource** | Terraform resource or Kubernetes object name |
| **Issue** | Issue type (missing attribute, incorrect value, etc.) |
| **Expected / Actual** | What the scanner expected to find vs what it found |

If the PR is clean, the comment reads: **✅ No new security findings introduced by this PR.**

The comment is updated in place on every push — it never accumulates duplicates.

---

## Supported IaC platforms

The scanner checks for security issues across a wide range of infrastructure-as-code formats:

| Platform | Examples |
|---|---|
| **Terraform** | AWS, Azure, GCP, OCI resource configurations |
| **Kubernetes** | Deployments, DaemonSets, Pods, StatefulSets, RBAC |
| **Helm** | Chart templates and values |
| **Dockerfile** | Container image build definitions |
| **AWS CloudFormation** | Templates (JSON and YAML) |
| **Azure Resource Manager** | ARM templates |
| **Ansible** | Playbooks and task files |
| **OpenAPI / Swagger** | API specification files |
| **Docker Compose** | `docker-compose.yml` |
| **Serverless Framework** | `serverless.yml` |
| **GitHub Actions** | Workflow files |
| **Knative** | Service and event definitions |
| **Pulumi** | Infrastructure programs |
| **gRPC** | Protocol buffer definitions |

---

## Findings coverage

Security findings are categorised across the following domains:

- **Access Control** — overly permissive IAM roles, public bucket policies, missing authentication
- **Networking and Firewall** — unrestricted ingress, open management ports (SSH, RDP), missing network policies
- **Encryption** — unencrypted storage volumes, databases without encryption at rest, plaintext secrets
- **Insecure Configurations** — privileged containers, missing security contexts, default credentials
- **Backup and Recovery** — versioning disabled, missing lifecycle policies, no point-in-time recovery
- **Observability** — logging disabled, missing audit trails, CloudTrail gaps
- **Resource Management** — missing resource limits, overly broad permissions, untagged resources
- **Supply Chain** — unpinned base images, unsigned artefacts, missing content trust

Findings are reported with severity levels: **CRITICAL**, **HIGH**, **MEDIUM**, **LOW**, **INFO**.

---

## Configuration

Set these as environment variables in your CI configuration. All are optional.

| Variable | Default | Description |
|---|---|---|
| `ZAGWARE_MIN_SEVERITY` | _(unset — all)_ | Minimum severity to report. Findings below this level are excluded from both scans and the PR comment. Valid values: `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` `TRACE` |
| `ZAGWARE_FAIL_ON_NEW` | `false` | Exit with a non-zero code when new findings exist at or above `ZAGWARE_MIN_SEVERITY`, blocking the PR merge. |
| `ZAGWARE_EXCLUDE_PATHS` | `.git` | Comma-separated list of paths or glob patterns to skip during scanning. |
| `ZAGWARE_DEBUG` | _(unset)_ | Set to any value to enable verbose debug logging from the scanner. |
| `ZAGWARE_PLATFORM_URL`   | _(unset)_ | Base URL of the GTP API, e.g. `https://api.gtp.example.com`. When set together with `ZAGWARE_PLATFORM_TOKEN`, scan results are uploaded to the platform after each run. |
| `ZAGWARE_PLATFORM_TOKEN` | _(unset)_ | GTP API token (`gtp_...`). Create one at **Settings → API Tokens** in the platform dashboard. |

### Severity threshold

`ZAGWARE_MIN_SEVERITY` controls what gets scanned, shown in the PR comment, and counted for pass/fail. Findings below the threshold are never generated — they do not appear in the comment or affect the build outcome.

| `ZAGWARE_MIN_SEVERITY` | Severities scanned |
|---|---|
| `CRITICAL` | 🔴 CRITICAL only |
| `HIGH` | 🔴 CRITICAL · 🟠 HIGH |
| `MEDIUM` | 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM |
| `LOW` | 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🔵 LOW |
| `INFO` or unset | All severities including ⚪ INFO |

**GitHub Actions — block merges on HIGH or above:**
```yaml
- uses: docker://davymcaleer99/zagware-iac-scan:latest
  env:
    GITHUB_TOKEN:          ${{ github.token }}
    PR_NUMBER:             ${{ github.event.pull_request.number }}
    ZAGWARE_MIN_SEVERITY:  "HIGH"
    ZAGWARE_FAIL_ON_NEW:   "true"
```

**GitLab CI — report MEDIUM and above, block on any new finding:**
```yaml
zagware-iac-scan:
  image: davymcaleer99/zagware-iac-scan:latest
  script:
    - /usr/local/bin/zagware-scan
  variables:
    ZAGWARE_MIN_SEVERITY: "MEDIUM"
    ZAGWARE_FAIL_ON_NEW:  "true"
    # GITLAB_TOKEN is set as a masked project/group variable — see GitLab setup above
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

**Bitbucket Pipelines** — add `ZAGWARE_MIN_SEVERITY` and `ZAGWARE_FAIL_ON_NEW` as repository variables alongside `BITBUCKET_API_TOKEN` and `ATLASSIAN_EMAIL`.

**Azure DevOps** — add `ZAGWARE_MIN_SEVERITY` and `ZAGWARE_FAIL_ON_NEW` as pipeline variables and pass them with `-e ZAGWARE_MIN_SEVERITY -e ZAGWARE_FAIL_ON_NEW` in the docker run command.

### How `ZAGWARE_FAIL_ON_NEW` interacts with `ZAGWARE_MIN_SEVERITY`

When both are set, the build fails **only** if there are new findings at or above `ZAGWARE_MIN_SEVERITY`. A PR that introduces only LOW or INFO findings against a `ZAGWARE_MIN_SEVERITY=HIGH` threshold will pass the build — those findings are filtered out before any comparison occurs.

---

## Pinning to a specific version

The `latest` tag always points to the most recent release. For reproducible builds, pin to a specific version tag or image digest:

```yaml
# GitHub Actions — pin by version tag
uses: docker://davymcaleer99/zagware-iac-scan:1.0.4

# GitHub Actions — pin by digest (most reproducible)
uses: docker://davymcaleer99/zagware-iac-scan@sha256:1c39d5a5d300c3a20346f016b60d69b31ed69704c6c5a6a0103cb613e0cee3f6
```

```yaml
# GitLab CI / Bitbucket — pin by version tag
image: davymcaleer99/zagware-iac-scan:1.0.4
```

---

## Self-hosting

The `Dockerfile` in this repository is fully self-contained. To build and host your own image:

```bash
git clone https://github.com/zagware/iac-scanner.git
cd iac-scanner

docker build -t your-registry/iac-scanner:latest .
docker push your-registry/iac-scanner:latest
```

Then substitute `your-registry/iac-scanner:latest` wherever this documentation references `davymcaleer99/zagware-iac-scan:latest`.

The only build-time dependency is internet access to download the scanner binary and rule set from their public GitHub releases. After the image is built, no outbound network access is required at scan time other than to clone your repository and post the PR comment.

---

## How findings are fingerprinted

Each finding is identified by a content-based fingerprint computed from the query that triggered it, the resource key path, and the file content at the flagged location. This means:

- **Reformatting or shifting code** does not create spurious new findings.
- **Moving a resource to a different file** is detected as a new finding (because it's a genuine change to that resource's location).
- **Fixing a finding** correctly removes its fingerprint from the PR result, even if other instances of the same issue remain in the codebase.

This approach eliminates the line-number instability that affects SARIF-based diff tools.

---

## Frequently asked questions

**Does the scanner send my code anywhere?**  
No. The container runs entirely within your CI environment. It clones your repository using the token your CI platform already has, scans locally, and posts results to your PR via the platform API. No data leaves your infrastructure.

**What permissions does it need?**

| Platform | What's needed | How |
|---|---|---|
| **GitHub Actions** | `pull-requests: write` | Add `permissions: pull-requests: write` to the workflow job. `GITHUB_TOKEN` is automatic. |
| **GitLab CI** | `GITLAB_TOKEN` with `api` scope | Create a project or group access token and add it as a masked CI/CD variable named `GITLAB_TOKEN`. See [GitLab setup](#gitlab-ci) above. For group-wide enforcement without per-project configuration, see [Pipeline Execution Policy](#gitlab--group-wide-enforcement-pipeline-execution-policy). |

**Can I use it on private repositories?**  
Yes. The clone uses the token provided by your CI platform, which already has access to your private repository.

**Does it scan every file on every PR?**  
Yes — both the base branch and the PR branch are cloned fresh and scanned in full. The diff is computed from the fingerprints, not from git diff output. This ensures nothing is missed due to changed context lines.

**What if I already have thousands of existing findings?**  
That's exactly the scenario this tool is built for. Existing findings are ignored entirely. You see only what the PR under review introduces.

---

## Contributing

Issues and pull requests are welcome. The scanner logic lives in [`src/scanner.py`](src/scanner.py) — it's a single-file Python script with no external dependencies.

Please open an issue before starting significant work so we can discuss approach.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text.

Copyright 2024 Zagware Ltd.
