# Changelog

All notable changes to Zagware Scanner are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions are published as container tags — see the
[pinning guidance](README.md#pinning-to-a-specific-version) for which tag to depend on.

## [Unreleased]

## [3.2.0] — 2026-08-06

Advisory SCA reachability enrichment. Language-native tools now layer a
reachability verdict, dependency scope, and evidence traces onto Grype findings
and upload them to the platform alongside the usual results. This release also
folds in the release-process and CI changes previously staged as unreleased; the
image contents move, so `__version__` bumps to 3.2.0.

### Changed

- **Promotion cooling period 14 days → 7.** The window exists so a regression can
  surface in real pipelines before an image becomes `:stable`; at two weeks it
  mostly delayed *security fixes* reaching the channel recommended for
  production. Every regression actually shipped has surfaced within hours to a
  day or two. The value is now a single `COOLING_DAYS` in `promote.yml` — it had
  been the literal `14` in six places, three of them operator-facing error
  strings, which is how a gate and its own error message drift apart.
- **The promotion gate and the weekly audit now fire on *fixable* CRITICAL/HIGH
  findings**, not the raw count. Two `containerd` advisories inside KICS have no
  upstream patch in existence, so a raw-count gate would have filed an identical
  issue every week forever for something nobody can action. Totals are still
  reported everywhere; they just no longer block a release.

### Added
- **SCA reachability enrichment (advisory).** Where a supported manifest and the
  matching tool are both present, the scanner enriches each Grype finding with a
  reachability verdict, dependency scope, and evidence traces, uploaded via the
  new fields on `POST /api/v1/sca/upload` plus a per-scan `enrichment` map:
  - **govulncheck** — Go call-graph reachability (`reachable` / `not_reachable`)
    with call-path traces.
  - **npm audit** — dependency scope (runtime vs dev); reachability left
    `unknown` (it is not call analysis).
  - **osv-scanner** — cross-ecosystem; only claims a reachability verdict where
    OSV call analysis is present (needs the Go toolchain), otherwise it records
    an advisory version-match pass and leaves findings as plain Grype.

  Additive and best-effort: each tool is gated on its binary and the ecosystem's
  manifest, runs under `ZAGWARE_ENRICH_TIMEOUT`, and never blocks or fails a scan.
  `unknown` is never treated as `not_reachable`. Disable with
  `ZAGWARE_SCA_REACHABILITY=false`.
- **Two published images, both cosign-signed + SLSA-attested.** The default
  `:latest` (`--target core`) stays the minimal, fully-attested image, gaining
  only the `osv-scanner` static binary — SHA256-pinned and checksum-matched
  against upstream in `publish.yml`, exactly like Syft/Grype/Betterleaks; it
  carries **no compiler or Node runtime**. Call-graph reachability needs a Go
  toolchain and `npm` needs Node at scan time, so those live in a separate opt-in
  `:reachability` tag (`--target reachability`) that layers `go`/`nodejs`/`npm`
  (apk, Chainguard-signed) plus `govulncheck` (built from pinned source via the
  Go checksum DB). Consumers choose the surface they trust; the core's posture is
  unchanged.

- **`tool-currency.yml`** — a weekly watch over the four bundled scanners and
  three base images, maintaining one continuously-updated issue. It never edits
  a pin; it reports. Three signals: *behind* (newer upstream release), *escalate*
  (fixable CVEs **and** upstream quiet for 90 days or no longer shipping
  `linux/amd64` binaries), and *unpullable pin* (a pinned base digest that no
  longer resolves — a live risk, since Chainguard garbage-collects old digests).
  The escalation signal is the one that caught us out: Checkmarx stopped
  publishing KICS binaries after v2.1.20 and nothing alerted.
- README section **"Keeping the tools current"**, documenting the currency
  signals, the criteria under which we build a tool from source, and the trade
  that decision makes — a source build gains control of the Go toolchain but
  gives up the vendor's cosign release signature, which is why KICS qualifies
  and Syft, Grype, and betterleaks do not.
- README section **"Our vulnerability posture"**, publishing the actual CVE
  numbers and the fixable/unfixable split rather than claiming zero.

### Fixed

- The `install-grype` composite action still pinned Grype **v0.112.0** after the
  Dockerfile moved to v0.116.1, so every CVE-gating workflow was scanning with a
  four-releases-old scanner while the image shipped a current one. SUP-08 had
  flagged the duplication but nothing enforced it; a test now asserts the two
  agree.
- **Every pinned GitHub Action bumped off the deprecated `node20` runtime.**
  All nine were annotated as deprecated by the runner. Each was verified before
  bumping — the target SHA resolved from its release tag, its `runs.using`
  confirmed as `node24` (or `composite`), and every input and output we consume
  checked against the new definition:

  | Action | From | To |
  |---|---|---|
  | `actions/checkout` | v4.4.0 | v7.0.1 |
  | `actions/github-script` | v7.1.0 | v9.0.0 |
  | `actions/attest` | v2.4.0 | v4.2.2 |
  | `actions/attest-build-provenance` | v2.x | v4.1.1 |
  | `docker/build-push-action` | v6.19.2 | v7.3.0 |
  | `docker/login-action` | v3.7.0 | v4.6.0 |
  | `docker/metadata-action` | v5.10.0 | v6.2.0 |
  | `docker/setup-buildx-action` | v3.12.0 | v4.2.0 |
  | `sigstore/cosign-installer` | v3.x | v4.1.2 |

  All are major bumps. The `docker/*` majors are runtime-only. `github-script`
  v9 drops `require('@actions/github')` — our only `require` is `require('fs')`,
  a Node builtin, so it is unaffected. `checkout` v7 blocks fork checkouts on
  `pull_request_target` and `workflow_run`; no workflow here uses either
  trigger, and the change is hardening regardless.

  These actions require Actions Runner **v2.327.1+**. GitHub-hosted runners are
  fine. This affects building this repo only — consumers invoke the scanner as
  a container action, which has no Node runtime.
- Action pins now carry a `# vX.Y.Z` comment, and a test requires it. The SHA is
  the security property but is unreadable; nothing in the file said whether a
  pin was current or three majors behind, which is exactly how all nine aged
  onto a deprecated runtime unnoticed. A second test asserts an action is not
  pinned at two different SHAs in different workflows.

## [3.1.0] — 2026-07-31

Container CVE reduction. **Critical/high drops from 153 to 8** and total matches
from 455 to 21, with no change to scan behaviour: identical IaC output on the
same fixture (157 queries, 338 findings).

| | 3.0.2 | 3.1.0 |
|---|---|---|
| total matches | 455 | **21** |
| critical | 36 | **2** |
| high | 117 | **6** |
| OS-level critical/high | 105 | **0** |
| image size | 511 MB | 418 MB |

### Changed

- **Runtime base is now Chainguard Wolfi** instead of `debian:bookworm-slim`.
  Not a preference — of the 105 critical/high CVEs Debian contributed, *zero*
  were fixable: 70 were marked "won't fix" and 35 had no fix at all, so no
  amount of patching could have closed them. 44 came from `perl`, present only
  because Debian's `git` depends on it; Wolfi's git does not. 24 more came from
  Python 3.11; Wolfi ships 3.13. The OS contribution is now zero.
- **KICS is built from source** at a pinned commit rather than downloaded.
  Checkmarx published no release binary after v2.1.20 — v2.1.21 is a tag with
  no assets — so the previous approach meant freezing on an ageing artifact.
  Building with Go 1.26.5 took KICS from 23 critical/high to 2. It is also the
  stronger supply-chain position: TeamPCP compromised Checkmarx's *release
  pipeline*, which is now entirely outside our trust path. The same commit
  supplies the binary and the Rego query rules, so they can no longer drift.
- **Grype v0.112.0 → v0.116.1**, four minor releases forward. It had been
  reporting 22 critical/high against itself; now 3.
- Python in the image moves 3.11 → 3.13, and git 2.39 → 2.55.

### Known remaining

All 8 remaining critical/high live inside third-party scanner binaries, not in
anything this project controls at the OS level:

- 2 critical `containerd` advisories inside KICS with **no upstream fix**.
- 6 high in Grype, Syft, and betterleaks — `docker/docker`, `golang.org/x/text`,
  and Go stdlib from the toolchain Anchore built their releases with. These
  clear when those projects publish rebuilt binaries.

### Note for operators

Chainguard's free tier publishes only `:latest` and garbage-collects older
digests, so the pinned Wolfi digest can eventually become unpullable. Re-pin on
a regular cadence — a rolling base wants that anyway — or mirror the digest into
your own registry if reproducible rebuilds of old tags are a hard requirement.

## [3.0.2] — 2026-07-31

Fixes secrets scanning, which was broken for every user in 3.0.0 and 3.0.1.

### Fixed

- **The secrets scan failed on every run.** betterleaks exited 1 without
  writing a report, and the scan aborted with "could not read betterleaks
  output". The generated allowlist config put its path regexes in TOML *basic*
  strings, so `re.escape('.git')` produced `"^\.git/"` — and TOML only
  recognises a fixed set of backslash escapes, making `\.` invalid:

      FTL unable to load config, err: toml: invalid escaped character U+002E

  Regexes now go into TOML *literal* strings, which process no escapes. Because
  `.git` is always appended to the exclude list, this affected everyone, not
  only those setting `ZAGWARE_EXCLUDE_PATHS`. It stayed hidden until 3.0.1
  because the SCA failure aborted the scan first.
- The generated config is now parsed before it is handed to betterleaks. If it
  is ever malformed again the scan **degrades to an unscoped scan** — which
  over-reports rather than silently skipping paths — instead of failing
  outright. This matters because betterleaks' console output is deliberately
  withheld (SEC-08), so a config error is otherwise indistinguishable from a
  crash.
- `ZAGWARE_EXCLUDE_PATHS` values containing dots, spaces, backslashes, or
  apostrophes can no longer produce an invalid config.

### Added

- Local working-tree scan mode for the VS Code extension —
  `ZAGWARE_LOCAL_SCAN`, `ZAGWARE_LOCAL_PATH`, `ZAGWARE_LOCAL_OUTPUT`, now
  documented under **Configuration → Local scanning**. Off by default; the CI
  pull-request flow is unchanged.

## [3.0.1] — 2026-07-31

Fixes SCA being broken on GitHub Actions in 3.0.0. Anyone on 3.0.0 or `latest`
should upgrade; there is no workaround short of disabling SCA.

### Fixed

- **SCA failed on every GitHub Actions run.** Grype exited 1 within a second of
  starting, and the scan aborted with "Grype failed — this is NOT 'no
  findings'". Syft and Grype resolve their cache from `$XDG_CACHE_HOME`,
  falling back to `$HOME/.cache`; the Actions docker-action runtime overrides
  `HOME` to a runner-owned `/github/home` that the non-root user introduced in
  3.0.0 (SUP-06) cannot write, so Grype could not create its vulnerability
  database. The cache is now pinned to a path that is always writable,
  independent of whatever `HOME` a caller injects. Root cause was reproduced
  against the published 3.0.0 image and the fix verified under the same
  conditions.
- **The failure was undiagnosable.** `--quiet` suppressed 100% of Grype's
  output — the DB error wrote literally zero bytes to stdout and stderr — so
  the log read `Grype exited 1: ` with nothing after the colon. Both Syft and
  Grype now run unsilenced (output is captured, not printed; measured cost on a
  clean run is ~105 bytes), and the reported detail is the *tail* of that
  output, where the fatal error is, rather than the head, which held only a
  schema warning.
- **`Unexpected KICS exit code 60` on any repository with a CRITICAL finding.**
  KICS returns the exit code of the highest severity it found. The accepted set
  was `(0, 30, 40, 50)` under a stale comment predating CRITICAL getting its
  own code. Verified against the bundled binary — INFO=20, LOW=30, MEDIUM=40,
  HIGH=50, CRITICAL=60 — and widened accordingly. Genuine engine errors (1,
  126, 130) still warn.

## [3.0.0] — 2026-07-30

Remediation of a full security and quality audit: **90 findings** (2 critical, 18 high,
38 medium, 29 low, 3 nits) across the scanner, its documentation, and its supply chain.
Every finding is closed.

The major bump is for the three behavioural contracts below — the audit itself was
remediation, not new features.

### Breaking

- **Exit code `2` now means "the scanner crashed".** Previously any failure exited `1`,
  making a broken tool indistinguishable from a pull request that legitimately has
  findings. `0` = clean, `1` = a policy gate fired or a scan failed, `2` = the scanner
  itself crashed. Pipelines that branch on the exact value `1` need updating; pipelines
  that treat any non-zero as failure are unaffected.
- **Scan artifacts are written as compact JSON.** The findings dumps scale with the
  dependency and finding count of an attacker-supplied tree, and `indent=2` roughly
  doubled the serialised copy held in memory. Every documented `jq` path still works;
  anything parsing these files line-by-line does not. `summary.json` keeps its
  indentation.
- **SCA and Secrets sections distinguish three outcomes, not two.** "Scanning is
  disabled", "no manifests were found", and "scanned and clean" previously collapsed
  into one silent empty section, so a Go monorepo using only `go.mod` produced the same
  output as a repo with scanning switched off.

### Security

- Redirects no longer carry the `Authorization` header across hosts. `urllib` follows
  30x by default and CPython's redirect handler strips only content headers, so a
  redirect to an attacker-controlled host received the bearer token intact.
- The platform URL is validated as `https://` before any upload; an `http://` URL would
  have put the token on the wire in cleartext.
- CI credentials are kept out of `git` argv and `.git/config`, supplied out-of-band via
  `http.extraHeader` instead.
- Every value interpolated into the PR comment is escaped — file names, resource names,
  and issue types all originate in the pull request under review.
- `betterleaks` runs with `--redact` and its stdout is no longer logged; the console
  output retained matched secret material and was written into the job log.
- `suppressed_by` supplied by the scanned repository is no longer presented as verified
  attribution. Repo-supplied values are surfaced as unverified claims.
- Telemetry sends `$geoip_disable`; the "not reversible" claim about hashed repo names
  is corrected to "pseudonymous" in the README.
- `git` is bounded by a 300 s timeout — it was the only subprocess wrapper without one.
- `--` terminates option parsing on every clone, fetch, and checkout, so a ref taken
  from the environment can never be read as a flag.
- `ZAGWARE_OUTPUT_DIR` and `ZAGWARE_SUPPRESSIONS_FILE` reject absolute and traversing
  values, falling back to their documented defaults.
- Suppression counts are bucketed before transmission like every other telemetry count.
- Grype writes its report via `--file` rather than being captured through stdout.

### Fixed

- A KICS timeout or a missing KICS binary is now an explicit scanner failure rather than
  being reported as "no findings". Configurable via `ZAGWARE_SCAN_TIMEOUT` (default
  `600` seconds, per branch).
- Fork pull requests are scanned by preferring the merge ref (`refs/pull/N/head`) and
  checking out `FETCH_HEAD`.
- Non-pull-request pipelines behave consistently across GitHub, GitLab, Bitbucket, and
  Azure DevOps. Azure previously substituted the literal `main` for a missing target
  branch, producing a permanently green build that diffed `main` against itself.
- `ZAGWARE_EXCLUDE_PATHS` is honoured by the SCA and Secrets scanners, not just KICS,
  and `.git` is always excluded regardless of its value.
- Real commit SHAs are sent to the platform instead of placeholder values.
- Already-suppressed findings are no longer reported as unrecognised suppression ids;
  ambiguous prefixes are reported as ambiguous.
- A failed suppression push is surfaced in the PR comment. Previously the only trace was
  one `ERROR` line in the job log, and the suppression silently never applied.
- The suppressions YAML parser reports how many entries it parsed against how many it
  saw, so a half-parsed file is visible rather than silently ignored.
- A CVSS base score of `0.0` survives both parsing and rendering; the falsy check
  discarded it and rendered an unscored em-dash.
- Malformed API responses raise an error naming the platform and the received type.
  These were bare `assert isinstance(...)` calls, which vanish under `python -O`.
- The SCA manifest gate covers the ecosystems Syft already supports — Go without a
  vendored `go.sum`, Kotlin-DSL Gradle, Elixir, Dart, and .NET project files. Those
  repositories previously got zero dependency scanning with zero indication.
- PR comment truncation cuts on a line boundary and closes any open `<details>`. A blind
  character slice landed mid-table-row and left the truncation note inside a collapsed
  section where no reviewer would see it.
- Both exit-gate reasons are logged. A public repository with a new secret *and* new IaC
  findings reported only the secret, so fixing it produced a second surprise red build.
- A partial KICS report degrades the affected row instead of failing the run with a
  `KeyError`.
- `.zagware/suppressions.yaml` no longer directs users to `summary.json` for
  `similarity_id`, which never contained one.

### Added

- `iac-new.json` scan artifact — net-new IaC findings. Its SCA and Secrets counterparts
  already existed, leaving the one category whose ids the comment tells users to look up
  without a net-new file. Artifact count is now eleven.
- `ZAGWARE_SCAN_TIMEOUT` — per-branch KICS wall-clock budget.
- Documentation for six environment variables the scanner read but never documented:
  `ZAGWARE_ASSUME_PRIVATE`, `ZAGWARE_SUPPRESS_ALLOWED_ASSOCIATIONS`, and the
  `ZAGWARE_SCANNER_BIN` / `ZAGWARE_SYFT_BIN` / `ZAGWARE_GRYPE_BIN` /
  `ZAGWARE_SECRETS_BIN` overrides.
- This changelog.

### Changed

- Boolean environment variables share one parser, so `off`, `false`, `0`, `no`, and
  `disabled` are accepted consistently. Five mutually incompatible conventions coexisted.
- Syft upgraded from v1.19.0 to v1.50.0.
- Supply chain hardening: pinned action digests, KICS rules provenance, and audit
  rollback in the publish workflow.
- Test suite grown from 287 to 546 tests.

### Removed

- The documented Trivy scan in the promotion gate, which did not exist anywhere in the
  repository.
- The git-blame suppression attribution fallback, which credited whoever last touched a
  line rather than whoever added the suppression.

## [2.8.2] — 2026-07-29

### Fixed
- Secrets `similarity_id` was the raw file path rather than a hash.

## [2.8.1] — 2026-07-29

### Fixed
- PR comment formatting — icon/title alignment, footer placement, and Setext heading
  corruption.

## [2.8.0] — 2026-07-28

### Added
- Secrets detection via betterleaks — the third scan engine, alongside IaC and SCA.

## [2.7.0] — 2026-07-28

### Added
- Platform-side audit trail for suppressions: who, when, and why.

## [2.6.1] — 2026-07-28

### Fixed
- `/zagware suppress` hints are shown only on GitHub, the only platform that supports
  interactive suppression.

## [2.6.0] — 2026-07-28

### Added
- PostHog usage telemetry — opt-out, with a hashed identity by default.

### Fixed
- Azure DevOps setup documentation, including the missing `BUILD_REPOSITORY_NAME`.

## [2.5.1] — 2026-07-28

### Fixed
- GitHub Actions reserves `GITHUB_*` environment names and silently ignores
  workflow-declared overrides for them; `ZAGWARE_BASE_REF` / `ZAGWARE_HEAD_REF` are used
  instead.

## [2.5.0] — 2026-07-28

### Fixed
- Interactive suppression now works end to end.
- Azure DevOps falls back to a new PR thread when the existing comment cannot be PATCHed
  (403 — owned by a different identity).

## [2.4.0] — 2026-07-28

### Added
- Interactive suppression, CI workflow, and GitHub Releases.

### Fixed
- Restored the emoji variable dropped from the SCA section during the collapsible edit.
- Added a missing `import re`, which caused a `NameError`.
- `contents: write` permission for GitHub Releases.

## [2.3.0] — 2026-07-28

### Changed
- Container hardening, release workflows, and README accuracy.

## [2.2.0] — 2026-07-28

### Fixed
- KICS exit codes 30/40 are severity levels, not crashes, and are accepted as such.
- Security, crash, suppression, and severity-filter fixes.

## [2.1.0] — 2026-07-27

### Added
- Scan artifacts and per-phase timings.

## [2.0.9] — 2026-07-27

### Fixed
- `render_sca_section` crashed on a `None` `base_sca` / `head_sca` (`TypeError: len(None)`).

## [2.0.8] — 2026-07-27

### Fixed
- Corrected Syft and Grype binary paths to `/usr/bin` — dpkg installs there, not
  `/usr/local/bin`.

## [2.0.7] — 2026-07-27

### Fixed
- Syft stderr is logged on failure, and output is accepted on a non-zero exit code.

## [2.0.6] — 2026-07-27

### Fixed
- SCA results are uploaded even at zero findings; the upload was gated on a truthy list.

## [2.0.5] — 2026-07-26

### Added
- Hardened supply chain: GHCR publication, checksums, cosign signing, SBOM, and SLSA
  provenance.

## [2.0.4] — 2026-07-24

### Fixed
- Stripped the `v` prefix in the `.deb` filename
  (`SYFT_VERSION=v1.19.0` → `syft_1.19.0*.deb`).

## [2.0.3] — 2026-07-24

### Fixed
- Syft and Grype install via `.deb` to avoid pre-signed redirect chain failures.

## [2.0.2] — 2026-07-24

### Fixed
- Direct binary downloads for Syft and Grype; added `tar` to dependencies.

## [2.0.1] — 2026-07-24

### Added
- `repo_base_url` included in platform uploads.

### Changed
- README rewritten for the unified scanner (IaC + SCA).

## [2.0.0] — 2026-07-24

### Added
- Grype SCA scanning alongside KICS IaC scanning, unified into a single scanner.

[3.2.0]: https://github.com/zagware/zagware-scanner/releases/tag/v3.2.0
[3.1.0]: https://github.com/zagware/zagware-scanner/releases/tag/v3.1.0
[3.0.2]: https://github.com/zagware/zagware-scanner/releases/tag/v3.0.2
[3.0.1]: https://github.com/zagware/zagware-scanner/releases/tag/v3.0.1
[3.0.0]: https://github.com/zagware/zagware-scanner/releases/tag/v3.0.0
[2.8.2]: https://github.com/zagware/zagware-scanner/releases/tag/v2.8.2
[2.8.1]: https://github.com/zagware/zagware-scanner/releases/tag/v2.8.1
[2.8.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.8.0
[2.7.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.7.0
[2.6.1]: https://github.com/zagware/zagware-scanner/releases/tag/v2.6.1
[2.6.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.6.0
[2.5.1]: https://github.com/zagware/zagware-scanner/releases/tag/v2.5.1
[2.5.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.5.0
[2.4.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.4.0
[2.3.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.3.0
[2.2.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.2.0
[2.1.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.1.0
[2.0.9]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.9
[2.0.8]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.8
[2.0.7]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.7
[2.0.6]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.6
[2.0.5]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.5
[2.0.4]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.4
[2.0.3]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.3
[2.0.2]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.2
[2.0.1]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.1
[2.0.0]: https://github.com/zagware/zagware-scanner/releases/tag/v2.0.0
