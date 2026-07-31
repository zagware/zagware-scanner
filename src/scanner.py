#!/usr/bin/env python3
"""
Zagware IaC Scanner
-------------------
Detects infrastructure-as-code security findings introduced by a pull/merge
request and posts a diff comment directly on the PR.

Supported CI platforms: GitHub Actions, GitLab CI, Bitbucket Pipelines,
Azure DevOps.

Environment variables
---------------------
Required by each platform — see platform classes below.

Optional (all platforms):
  ZAGWARE_EXCLUDE_PATHS   Comma-separated paths/globs to skip (default: .git)
  ZAGWARE_FAIL_ON_NEW     Exit 1 if new findings are found (default: false)
"""

from __future__ import annotations

import base64
import re as _re
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
import hashlib


# ── Internal constants ─────────────────────────────────────────────────────────
__version__ = "2.10.0"

# Boolean-shaped env vars previously used five different, mutually incompatible
# parsing conventions (.lower()=="true", .lower()!="false", bare truthiness, and
# two different "off" vocabularies): ZAGWARE_FAIL_ON_NEW=1 silently left the
# merge gate off, ZAGWARE_SECRETS_FAIL_ON_PUBLIC=0 could not turn that gate off
# at all, and ZAGWARE_DEBUG=false enabled debug logging. One helper, one
# documented vocabulary, used for every boolean-shaped ZAGWARE_* var. The false
# side matches ZAGWARE_TELEMETRY's existing (and now-canonical) vocabulary
# rather than narrowing it, so ZAGWARE_TELEMETRY=disabled keeps working. See
# QUAL-19/DOC-25.
_ENV_BOOL_TRUE  = {"1", "true", "yes", "on"}
_ENV_BOOL_FALSE = {"0", "false", "no", "off", "disabled"}


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean-shaped env var against the shared vocabulary above.
    Unset or empty -> *default*. Any other non-empty value is not silently
    guessed at: it is logged (via the module-level `logging.warning`, since
    this runs for some vars before `log` is configured below) and *default*
    is used rather than misinterpreted."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    val = raw.strip().lower()
    if val in _ENV_BOOL_TRUE:
        return True
    if val in _ENV_BOOL_FALSE:
        return False
    logging.warning(
        "%s=%r is not a recognised boolean value (true: %s / false: %s) "
        "-- using default %s",
        name, raw, sorted(_ENV_BOOL_TRUE), sorted(_ENV_BOOL_FALSE), default,
    )
    return default


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    """Parse an integer-shaped env var, same fail-safe contract as _env_bool:
    unset/empty -> *default*; anything unparseable or below *minimum* is
    logged and *default* is used rather than silently coerced. Never raises --
    a typo in a timeout must not crash the scan before it starts."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = int(raw.strip())
    except ValueError:
        logging.warning("%s=%r is not an integer -- using default %d", name, raw, default)
        return default
    if val < minimum:
        logging.warning("%s=%d is below the minimum of %d -- using default %d",
                        name, val, minimum, default)
        return default
    return val


_SCANNER_BIN   = os.environ.get("_ZAGWARE_SCANNER_BIN", "/usr/local/bin/kics")
_QUERIES_PATH  = os.environ.get("ZAGWARE_QUERIES_PATH",  "/opt/iac-rules/assets/queries")
_COMMENT_MARKER    = "<!-- zagware-scanner -->"              # GitHub / Gitlab (hidden HTML comment)
_BB_COMMENT_MARKER = "[zagware-scanner]: https://github.com/zagware/zagware-scanner"  # Bitbucket (invisible link ref)
_MAX_COMMENT   = 60_000
_FAIL_ON_NEW   = _env_bool("ZAGWARE_FAIL_ON_NEW", False)
_EXCLUDE_PATHS = os.environ.get("ZAGWARE_EXCLUDE_PATHS", ".git")
_MIN_SEVERITY  = os.environ.get("ZAGWARE_MIN_SEVERITY", "").upper().strip()
_OUTPUT_DIR    = os.environ.get("ZAGWARE_OUTPUT_DIR", "zagware-scan-results")
# Wall-clock budget for a single KICS invocation (per branch, so a full run
# allows up to 2x this). Configurable because the failure it guards is
# size-driven: a large monorepo can legitimately exceed the default, and
# before QUAL-04 the only symptom was an unhandled TimeoutExpired traceback
# with no hint that a longer budget was the fix.
_SCAN_TIMEOUT  = _env_int("ZAGWARE_SCAN_TIMEOUT", 600)

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TRACE"]
_SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW":      "🔵", "INFO": "⚪", "TRACE":   "⚫",
}

# ── SCA (Grype) constants ──────────────────────────────────────────────────────
_SCA_ENABLED      = _env_bool("ZAGWARE_SCA_ENABLED", True)
_GRYPE_BIN        = os.environ.get("_ZAGWARE_GRYPE_BIN",  "/usr/bin/grype")
_SYFT_BIN         = os.environ.get("_ZAGWARE_SYFT_BIN",   "/usr/bin/syft")
_SCA_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
_SCA_SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵",
    "NEGLIGIBLE": "⚪", "UNKNOWN": "❓",
}
# Threshold rank map for ZAGWARE_MIN_SEVERITY against SCA findings — kept separate
# from the display order above. _MIN_SEVERITY is validated at startup against the
# 6-tier IaC _SEVERITY_ORDER (which has INFO/TRACE, absent from Grype's own severity
# set), so this map covers all six IaC tiers, not just the five/six SCA display
# buckets — see QUAL-03: INFO/TRACE previously fell through a rank.get(..., 0)
# default and silently collapsed the threshold to CRITICAL-only. UNKNOWN (a real
# Grype severity value Grype itself emits, not just our own missing-key default)
# ranks below CRITICAL so it is NEVER excluded by any threshold — hiding a finding
# Grype could not classify is worse than over-showing it. See QUAL-07.
_SCA_MIN_RANK = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "TRACE": 4,
    "UNKNOWN": -1,
}
_SCA_MANIFESTS = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.sum", "Cargo.lock",
    "requirements.txt", "Pipfile.lock", "poetry.lock",
    "Gemfile.lock", "pom.xml", "build.gradle",
    "composer.lock", "packages.lock.json",
]

# ── Secrets (betterleaks) constants ────────────────────────────────────────────
_SECRETS_ENABLED = _env_bool("ZAGWARE_SECRETS_ENABLED", True)
_SECRETS_BIN     = os.environ.get("_ZAGWARE_SECRETS_BIN", "/usr/local/bin/betterleaks")
# Fail the build if a NEW secret lands in a PUBLIC repo, regardless of ZAGWARE_FAIL_ON_NEW.
# Betterleaks has no severity taxonomy, so repo visibility is the priority signal instead —
# a leaked credential in a public repo is immediately exposed to the world.
_SECRETS_FAIL_ON_PUBLIC = _env_bool("ZAGWARE_SECRETS_FAIL_ON_PUBLIC", True)
# When repo_visibility() cannot be determined (transient API error, missing
# permission, GitHub Enterprise quirk), ZAGWARE_SECRETS_FAIL_ON_PUBLIC treats
# "unknown" the same as "public" (fail closed) by default — see QUAL-02. Set
# this to explicitly opt out, e.g. for an air-gapped install where visibility
# can never be resolved and the operator has independently confirmed the repo
# is private.
_ASSUME_PRIVATE = _env_bool("ZAGWARE_ASSUME_PRIVATE", False)

def _severities_below() -> list[str]:
    """Return severities to pass to --exclude-severities based on ZAGWARE_MIN_SEVERITY.

    ZAGWARE_MIN_SEVERITY=HIGH  →  exclude MEDIUM,LOW,INFO,TRACE
    ZAGWARE_MIN_SEVERITY=MEDIUM →  exclude LOW,INFO,TRACE
    Empty / unset              →  no exclusion (scan everything)
    """
    if not _MIN_SEVERITY:
        return []
    if _MIN_SEVERITY not in _SEVERITY_ORDER:
        # Validated at startup; warn once here in case of late env mutation
        return []
    idx = _SEVERITY_ORDER.index(_MIN_SEVERITY)
    return _SEVERITY_ORDER[idx + 1:]   # everything with a lower severity rank

# ── Logging ────────────────────────────────────────────────────────────────────

_DEBUG = _env_bool("ZAGWARE_DEBUG", False)

logging.basicConfig(
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.DEBUG if _DEBUG else logging.INFO,
)
log = logging.getLogger("zagware")

# ── Telemetry (opt-out, non-blocking, fail-silent) ─────────────────────────────
#
# What is sent: CI platform name, scanner version, whether the run is a PR scan,
# whether IaC/SCA scanning ran, scan duration, a bucketed (not exact) new-finding
# count per scan type, whether suppressions were used, and a SHA-256 hash of the
# org/repo identity (not the plaintext name, unless explicitly opted in — see
# ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME below).
#
# What is NEVER sent: file contents, file paths, finding descriptions, CVE IDs,
# package names, branch names, commit SHAs, tokens/secrets, or any CI/platform
# credential. PostHog's IP-based geolocation is disabled via $geoip_disable
# (see _send_telemetry_event for why $ip: 0 alone did NOT work). Note that
# repo_id/org_id are pseudonymous, not irreversible -- see _telemetry_identity.
#
# Disable entirely:            ZAGWARE_TELEMETRY=off (or false/0/no/disabled)
# Send org/repo name in clear: ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME=true
#
# The PostHog project API key below is a public, write-only project token —
# safe to embed (see PostHog docs: project API keys are not secret credentials).

_POSTHOG_API_KEY        = "phc_12P9WCCmeTB6969NvX6qt2nKZirAegKPtfozTzxH1yG"
_POSTHOG_CAPTURE_URL    = "https://eu.i.posthog.com/capture/"
_TELEMETRY_HTTP_TIMEOUT = 3  # seconds
_TELEMETRY_ENABLED = _env_bool("ZAGWARE_TELEMETRY", True)
_TELEMETRY_INCLUDE_REPO_NAME = _env_bool("ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME", False)

_telemetry_threads: list[threading.Thread] = []


def _telemetry_hash(s: str) -> str:
    """Short (16-char) SHA-256 prefix — enough entropy to avoid collisions across
    the scanner's realistic install base, without embedding a full 64-char hash.

    NOT irreversible. This is an unsalted digest over a small, public, fully
    enumerable namespace (platform + `owner/repo` strings), so anyone holding
    the values can recover the original name for a public repo with a
    precomputed table. It is a *pseudonym* — stable and linkable, not
    anonymous. Salting per-install would defeat the cross-run grouping this
    exists for, and a CI container has nowhere durable to persist a salt, so
    the honest fix is to describe it accurately rather than overclaim. See
    SEC-09.
    """
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _bucket_count(n: int) -> str:
    """Coarse-bucket a finding count so exact vulnerability inventories are never
    transmitted — only rough usage/engagement signal."""
    if n <= 0:
        return "0"
    if n <= 5:
        return "1-5"
    if n <= 20:
        return "6-20"
    return "21+"


def _telemetry_identity(platform_name: str, repo_full_name: str) -> tuple[str, dict]:
    """Return (distinct_id, base_properties) identifying the CI platform + repo.

    By default org/repo identity is sent as a stable pseudonymous hash rather
    than plaintext, so the same repo groups consistently in PostHog. For a
    public repo that hash is reversible by anyone who has it (see
    _telemetry_hash) — it reduces casual exposure, it is not anonymity. Set
    ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME=true to send the plaintext name
    instead, or ZAGWARE_TELEMETRY=off to send nothing at all.
    """
    repo_full_name = repo_full_name or ""
    org = repo_full_name.split("/", 1)[0] if "/" in repo_full_name else ""
    repo_hash = _telemetry_hash(f"{platform_name}:{repo_full_name}") if repo_full_name else "unknown"
    org_hash  = _telemetry_hash(org) if org else "unknown"
    props: dict = {
        "platform": platform_name,
        "repo_id":  repo_hash,
        "org_id":   org_hash,
    }
    if _TELEMETRY_INCLUDE_REPO_NAME and repo_full_name:
        props["repo_name"] = repo_full_name
        props["org_name"]  = org
    return repo_hash, props


def _send_telemetry_event(name: str, props: dict) -> None:
    if not _TELEMETRY_ENABLED:
        return
    try:
        props = dict(props)
        distinct_id = props.pop("_distinct_id", "anonymous")
        props["tool"]            = "zagware-scanner"
        props["scanner_version"] = __version__
        # PostHog's GeoIP plugin reads `event.properties?.$ip || event.ip` and
        # only skips when `event.properties?.$geoip_disable` is truthy. The
        # previous `$ip = 0` is FALSY in JS, so it was discarded and the plugin
        # fell back to event.ip -- the runner's public IP -- and geolocated
        # normally, despite the docs claiming otherwise. $geoip_disable is the
        # documented switch; $ip is set to None so no address is sent at all.
        # See SEC-09.
        props["$geoip_disable"] = True
        props["$ip"] = None
        payload = {
            "api_key":     _POSTHOG_API_KEY,
            "event":       name,
            "distinct_id": distinct_id,
            "properties":  props,
        }
        body = json.dumps(payload).encode("utf-8")
    except Exception:
        return  # telemetry construction must never break the scan

    def _post() -> None:
        try:
            req = urllib.request.Request(
                _POSTHOG_CAPTURE_URL, data=body,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            # Plain urlopen, deliberately: this request carries no Authorization
            # header (the PostHog project key is a public write-only token), so
            # the cross-host-redirect concern in SEC-05 does not apply, and it
            # already has its own tighter timeout. Keeping it off the shared
            # opener also keeps this daemon thread independent of it.
            urllib.request.urlopen(req, timeout=_TELEMETRY_HTTP_TIMEOUT).close()
        except Exception:
            pass  # network/DNS/timeout — never surfaced, never retried

    t = threading.Thread(target=_post, daemon=True)
    t.start()
    _telemetry_threads.append(t)


def telemetry_flush(timeout: float = 2.0) -> None:
    """Wait briefly for in-flight telemetry to send before process exit.
    Bounded — never blocks the pipeline waiting on a slow/unreachable endpoint."""
    deadline = time.monotonic() + timeout
    for t in _telemetry_threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        t.join(timeout=remaining)


def track_scan_started(
    platform_name: str, repo: str, is_pr: bool, sca_enabled: bool,
    has_platform_integration: bool, min_severity: str, fail_on_new: bool,
    secrets_enabled: bool = False,
) -> None:
    distinct_id, props = _telemetry_identity(platform_name, repo)
    props.update({
        "is_pr":                    is_pr,
        "sca_enabled":               sca_enabled,
        "secrets_enabled":           secrets_enabled,
        "has_platform_integration":  has_platform_integration,
        "min_severity_filter":       min_severity or "none",
        "fail_on_new":               fail_on_new,
        "_distinct_id":              distinct_id,
    })
    _send_telemetry_event("scan_started", props)


def track_scan_completed(
    platform_name: str, repo: str, duration_seconds: float,
    iac_new: int, sca_new: int | None, iac_scanned: bool, sca_scanned: bool,
    suppressions_used: bool, exit_code: int,
    secrets_new: int | None = None, secrets_scanned: bool = False,
) -> None:
    distinct_id, props = _telemetry_identity(platform_name, repo)
    props.update({
        "duration_seconds":           round(duration_seconds, 1),
        "iac_new_findings_bucket":    _bucket_count(iac_new),
        "sca_new_findings_bucket":    _bucket_count(sca_new) if sca_scanned and sca_new is not None else "not_scanned",
        "secrets_new_findings_bucket": _bucket_count(secrets_new) if secrets_scanned and secrets_new is not None else "not_scanned",
        "iac_scanned":                iac_scanned,
        "sca_scanned":                sca_scanned,
        "secrets_scanned":            secrets_scanned,
        "suppressions_used":          suppressions_used,
        "exit_code":                  exit_code,
        "_distinct_id":               distinct_id,
    })
    _send_telemetry_event("scan_completed", props)


def track_scan_failed(platform_name: str, repo: str, stage: str) -> None:
    """stage: coarse failure location only (e.g. 'clone', 'iac_scan') — never the
    raw exception message, which could contain file paths or credential fragments."""
    distinct_id, props = _telemetry_identity(platform_name, repo)
    props.update({"failure_stage": stage, "_distinct_id": distinct_id})
    _send_telemetry_event("scan_failed", props)


def track_suppression_applied(platform_name: str, repo: str, count: int) -> None:
    distinct_id, props = _telemetry_identity(platform_name, repo)
    props.update({"count": count, "_distinct_id": distinct_id})
    _send_telemetry_event("suppression_applied", props)


# ── HTTP helper (stdlib only, no pip deps) ─────────────────────────────────────

_HTTP_TIMEOUT = 30  # seconds — every authenticated request below is bounded


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse any 30x that changes host.

    urllib follows redirects by default, and CPython's
    HTTPRedirectHandler.redirect_request strips only *content* headers —
    Authorization survives. A POST to https://a.example carrying
    `Authorization: Bearer <token>` redirected to https://evil.example arrives
    there with the token intact. That reaches every path here: the platform
    uploads (bearer `gtp_…`), and every _http() call, where CI_SERVER_URL and
    SYSTEM_TEAMFOUNDATIONCOLLECTIONURI are already operator-supplied hosts
    carrying GITHUB_TOKEN / GITLAB_TOKEN / SYSTEM_ACCESSTOKEN.

    Returning None makes urllib surface the 30x as an HTTPError instead of
    following it — fail closed, and loudly. See SEC-05.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old_host = urllib.parse.urlsplit(req.full_url).netloc
        new_host = urllib.parse.urlsplit(newurl).netloc
        if old_host != new_host:
            log.error(
                "Refusing cross-host redirect %s → %s (HTTP %s): credentials would "
                "follow to the new host", old_host, new_host, code,
            )
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_NoCrossHostRedirect())


def _urlopen(req, timeout: int = _HTTP_TIMEOUT):
    """Single chokepoint for every credential-bearing request: cross-host
    redirects blocked, and always bounded by a timeout. See SEC-05."""
    return _opener.open(req, timeout=timeout)


def _validate_platform_url(url: str) -> str:
    """Return *url* if a bearer token may safely be sent to it, else "".

    ZAGWARE_PLATFORM_URL was previously consumed with no scheme check at all,
    so `http://…` was accepted and the `gtp_…` token plus full scan results
    went out in cleartext. https is required; plain http is tolerated only for
    loopback, where there is no network to intercept. See SEC-05.
    """
    if not url:
        return ""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "https":
        return url
    if parts.scheme == "http" and host in ("localhost", "127.0.0.1", "::1"):
        log.warning("ZAGWARE_PLATFORM_URL uses http:// on a loopback host — "
                    "acceptable for local development only")
        return url
    log.error(
        "Refusing ZAGWARE_PLATFORM_URL=%r — platform uploads carry a bearer token and "
        "require https:// (http:// is allowed only for localhost). Platform upload is "
        "disabled for this run; the scan and PR comment are unaffected.", url,
    )
    return ""


def _http(method: str, url: str, data: dict | None = None, headers: dict | None = None) -> dict | list:
    body = json.dumps(data).encode() if data is not None else None
    req  = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        # _urlopen, not urllib.request.urlopen: this call carries the CI
        # platform token and previously had NO timeout at all, so one stalled
        # socket inside the comment-pagination loop hung the job until the CI
        # platform's global timeout. See SEC-05.
        with _urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        log.error("HTTP %s %s → %d: %s", method, url, exc.code, detail)
        raise


# ── Platform adapters ──────────────────────────────────────────────────────────

class Platform(ABC):
    """Abstract base — one concrete subclass per CI platform."""

    @abstractmethod
    def detected(self) -> bool:
        """Return True when running inside this platform."""

    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def clone_url(self) -> str:
        """Authenticated git clone URL (credentials embedded in URL)."""

    @abstractmethod
    def base_branch(self) -> str:
        """Branch name of the PR target (the branch being merged into)."""

    @abstractmethod
    def head_branch(self) -> str:
        """Branch name or SHA of the PR source."""

    @abstractmethod
    def base_label(self) -> str:
        """Human-readable name for the base branch, used in the comment."""

    @abstractmethod
    def head_label(self) -> str:
        """Human-readable name for the PR branch, used in the comment."""

    @abstractmethod
    def post_or_update_comment(self, body: str) -> None:
        """Create a new comment or update the existing one (identified by marker)."""

    def supports_html_details(self) -> bool:
        """Return True if the platform renders <details>/<summary> in PR comments.
        GitHub and GitLab support HTML details; Bitbucket does not."""
        return True

    def supports_interactive_suppression(self) -> bool:
        """Return True if the scanner can read back PR comments on this platform,
        making the `/zagware suppress <id> <reason>` comment command usable.
        Only GitHub implements read_pr_comments() today — GitLab, Bitbucket, and
        Azure DevOps fall back to the default (empty) read_pr_comments() below, so
        showing the interactive suppress hint there would be misleading (the
        command would silently do nothing)."""
        return False

    def repo_visibility(self) -> str:
        """Return 'public' | 'private' | 'internal' | 'unknown' — best-effort repo
        visibility. Used as the priority signal for secrets findings in place of a
        severity level (betterleaks has no severity taxonomy): a leaked credential
        in a public repo is immediately exposed to the world, so public repos are
        treated as materially higher urgency than private ones. Never raises —
        network/auth failures fall back to 'unknown' rather than breaking the scan."""
        return "unknown"

    def repo(self) -> str:
        """Full repository name (owner/repo or similar). Empty string if unavailable."""
        return ''

    def pr_number(self) -> int | None:
        """PR/MR number as an integer, or None if not a PR pipeline."""
        return None

    def read_pr_comments(self) -> list[dict]:
        """Return all PR/MR comments as {body, author, created_at} dicts.
        Default: empty (platform-specific override needed)."""
        return []

    def is_pr_pipeline(self) -> bool:
        """True when this run has a pull/merge-request context.

        The scanner diffs a PR against its base branch; without that context
        there is nothing to diff. Each platform previously failed differently
        on a push/branch/scheduled pipeline: GitHub produced
        `git clone --branch ""` (GITHUB_BASE_REF is defined-but-empty),
        GitLab and Bitbucket raised an unhandled KeyError before any try
        block, and Azure silently substituted the literal "main" — which on a
        repo whose default branch IS main produced a green build that diffed
        main against itself and reported "0 new findings" forever. One check,
        one message, checked BEFORE any clone_url()/base_branch() call.
        See QUAL-09.
        """
        return self.pr_number() is not None

    def base_sha(self) -> str:
        """Commit SHA of the base branch, or "" if unavailable.

        Uploaded to the platform so a scan can be correlated with a commit:
        dedup of re-runs, "which commit introduced this finding", and linkage
        between the IaC/SCA/Secrets records for one push. The payload field
        already existed and was always null. See QUAL-16."""
        return ""

    def head_sha(self) -> str:
        """Commit SHA of the PR head, or "" if unavailable. See QUAL-16."""
        return ""



class GitHub(Platform):
    """
    Required env vars:
      GITHUB_TOKEN    ${{ github.token }} or ${{ secrets.GITHUB_TOKEN }}
      PR_NUMBER       ${{ github.event.pull_request.number }}

    Auto-injected by the runner:
      GITHUB_ACTIONS, GITHUB_REPOSITORY, GITHUB_BASE_REF, GITHUB_HEAD_REF
    """

    def detected(self) -> bool:
        return os.environ.get("GITHUB_ACTIONS") == "true"

    def name(self) -> str:
        return "GitHub"

    @property
    def _token(self) -> str:
        return os.environ["GITHUB_TOKEN"]

    @property
    def _repo(self) -> str:
        return os.environ["GITHUB_REPOSITORY"]  # owner/repo

    def clone_url(self) -> str:
        return f"https://x-access-token:{self._token}@github.com/{self._repo}.git"

    def base_branch(self) -> str:
        # ZAGWARE_BASE_REF overrides for issue_comment-triggered runs: GitHub Actions
        # reserves GITHUB_* names and silently ignores any workflow-declared env:
        # override for them on docker:// actions, so a distinct name is required.
        return os.environ.get("ZAGWARE_BASE_REF") or os.environ["GITHUB_BASE_REF"]

    def head_branch(self) -> str:
        """Ref to check out for the PR head.

        Prefers `refs/pull/<n>/head`, which GitHub maintains inside the BASE
        repository for every PR including forks. GITHUB_HEAD_REF is the branch
        name in the *contributor's fork*, a ref that does not exist in the base
        repo, and clone_url() always points at the base repo — so every
        fork-originated PR previously failed with "Clone failed for PR
        branch/SHA" and no comment at all, on exactly the population (public
        repos taking outside contributions) that most needs the secrets gate.
        ZAGWARE_HEAD_REF still wins when set, for issue_comment-triggered
        runs. See QUAL-13.
        """
        override = os.environ.get("ZAGWARE_HEAD_REF")
        if override:
            return override
        pr = os.environ.get("PR_NUMBER", "").strip()
        if pr.isdigit():
            return f"refs/pull/{pr}/head"
        return os.environ.get("GITHUB_HEAD_REF") or os.environ["GITHUB_SHA"]

    def base_label(self) -> str:
        return os.environ.get("ZAGWARE_BASE_REF") or os.environ.get("GITHUB_BASE_REF", "base")

    def head_label(self) -> str:
        return os.environ.get("ZAGWARE_HEAD_REF") or os.environ.get("GITHUB_HEAD_REF", "PR branch")

    def repo(self) -> str:
        return os.environ.get("GITHUB_REPOSITORY", "")

    def pr_number(self) -> int | None:
        val = os.environ.get("PR_NUMBER", "").strip()
        return int(val) if val else None

    def base_sha(self) -> str:
        # On a pull_request event GITHUB_SHA is the ephemeral merge commit, not
        # the base tip, so it is not a base_sha. GitHub exposes no base-tip env
        # var; "" keeps the field honestly null rather than wrong. See QUAL-16.
        return ""

    def head_sha(self) -> str:
        return os.environ.get("GITHUB_SHA", "")

    def _headers(self) -> dict:
        return {
            "Authorization":        f"Bearer {self._token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def post_or_update_comment(self, body: str) -> None:
        owner, repo = self._repo.split("/", 1)
        pr  = os.environ["PR_NUMBER"]
        api = f"https://api.github.com/repos/{owner}/{repo}"

        # Paginate through existing comments to find ours.
        existing_id: int | None = None
        page = 1
        while not existing_id:
            comments = _http("GET", f"{api}/issues/{pr}/comments?per_page=100&page={page}",
                             headers=self._headers())
            assert isinstance(comments, list)
            for c in comments:
                if _COMMENT_MARKER in c.get("body", ""):
                    existing_id = c["id"]
                    break
            if len(comments) < 100:
                break
            page += 1

        if existing_id:
            _http("PATCH", f"{api}/issues/comments/{existing_id}",
                  {"body": body}, self._headers())
            log.info("Updated GitHub comment %d on PR #%s", existing_id, pr)
        else:
            _http("POST", f"{api}/issues/{pr}/comments",
                  {"body": body}, self._headers())
            log.info("Posted GitHub comment on PR #%s", pr)

    def read_pr_comments(self) -> list[dict]:
        """Return PR comments as {body, author, created_at, author_association} dicts.
        author/created_at attribute /zagware suppress commands for the suppression audit
        trail (see collect_suppression_records()); author_association gates which comments
        the scanner will treat as authorized suppress commands (see SEC-01,
        _filter_authorized_comments())."""
        owner, repo = self._repo.split("/", 1)
        pr  = os.environ.get("PR_NUMBER", "").strip()
        if not pr:
            return []
        api = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr}/comments"
        result: list[dict] = []
        page = 1
        while True:
            comments = _http("GET", f"{api}?per_page=100&page={page}", headers=self._headers())
            if not isinstance(comments, list) or not comments:
                break
            for c in comments:
                result.append({
                    "body":               c.get("body", ""),
                    "author":             (c.get("user") or {}).get("login") or "unknown",
                    "created_at":         c.get("created_at", ""),
                    "author_association": c.get("author_association", ""),
                })
            if len(comments) < 100:
                break
            page += 1
        return result

    def supports_interactive_suppression(self) -> bool:
        return True  # GitHub is the only platform with read_pr_comments() implemented

    def repo_visibility(self) -> str:
        try:
            owner, repo = self._repo.split("/", 1)
            data = _http("GET", f"https://api.github.com/repos/{owner}/{repo}", headers=self._headers())
            assert isinstance(data, dict)
            return "private" if data.get("private") else "public"
        except Exception as exc:
            log.warning("Could not determine repo visibility: %s", exc)
            return "unknown"


class GitLab(Platform):
    """
    GitLab CI/CD MR pipelines inject most variables automatically.

    Auto-injected by GitLab:
      CI_JOB_TOKEN, CI_PROJECT_PATH, CI_PROJECT_ID, CI_SERVER_URL,
      CI_MERGE_REQUEST_IID, CI_MERGE_REQUEST_TARGET_BRANCH_NAME,
      CI_MERGE_REQUEST_SOURCE_BRANCH_NAME

    Required CI/CD variable (add once in Settings → CI/CD → Variables):
      GITLAB_TOKEN   A project or group access token with 'api' scope.
                     CI_JOB_TOKEN cannot post MR notes (GitLab limitation);
                     a dedicated token is required for comment posting.
    """

    def detected(self) -> bool:
        return os.environ.get("GITLAB_CI") == "true"

    def name(self) -> str:
        return "GitLab"

    @property
    def _api_token(self) -> str:
        """Token used for GitLab REST API calls (comment posting).

        GITLAB_TOKEN (PAT / project access token) is required because
        CI_JOB_TOKEN does not have permission to write MR notes.
        """
        tok = os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN", "")
        if not tok:
            raise RuntimeError("Set GITLAB_TOKEN (project/group access token with api scope) as a CI/CD variable")
        return tok

    @property
    def _clone_token(self) -> str:
        """CI_JOB_TOKEN is sufficient for git clone operations."""
        return os.environ["CI_JOB_TOKEN"]

    @property
    def _server(self) -> str:
        return os.environ.get("CI_SERVER_URL", "https://gitlab.com")

    @property
    def _project_path(self) -> str:
        return os.environ["CI_PROJECT_PATH"]

    @property
    def _project_id(self) -> str:
        return os.environ["CI_PROJECT_ID"]

    def clone_url(self) -> str:
        host = self._server.split("://", 1)[-1]
        return f"https://gitlab-ci-token:{self._clone_token}@{host}/{self._project_path}.git"

    def base_branch(self) -> str:
        return os.environ["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]

    def head_branch(self) -> str:
        return (os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
                or os.environ["CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"])

    def base_label(self) -> str:
        return os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "base")

    def head_label(self) -> str:
        return os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "MR branch")

    def repo(self) -> str:
        return os.environ.get("CI_PROJECT_PATH", "")

    def repo_visibility(self) -> str:
        # GitLab CI injects this automatically — no API call needed.
        vis = os.environ.get("CI_PROJECT_VISIBILITY", "").strip().lower()
        return vis if vis in ("public", "private", "internal") else "unknown"

    def pr_number(self) -> int | None:
        val = os.environ.get("CI_MERGE_REQUEST_IID", "").strip()
        return int(val) if val else None

    def base_sha(self) -> str:
        return os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_SHA", "")

    def head_sha(self) -> str:
        return (os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA")
                or os.environ.get("CI_COMMIT_SHA", ""))

    def _headers(self) -> dict:
        # PRIVATE-TOKEN header works for both PATs and project/group access tokens.
        return {"PRIVATE-TOKEN": self._api_token}

    def post_or_update_comment(self, body: str) -> None:
        mr  = os.environ["CI_MERGE_REQUEST_IID"]
        api = f"{self._server}/api/v4/projects/{self._project_id}/merge_requests/{mr}/notes"

        # Paginate through existing notes to find ours — GitLab's /notes endpoint
        # returns system notes (label changes, pushes, approvals) intermixed with
        # user comments, newest-first, so an active MR can push the scanner's own
        # note past a single 100-item page. See QUAL-12.
        existing_id: int | None = None
        page = 1
        while not existing_id:
            notes = _http("GET", f"{api}?per_page=100&page={page}", headers=self._headers())
            assert isinstance(notes, list)
            for n in notes:
                if _COMMENT_MARKER in n.get("body", ""):
                    existing_id = n["id"]
                    break
            if len(notes) < 100:
                break
            page += 1

        if existing_id:
            _http("PUT", f"{api}/{existing_id}", {"body": body}, self._headers())
            log.info("Updated GitLab note %d on MR !%s", existing_id, mr)
        else:
            _http("POST", api, {"body": body}, self._headers())
            log.info("Posted GitLab note on MR !%s", mr)


class Bitbucket(Platform):
    """
    Bitbucket Pipelines injects most variables automatically.

    Auto-injected by Bitbucket:
      BITBUCKET_WORKSPACE, BITBUCKET_REPO_SLUG, BITBUCKET_PR_ID,
      BITBUCKET_PR_DESTINATION_BRANCH, BITBUCKET_BRANCH, BITBUCKET_COMMIT,
      BITBUCKET_TOKEN (OAuth Bearer — usable for git clone only)

    Required repo variables (Repository settings → Pipelines → Repository variables):
      BITBUCKET_API_TOKEN   Atlassian API token with Bitbucket repository + pull-request scopes.
                            The auto-injected BITBUCKET_TOKEN is OAuth and cannot post PR
                            comments; the Atlassian API token uses HTTP Basic auth (email:token).
      ATLASSIAN_EMAIL       The Atlassian account email paired with BITBUCKET_API_TOKEN.
    """

    def detected(self) -> bool:
        return bool(os.environ.get("BITBUCKET_BUILD_NUMBER"))

    def name(self) -> str:
        return "Bitbucket"

    def supports_html_details(self) -> bool:
        return False  # Bitbucket renders <details>/<summary> as literal text

    @property
    def _api_token(self) -> str:
        """Atlassian API token for REST API calls (Basic auth: email:token)."""
        return os.environ["BITBUCKET_API_TOKEN"]

    @property
    def _email(self) -> str:
        """Atlassian account email — the username component for Basic auth."""
        return os.environ["ATLASSIAN_EMAIL"]

    @property
    def _git_user(self) -> str:
        """Git HTTP username for Atlassian API token auth.

        Bitbucket's HTTP clone URL uses '{workspace}-admin' as the username
        for workspace-level Atlassian API token authentication.
        Can be overridden by setting BITBUCKET_GIT_USER.
        """
        return os.environ.get("BITBUCKET_GIT_USER", f"{self._workspace}-admin")

    @property
    def _workspace(self) -> str:
        return os.environ["BITBUCKET_WORKSPACE"]

    @property
    def _slug(self) -> str:
        return os.environ["BITBUCKET_REPO_SLUG"]

    def clone_url(self) -> str:
        # Atlassian API token git auth: {workspace}-admin:{token}
        return f"https://{self._git_user}:{self._api_token}@bitbucket.org/{self._workspace}/{self._slug}.git"

    def base_branch(self) -> str:
        return os.environ["BITBUCKET_PR_DESTINATION_BRANCH"]

    def head_branch(self) -> str:
        return os.environ.get("BITBUCKET_BRANCH") or os.environ["BITBUCKET_COMMIT"]

    def base_label(self) -> str:
        return os.environ.get("BITBUCKET_PR_DESTINATION_BRANCH", "base")

    def head_label(self) -> str:
        return os.environ.get("BITBUCKET_BRANCH", "PR branch")

    def repo(self) -> str:
        ws   = os.environ.get("BITBUCKET_WORKSPACE", "")
        slug = os.environ.get("BITBUCKET_REPO_SLUG", "")
        return f"{ws}/{slug}" if ws and slug else ""

    def repo_visibility(self) -> str:
        try:
            api = f"https://api.bitbucket.org/2.0/repositories/{self._workspace}/{self._slug}"
            data = _http("GET", api, headers=self._headers())
            assert isinstance(data, dict)
            return "private" if data.get("is_private") else "public"
        except Exception as exc:
            log.warning("Could not determine repo visibility: %s", exc)
            return "unknown"

    def pr_number(self) -> int | None:
        val = os.environ.get("BITBUCKET_PR_ID", "").strip()
        return int(val) if val else None

    def base_sha(self) -> str:
        # Bitbucket exposes no base-tip variable; "" keeps the field honestly
        # null rather than wrong. See QUAL-16.
        return ""

    def head_sha(self) -> str:
        return os.environ.get("BITBUCKET_COMMIT", "")

    def _headers(self) -> dict:
        # Atlassian API tokens require HTTP Basic auth: email:token
        creds = base64.b64encode(f"{self._email}:{self._api_token}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    def post_or_update_comment(self, body: str) -> None:
        pr  = os.environ["BITBUCKET_PR_ID"]
        api = (f"https://api.bitbucket.org/2.0/repositories"
               f"/{self._workspace}/{self._slug}/pullrequests/{pr}/comments")

        # Follow the response envelope's "next" URL rather than assuming a
        # single page — a PR with over 100 comments would otherwise never
        # find the scanner's own comment and duplicate it on every push. See
        # QUAL-12. The "## Zagware IaC Scanner" string fallback matcher this
        # loop used to also check for was dead: no rendered comment has ever
        # contained that heading text (see QUAL-05).
        existing: int | None = None
        url = f"{api}?pagelen=100"
        while url and not existing:
            data = _http("GET", url, headers=self._headers())
            assert isinstance(data, dict)
            for c in data.get("values", []):
                if _BB_COMMENT_MARKER in c.get("content", {}).get("raw", ""):
                    existing = c["id"]
                    break
            url = data.get("next") if not existing else None
        payload = {"content": {"raw": body}}

        if existing:
            _http("PUT", f"{api}/{existing}", payload, self._headers())
            log.info("Updated Bitbucket comment %d on PR #%s", existing, pr)
        else:
            _http("POST", api, payload, self._headers())
            log.info("Posted Bitbucket comment on PR #%s", pr)


class AzureDevOps(Platform):
    """
    Required env vars:
      SYSTEM_ACCESSTOKEN   $(System.AccessToken) — must be explicitly mapped

    Auto-injected (when explicitly mapped in pipeline YAML):
      SYSTEM_TEAMFOUNDATIONCOLLECTIONURI, SYSTEM_TEAMPROJECT,
      BUILD_REPOSITORY_ID, BUILD_REPOSITORY_URI, BUILD_SOURCEVERSION,
      SYSTEM_PULLREQUEST_TARGETBRANCH, SYSTEM_PULLREQUEST_SOURCEBRANCH,
      SYSTEM_PULLREQUEST_PULLREQUESTID
    """

    def detected(self) -> bool:
        return os.environ.get("TF_BUILD") == "True"

    def name(self) -> str:
        return "Azure DevOps"

    @property
    def _token(self) -> str:
        return os.environ["SYSTEM_ACCESSTOKEN"]

    @property
    def _org_url(self) -> str:
        return os.environ["SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"].rstrip("/")

    @property
    def _project(self) -> str:
        return os.environ["SYSTEM_TEAMPROJECT"]

    @property
    def _repo_id(self) -> str:
        return os.environ["BUILD_REPOSITORY_ID"]

    def clone_url(self) -> str:
        # BUILD_REPOSITORY_URI doesn't include auth; embed the token.
        uri = os.environ["BUILD_REPOSITORY_URI"]
        if "://" in uri:
            scheme, rest = uri.split("://", 1)
            return f"{scheme}://:{self._token}@{rest}"
        return uri

    def base_branch(self) -> str:
        # No "main" fallback: substituting a hardcoded default here produced a
        # scan of main against the current SHA, which on a repo whose default
        # branch IS main is a permanently green build diffing main against
        # itself. main() now refuses non-PR pipelines outright, so this is
        # only ever reached with a real target branch. See QUAL-09.
        return os.environ["SYSTEM_PULLREQUEST_TARGETBRANCH"].replace("refs/heads/", "")

    def head_branch(self) -> str:
        return (os.environ.get("SYSTEM_PULLREQUEST_SOURCEBRANCH", "")
                .replace("refs/heads/", "")
                or os.environ["BUILD_SOURCEVERSION"])

    def base_label(self) -> str:
        return self.base_branch()

    def head_label(self) -> str:
        return (os.environ.get("SYSTEM_PULLREQUEST_SOURCEBRANCH", "PR branch")
                .replace("refs/heads/", ""))

    def repo(self) -> str:
        project = os.environ.get("SYSTEM_TEAMPROJECT", "")
        name    = os.environ.get("BUILD_REPOSITORY_NAME", "")
        return f"{project}/{name}" if project and name else ""

    def repo_visibility(self) -> str:
        try:
            api = f"{self._org_url}/_apis/projects/{urllib.parse.quote(self._project, safe='')}?api-version=7.1"
            data = _http("GET", api, headers=self._headers())
            assert isinstance(data, dict)
            vis = (data.get("visibility") or "").strip().lower()
            return vis if vis in ("public", "private") else "unknown"
        except Exception as exc:
            log.warning("Could not determine repo visibility: %s", exc)
            return "unknown"

    def pr_number(self) -> int | None:
        val = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID", "").strip()
        return int(val) if val else None

    def base_sha(self) -> str:
        return ""

    def head_sha(self) -> str:
        return os.environ.get("BUILD_SOURCEVERSION", "")

    def _headers(self) -> dict:
        creds = base64.b64encode(f":{self._token}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    def post_or_update_comment(self, body: str) -> None:
        pr  = os.environ["SYSTEM_PULLREQUEST_PULLREQUESTID"]
        api = (f"{self._org_url}/{urllib.parse.quote(self._project, safe='')}/_apis/git"
               f"/repositories/{self._repo_id}/pullRequests/{pr}")
        ver = "?api-version=7.1"

        threads = _http("GET", f"{api}/threads{ver}", headers=self._headers())
        assert isinstance(threads, dict)

        existing_thread: int | None = None
        existing_comment: int | None = None
        for thread in threads.get("value", []):
            for comment in thread.get("comments", []):
                if _COMMENT_MARKER in comment.get("content", ""):
                    existing_thread  = thread["id"]
                    existing_comment = comment["id"]
                    break
            if existing_thread:
                break

        def _post_new_thread() -> None:
            payload = {
                "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
                "status":   1,
            }
            _http("POST", f"{api}/threads{ver}", payload, self._headers())
            log.info("Posted ADO thread on PR #%s", pr)

        if existing_thread and existing_comment:
            url = f"{api}/threads/{existing_thread}/comments/{existing_comment}{ver}"
            try:
                _http("PATCH", url, {"content": body}, self._headers())
                log.info("Updated ADO comment on thread %d, PR #%s", existing_thread, pr)
            except urllib.error.HTTPError as exc:
                if exc.code == 403:
                    # Comment authored by a different identity (e.g. a prior manual
                    # run, or a Build Service identity change) — only the original
                    # author or a project admin can PATCH it. Don't fail the whole
                    # scan over an ownership conflict; start a fresh thread instead.
                    log.warning(
                        "Cannot update existing ADO comment on thread %d (403 — "
                        "owned by a different identity); posting a new thread instead",
                        existing_thread,
                    )
                    _post_new_thread()
                else:
                    raise
        else:
            _post_new_thread()


_PLATFORMS: list[Platform] = [GitHub(), GitLab(), Bitbucket(), AzureDevOps()]


def _repo_base_url() -> str:
    """Best-effort: compute the web URL of this repo from CI env vars."""
    # GitHub Actions
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        server = os.environ.get('GITHUB_SERVER_URL', 'https://github.com').rstrip('/')
        repo   = os.environ.get('GITHUB_REPOSITORY', '')
        return f'{server}/{repo}' if repo else ''
    # GitLab CI
    if os.environ.get('GITLAB_CI') == 'true':
        server = os.environ.get('CI_SERVER_URL', 'https://gitlab.com').rstrip('/')
        path   = os.environ.get('CI_PROJECT_PATH', '')
        return f'{server}/{path}' if path else ''
    # Bitbucket Pipelines
    if os.environ.get('BITBUCKET_BUILD_NUMBER'):
        ws   = os.environ.get('BITBUCKET_WORKSPACE', '')
        slug = os.environ.get('BITBUCKET_REPO_SLUG', '')
        return f'https://bitbucket.org/{ws}/{slug}' if ws and slug else ''
    # Azure DevOps
    if os.environ.get('TF_BUILD') == 'True':
        collection = os.environ.get('SYSTEM_TEAMFOUNDATIONCOLLECTIONURI', '').rstrip('/')
        project    = os.environ.get('SYSTEM_TEAMPROJECT', '')
        repo_name  = os.environ.get('BUILD_REPOSITORY_NAME', '')
        return (f"{collection}/{urllib.parse.quote(project, safe='')}/_git/"
                f"{urllib.parse.quote(repo_name, safe='')}") if all([collection, project, repo_name]) else ''
    return ''


# ── Git helpers ────────────────────────────────────────────────────────────────

def _scan_exclude_paths() -> str:
    """ZAGWARE_EXCLUDE_PATHS with `.git` always appended.

    `.git` used to be merely the *default* value, so the moment an operator set
    ZAGWARE_EXCLUDE_PATHS to anything else -- e.g. "vendor" -- the clone's
    .git directory silently became in-scope for scanning. It holds the packed
    object store and, historically, the credential-bearing remote URL, so it is
    appended unconditionally rather than left to a default that any config
    change removes. See SEC-07.
    """
    parts = [p.strip() for p in _EXCLUDE_PATHS.split(",") if p.strip()]
    if ".git" not in parts:
        parts.append(".git")
    return ",".join(parts)


def _split_credential(url: str) -> tuple[str, dict[str, str]]:
    """Split `https://user:pass@host/path` into a credential-free URL plus an
    env dict that supplies the same credential via `http.extraHeader`.

    Every platform adapter builds its clone URL with the credential inline, and
    passing that as a positional argv to git has two consequences: the token is
    visible in /proc/<pid>/cmdline for the life of the clone, and git persists
    it as remote.origin.url in the clone's .git/config -- a plaintext
    long-lived credential (GITLAB_TOKEN with api scope, BITBUCKET_API_TOKEN
    with repo+PR write, SYSTEM_ACCESSTOKEN) sitting on disk inside the very
    directory the scanner then hands to other tools.

    GIT_CONFIG_COUNT/KEY/VALUE apply the header for one invocation only and are
    never written to .git/config, so the clone ends up with a clean origin URL.

    Measured, not assumed: betterleaks in `dir` mode does NOT walk .git/ (a
    seeded token in .git/config produced 0 findings and an ~11-byte scan
    against the real bundled binary), so the "fed straight to a credential
    scanner" half of SEC-07 does not materialise. The on-disk and argv exposure
    are real regardless, which is what this fixes. See SEC-07.
    """
    parts = urllib.parse.urlsplit(url)
    if not parts.username and not parts.password:
        return url, {}
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    clean = urllib.parse.urlunsplit(
        (parts.scheme, host, parts.path, parts.query, parts.fragment))
    user = urllib.parse.unquote(parts.username or "")
    pw   = urllib.parse.unquote(parts.password or "")
    basic = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return clean, {
        "GIT_CONFIG_COUNT":   "1",
        "GIT_CONFIG_KEY_0":   "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }


def _git(args: list[str], cwd: str | None = None, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        env={**os.environ, **env} if env else None,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, ["git"] + args, result.stdout, result.stderr
        )


def clone_branch(url: str, branch: str, dest: str) -> None:
    """Shallow-clone a single branch with a credential-free argv. See SEC-07."""
    clean, auth_env = _split_credential(url)
    _git(["clone", "--depth=1", "--quiet", "--no-tags",
          "--branch", branch, clean, dest], env=auth_env)


def clone_and_checkout_sha(url: str, base_branch: str, ref: str, dest: str) -> None:
    """Clone the base branch, then fetch and check out an arbitrary *ref*.

    *ref* may be a bare SHA or a full ref path such as `refs/pull/7/head`.
    The checkout targets FETCH_HEAD rather than *ref* itself: `git fetch
    origin refs/pull/7/head` populates FETCH_HEAD but creates no local ref of
    that name, so `git checkout refs/pull/7/head` fails with "pathspec did not
    match" (verified against real git). FETCH_HEAD is correct for both shapes.

    The fetch needs the credential too, and origin is credential-free now, so
    the same out-of-band env is reapplied. See QUAL-13 and SEC-07."""
    clean, auth_env = _split_credential(url)
    _git(["clone", "--depth=1", "--quiet", "--no-tags",
          "--branch", base_branch, clean, dest], env=auth_env)
    _git(["fetch", "--depth=1", "origin", ref], cwd=dest, env=auth_env)
    _git(["checkout", "--quiet", "FETCH_HEAD"], cwd=dest)


# ── Scan ───────────────────────────────────────────────────────────────────────

class ScanFailure(RuntimeError):
    """Raised when a scan TOOL crashes, times out, or produces unreadable
    output — as distinct from the tool running successfully and finding zero
    issues. Subclasses RuntimeError so any existing `except RuntimeError`
    handler still catches it; callers that need to distinguish scan failures
    specifically should catch ScanFailure. Callers MUST NOT treat this the
    same as an empty result list. See QUAL-01 in REVIEW-2026-07-30.md.
    """


def run_scan(path: str, output_json: str) -> dict:
    """Run the IaC scanner on *path*, write JSON to *output_json*, return parsed results.

    Runs with cwd=path so the scanner emits file paths relative to the scan root
    (e.g. 'terraform/main.tf' instead of an absolute or '../..' relative path).
    """
    out_dir  = str(Path(output_json).parent)
    out_name = Path(output_json).stem

    cmd = [
        _SCANNER_BIN, "scan",
        "--path",         ".",          # relative to cwd=path below
        "--queries-path", _QUERIES_PATH,
        "--report-formats", "json",
        "--output-path",  out_dir,      # absolute — unaffected by cwd
        "--output-name",  out_name,
        "--exclude-paths", _scan_exclude_paths(),
        "--disable-full-descriptions",
        "--no-progress",
        "--ci",
    ]
    # Apply severity threshold: exclude findings below ZAGWARE_MIN_SEVERITY from both
    # base and PR scans so the diff only operates on in-scope severities.
    below = _severities_below()
    if below:
        cmd += ["--exclude-severities", ",".join(below)]

    # TimeoutExpired and FileNotFoundError must surface as ScanFailure, not as
    # an unhandled traceback: main() catches RuntimeError (ScanFailure's base)
    # and records telemetry, whereas a bare traceback kills the process before
    # telemetry_flush() and makes a 10-minute monorepo scan indistinguishable
    # from ZAGWARE_FAIL_ON_NEW legitimately blocking the merge. The SCA and
    # Secrets paths already do this; IaC was the outlier. See QUAL-04.
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=path,
                                timeout=_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise ScanFailure(
            f"KICS exceeded its {_SCAN_TIMEOUT}s budget scanning {path} — this is NOT "
            f"'no findings'; it is a scanner failure. Raise ZAGWARE_SCAN_TIMEOUT if this "
            f"repository legitimately needs longer."
        ) from exc
    except FileNotFoundError as exc:
        raise ScanFailure(
            f"KICS binary not found at {_SCANNER_BIN} ({exc}) — this is NOT 'no findings'; "
            f"it is a scanner failure. Check the image, or _ZAGWARE_SCANNER_BIN if overridden."
        ) from exc

    # KICS exit codes: 0=no findings, 30=LOW/INFO, 40=MEDIUM, 50=HIGH/CRITICAL.
    # All of these are valid — the output file is the source of truth, not the
    # exit code. Only fail if we can't read valid JSON output.
    if result.returncode not in (0, 30, 40, 50):
        log.warning("Unexpected KICS exit code %d", result.returncode)
        if result.stderr:
            log.debug("stderr: %s", result.stderr[:800])

    try:
        with open(output_json) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        # Output missing = KICS crashed before writing. This is NOT 'no findings'.
        raise ScanFailure(
            f"KICS output not readable ({exc}) — scanner may have crashed. "
            f"Exit code: {result.returncode}. This is NOT 'no findings'; it is a scanner failure."
        ) from exc


# ── Diff ───────────────────────────────────────────────────────────────────────

def _base_sim_ids(results: dict) -> set[str]:
    return {
        f["similarity_id"]
        for q in results.get("queries", [])
        for f in q.get("files", [])
    }


def new_findings(base: dict, pr: dict, suppressed: set[str] | None = None) -> list[dict]:
    """Return queries from *pr* containing only findings absent from *base*.

    If *suppressed* is provided, findings whose similarity_id is in the set
    are excluded from the novel list.
    """
    base_sims = _base_sim_ids(base)
    supp = suppressed or set()
    sev_rank  = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    out: list[dict] = []
    for q in pr.get("queries", []):
        novel = [f for f in q.get("files", [])
                 if f["similarity_id"] not in base_sims
                 and f["similarity_id"] not in supp]
        if novel:
            out.append({**q, "files": novel})
    out.sort(key=lambda q: sev_rank.get(q.get("severity", ""), 99))
    return out


def count_findings(queries: list[dict]) -> int:
    return sum(len(q.get("files", [])) for q in queries)


# ── SCA (Grype) ────────────────────────────────────────────────────────────────

def _sca_sim_id(vuln_id: str, pkg_name: str, pkg_version: str) -> str:
    return hashlib.sha256(f"{vuln_id}:{pkg_name}:{pkg_version}".encode()).hexdigest()


def _exclude_globs() -> list[str]:
    """Excluded paths as Syft-style globs, relative to the scan root.

    ZAGWARE_EXCLUDE_PATHS was threaded into exactly ONE command line (KICS),
    so an operator who scoped the scan with
    ZAGWARE_EXCLUDE_PATHS=".git,node_modules,vendor,test/fixtures" -- the
    documented mechanism -- still got every CVE from vendored trees and every
    secret from test fixtures. Test-fixture credentials are the classic
    secrets false positive, and with ZAGWARE_SECRETS_FAIL_ON_PUBLIC on a
    public repo they broke the build with no way to scope them out short of
    suppressing each fingerprint. See QUAL-10.
    """
    globs: list[str] = []
    for e in _scan_exclude_paths().split(","):
        e = e.strip().rstrip("/")
        if e:
            globs.append(f"./{e}/**" if "*" not in e else e)
    return globs


def _has_sca_manifests(path: str) -> bool:
    """True when at least one dependency manifest exists outside the excluded
    paths. Previously rglob'd the whole tree including .git and any path the
    operator excluded, so a vendored tree alone could switch SCA on. See
    QUAL-10."""
    p = Path(path)
    excluded = [e for e in _scan_exclude_paths().split(",") if e]
    for m in _SCA_MANIFESTS:
        for hit in p.rglob(m):
            rel = hit.relative_to(p).as_posix()
            if any(rel == e or rel.startswith(e.rstrip("/") + "/") for e in excluded):
                continue
            return True
    return False


def _run_syft(path: str, sbom_out: str) -> bool:
    cmd = [_SYFT_BIN, "scan", f"dir:{path}", "-o", f"syft-json={sbom_out}"]
    # One --exclude per excluded path. `.git` is always among them
    # (_scan_exclude_paths), so the clone's own object store is never
    # catalogued, and an operator's ZAGWARE_EXCLUDE_PATHS now actually scopes
    # SCA instead of applying to KICS alone. See QUAL-10 and SEC-07.
    for glob in _exclude_globs():
        cmd += ["--exclude", glob]
    cmd.append("--quiet")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            log.warning("Syft exited %d: %s", r.returncode, (r.stderr or r.stdout or "").strip()[:400])
        # Accept output even on non-zero exit (Syft may emit warnings as errors)
        return Path(sbom_out).exists() and Path(sbom_out).stat().st_size > 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.error("Syft unavailable: %s", e)
        return False


def _run_grype(sbom_path: str, grype_out: str) -> bool:
    try:
        r = subprocess.run(
            [_GRYPE_BIN, f"sbom:{sbom_path}", "-o", "json", "--quiet"],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            log.warning("Grype exited %d: %s", r.returncode, (r.stderr or r.stdout or "").strip()[:400])
        # Accept stdout output even on non-zero exit — Grype may emit warnings
        # as errors but still produce valid JSON with vulnerability matches.
        if r.stdout:
            Path(grype_out).write_text(r.stdout)
            return True
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.error("Grype unavailable: %s", e)
        return False


def run_sca_scan(path: str, tmp_dir: str, label: str) -> list[dict] | None:
    """Run Syft+Grype SCA scan.

    Returns:
        None  — SCA disabled or no manifest files found (skipped, not scanned).
        [...] — Scanned successfully; may be empty ([]) if genuinely clean.

    Raises:
        ScanFailure — Syft or Grype crashed, timed out, or produced unreadable
        output. Callers MUST treat this as a failed scan, not as "zero
        findings" — see QUAL-01 in REVIEW-2026-07-30.md.
    """
    if not _SCA_ENABLED:
        return None
    if not _has_sca_manifests(path):
        log.debug("SCA: no manifest files in %s — skipping", label)
        return None
    sbom_out  = f"{tmp_dir}/sbom_{label}.json"
    grype_out = f"{tmp_dir}/grype_{label}.json"
    log.info("SCA: running Syft on %s...", label)
    if not _run_syft(path, sbom_out):
        raise ScanFailure(f"SCA: Syft failed for {label} — this is NOT 'no findings'; it is a scanner failure.")
    log.info("SCA: running Grype on %s...", label)
    if not _run_grype(sbom_out, grype_out):
        raise ScanFailure(f"SCA: Grype failed for {label} — this is NOT 'no findings'; it is a scanner failure.")
    try:
        data = json.loads(Path(grype_out).read_text())
    except Exception as e:
        raise ScanFailure(
            f"SCA: could not read Grype output for {label}: {e} — this is NOT 'no findings'; it is a scanner failure."
        ) from e
    findings: list[dict] = []
    for match in data.get("matches", []):
        try:
            vuln     = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            vuln_id  = vuln.get("id", "")
            pkg_name = artifact.get("name", "")
            pkg_ver  = artifact.get("version", "")
            if not vuln_id or not pkg_name:
                continue
            cvss = None
            for c in vuln.get("cvss", []):
                b = c.get("metrics", {}).get("baseScore") or c.get("metrics", {}).get("base_score")
                if b is not None:
                    try:
                        cvss = float(b)
                    except (TypeError, ValueError):
                        pass
                    break
            epss_list = vuln.get("epss", [])
            epss = None
            if epss_list:
                try:
                    epss = float(epss_list[0].get("epss"))
                except (TypeError, ValueError, IndexError, KeyError):
                    pass
            fix  = vuln.get("fix", {})
            locs = artifact.get("locations", [])
            mdet = match.get("matchDetails", [])
            urls = list(vuln.get("urls") or [])
            for adv in vuln.get("advisories") or []:
                u = adv.get("url") or adv.get("link") or ""
                if u and u not in urls:
                    urls.append(u)
            severity = (vuln.get("severity") or "UNKNOWN").upper()
            # Apply ZAGWARE_MIN_SEVERITY to SCA findings (map NEGLIGIBLE→LOW for
            # comparison), via the module-level _SCA_MIN_RANK — not a dict rebuilt
            # from _SCA_SEVERITY_ORDER's position on every match. Startup validation
            # guarantees _MIN_SEVERITY is one of the six IaC tiers, all present as
            # _SCA_MIN_RANK keys, so the subscript below is safe. See QUAL-03/22.
            if _MIN_SEVERITY:
                sca_sev = "LOW" if severity == "NEGLIGIBLE" else severity
                if _SCA_MIN_RANK.get(sca_sev, -1) > _SCA_MIN_RANK[_MIN_SEVERITY]:
                    continue  # below threshold — skip
            findings.append({
                "vulnerability_id": vuln_id,
                "data_source":      vuln.get("dataSource") or "",
                "namespace":        vuln.get("namespace")  or "",
                "severity":         severity,
                "cvss_score":       cvss,
                "epss_score":       epss,
                # Grype's real field names (verified against the bundled v0.112.0
                # source, grype/presenter/models/vulnerability_metadata.go and
                # vulnerability.go): KEV is "knownExploited" (a list, non-empty
                # when listed), risk is "risk" (float64) on the outer Vulnerability
                # struct, not nested under "vulnerability". "kev"/"riskScore" are
                # not real Grype keys — reading them always returned
                # None/False. See QUAL-06.
                "kev_listed":       bool(vuln.get("knownExploited")),
                "risk_score":       vuln.get("risk"),
                "description":      vuln.get("description") or "",
                "vuln_urls":        urls,
                "fix_versions":     fix.get("versions") or [],
                "fix_state":        fix.get("state") or "unknown",
                "package_name":     pkg_name,
                "package_version":  pkg_ver,
                "package_type":     artifact.get("type")     or "",
                "package_language": artifact.get("language") or "",
                "package_purl":     artifact.get("purl")     or "",
                "file_path":        locs[0].get("path", "") if locs else "",
                "match_type":       mdet[0].get("type", "")  if mdet else "",
                "similarity_id":    _sca_sim_id(vuln_id, pkg_name, pkg_ver),
            })
        except Exception as e:
            log.warning("SCA: skipping malformed match: %s", e)
            continue
    log.info("SCA %s: %d finding(s)", label, len(findings))
    return findings


def new_sca_findings(
    base: list[dict] | None, head: list[dict] | None,
    suppressed: set[str] | None = None,
) -> list[dict]:
    base_sims = {f["similarity_id"] for f in (base or [])}
    supp = suppressed or set()
    return [f for f in (head or [])
            if f["similarity_id"] not in base_sims
            and f["similarity_id"] not in supp]

# ── Secrets (betterleaks) ────────────────────────────────────────────────────

def _write_betterleaks_config(tmp_dir: str, label: str) -> str | None:
    """Write a betterleaks config that allowlists the excluded paths.

    Returns the config path, or None when there is nothing to exclude (in
    which case betterleaks runs on its stock defaults). `extend.useDefault`
    keeps every built-in rule -- this only ADDS an allowlist, it never
    narrows detection. Paths are anchored regexes, so an entry like `vendor`
    excludes `vendor/...` and not `my-vendor-notes.txt`. See QUAL-10.
    """
    globs = [e.strip().rstrip("/") for e in _scan_exclude_paths().split(",") if e.strip()]
    if not globs:
        return None
    patterns = ",\n  ".join(f'"^{_re.escape(g)}/"' for g in globs)
    cfg = (
        'title = "zagware-generated"\n\n'
        "[extend]\n"
        "useDefault = true\n\n"
        "[[allowlists]]\n"
        'description = "ZAGWARE_EXCLUDE_PATHS"\n'
        f"paths = [\n  {patterns}\n]\n"
    )
    path = f"{tmp_dir}/betterleaks_{label}.toml"
    try:
        Path(path).write_text(cfg, encoding="utf-8")
    except OSError as exc:
        # Non-fatal: scanning the whole tree is worse than scoping it, but far
        # better than not scanning at all.
        log.warning("Could not write betterleaks exclude config (%s) — "
                    "ZAGWARE_EXCLUDE_PATHS will not apply to the secrets scan", exc)
        return None
    return path


def run_secrets_scan(path: str, tmp_dir: str, label: str) -> list[dict] | None:
    """Run betterleaks against the current working-tree state of *path*.

    Scans filesystem state only (betterleaks `dir` mode) — not git history. This
    matches the same shallow-clone / working-tree-diff architecture already used
    for IaC (KICS) and SCA (Syft+Grype): the scanner clones base and head branches
    shallow and diffs their checked-out state, so a `git`-mode history scan isn't
    applicable here (and would defeat the point of the shallow clone).

    SECURITY: betterleaks' JSON report includes the raw secret value in `Secret`/
    `Match` fields — `--redact` only affects console/log output, not the report
    file (confirmed against betterleaks source, since its help text says "redact
    secrets from logs and stdout"). This function reads ONLY rule_id/description/
    file_path/line/tags/validation_status/fingerprint from each finding and never
    touches Secret/Match/MatchContext/CaptureGroups/Line — those must never be
    stored, logged, or transmitted anywhere downstream of this function.

    Returns:
        None  — secrets scanning disabled (ZAGWARE_SECRETS_ENABLED=false).
        [...] — scanned successfully; may be empty ([]) if genuinely clean.

    Raises:
        ScanFailure — betterleaks crashed, timed out, or produced unreadable
        output. Callers MUST treat this as a failed scan, not as "zero
        findings" — see QUAL-01 in REVIEW-2026-07-30.md.
    """
    if not _SECRETS_ENABLED:
        return None

    out_json = f"{tmp_dir}/secrets_{label}.json"
    cmd = [
        _SECRETS_BIN, "dir", ".",
        "--report-path", out_json,
        "--report-format", "json",
        "--exit-code", "0",  # report file is the source of truth, not the exit code
        "--no-color",
        "--no-banner",
        # --redact masks matched secret material in betterleaks' console output
        # (it does NOT affect the report file -- see the SECURITY note above).
        # Without it, the tool's stdout carries the leaked credential and its
        # surrounding line, which the error path below used to copy verbatim
        # into the CI job log. See SEC-08.
        "--redact",
    ]
    # betterleaks has no --exclude flag; path scoping goes through an allowlist
    # in its config (verified against the real bundled 1.7.2 binary: a fixture
    # under an excluded path drops out of the report). Without this,
    # ZAGWARE_EXCLUDE_PATHS applied to KICS only, so test-fixture credentials
    # -- the classic secrets false positive -- could not be scoped out at all
    # short of suppressing each fingerprint by hand. See QUAL-10.
    cfg_path = _write_betterleaks_config(tmp_dir, label)
    if cfg_path:
        cmd += ["--config", cfg_path]
    log.info("Secrets: running betterleaks on %s...", label)
    try:
        # cwd=path + "." (not the absolute path) so the Fingerprint's embedded
        # file path is relative and stable across base/head's different tmp dirs —
        # otherwise every finding would show as "new" even when unchanged.
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=path, timeout=300)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise ScanFailure(
            f"Secrets: betterleaks unavailable for {label}: {e} — this is NOT 'no findings'; it is a scanner failure."
        ) from e
    if result.returncode != 0:
        # Deliberately does NOT interpolate stdout/stderr: for a secrets
        # scanner that output is the leaked credential. The report file is the
        # source of truth (see --exit-code 0 above), so the return code alone
        # is all the diagnostic this path needs. See SEC-08.
        log.warning("Secrets: betterleaks exited %d for %s — see the report file for findings; "
                    "console output withheld because it can contain raw secret material",
                    result.returncode, label)

    try:
        raw = json.loads(Path(out_json).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ScanFailure(
            f"Secrets: could not read betterleaks output for {label}: {e} — this is NOT 'no findings'; it is a scanner failure."
        ) from e
    if not raw:  # betterleaks writes the literal JSON `null` when zero findings
        log.info("Secrets %s: 0 finding(s)", label)
        return []

    findings: list[dict] = []
    for f in raw:
        try:
            rule_id     = f.get("RuleID", "")
            fingerprint = f.get("Fingerprint", "")
            if not rule_id or not fingerprint:
                continue
            findings.append({
                "rule_id":           rule_id,
                "description":       f.get("Description", ""),
                "file_path":         f.get("File") or (f.get("Attributes") or {}).get("path", ""),
                "line":              f.get("StartLine"),
                "tags":              list(f.get("Tags") or []),
                "validation_status": (f.get("ValidationStatus") or "unknown").lower(),
                # betterleaks' own Fingerprint is a *readable* "file_path:rule_id:line"
                # string, not a hash — using it verbatim would show raw file paths as
                # the suppress-command id (confusing, and inconsistent with IaC's KICS
                # hash and SCA's sha256(cve:pkg:version)). Hash it for a uniform,
                # opaque id; stability across scans is unaffected since sha256 is
                # deterministic on the same fingerprint input.
                "similarity_id":     hashlib.sha256(fingerprint.encode()).hexdigest(),
            })
            # NEVER read f["Secret"], f["Match"], f["MatchContext"], f["CaptureGroups"], f["Line"] here.
        except Exception as e:
            log.warning("Secrets: skipping malformed finding: %s", e)
            continue
    log.info("Secrets %s: %d finding(s)", label, len(findings))
    return findings


def new_secrets_findings(
    base: list[dict] | None, head: list[dict] | None,
    suppressed: set[str] | None = None,
) -> list[dict]:
    base_sims = {f["similarity_id"] for f in (base or [])}
    supp = suppressed or set()
    return [f for f in (head or [])
            if f["similarity_id"] not in base_sims
            and f["similarity_id"] not in supp]


# ── Interactive suppression from PR comments ──────────────────────────────────

_SUPPRESS_ALLOWED_ASSOCIATIONS = {
    a.strip().upper()
    for a in os.environ.get(
        "ZAGWARE_SUPPRESS_ALLOWED_ASSOCIATIONS", "OWNER,MEMBER,COLLABORATOR"
    ).split(",")
    if a.strip()
}

# Anchored to the start of the (already-stripped) line, with MULTILINE so the
# anchor also holds per-line when checking a whole comment body — this is what
# stops the scanner's own instructional text ("/zagware suppress <id> <reason>",
# quoted back at it by a reply) from being mistaken for an authored command.
# Reason is optional: "/zagware suppress <id>" with no trailing text is a
# valid command, not a silent no-op.
_SUPPRESS_CMD_RE = _re.compile(
    r'^/zagware\s+suppress\s+(\S+)(?:\s+(.*))?', _re.IGNORECASE | _re.MULTILINE,
)


def _filter_authorized_comments(comments: list[dict]) -> list[dict]:
    """Drop comments whose author is not authorized to issue /zagware suppress
    commands (see _SUPPRESS_ALLOWED_ASSOCIATIONS above). Default-deny: a
    comment with no author_association field — the platform doesn't provide
    one, or it's empty — is rejected rather than silently trusted.

    MUST be called on every comment list before it reaches
    parse_suppression_commands(); that function does not itself check
    authorization. See SEC-01 in REVIEW-2026-07-30.md.
    """
    allowed: list[dict] = []
    for c in comments:
        assoc = (c.get("author_association") or "").strip().upper()
        if assoc in _SUPPRESS_ALLOWED_ASSOCIATIONS:
            allowed.append(c)
        elif "/zagware suppress" in c.get("body", "").lower():
            log.warning(
                "Ignoring /zagware suppress command from '%s' — author_association "
                "'%s' not in allowed set %s",
                c.get("author", "unknown"), assoc or "(none)",
                sorted(_SUPPRESS_ALLOWED_ASSOCIATIONS),
            )
    return allowed


def parse_suppression_commands(comments: list[dict]) -> list[tuple[str, str, str, str]]:
    """Parse /zagware suppress <id> <reason> commands from PR comments.

    Callers MUST pass comments through _filter_authorized_comments() first —
    this function does not itself check authorization (see SEC-01).

    Returns list of (similarity_id, reason, author, created_at) tuples. author/created_at
    identify who posted the command and when — used to attribute the suppression audit
    trail (see collect_suppression_records()) without depending on git blame.
    """
    commands: list[tuple[str, str, str, str]] = []
    for c in comments:
        body = c.get("body", "")
        if _COMMENT_MARKER in body or _BB_COMMENT_MARKER in body:
            continue  # the scanner's own comment — never a trusted command source
        author = c.get("author") or "unknown"
        created_at = c.get("created_at", "")
        for line in body.splitlines():
            m = _SUPPRESS_CMD_RE.match(line.strip())
            if m:
                sim_id = m.group(1).strip()
                # Strip leading/trailing non-hex chars (e.g. copy-pasted backticks
                # or a "…" truncation marker), not just trailing.
                sim_id = _re.sub(r'^[^0-9a-fA-F]+|[^0-9a-fA-F]+$', '', sim_id)
                if not sim_id:
                    continue
                reason = (m.group(2) or "").strip() or "Suppressed via PR comment"
                # Strip "reason:" prefix if present
                if reason.lower().startswith("reason:"):
                    reason = reason[7:].strip()
                log.info("Parsed suppress command: id=%s author=%s", sim_id[:16], author)
                commands.append((sim_id, reason, author, created_at))
    return commands


def resolve_suppression_id(
    prefix: str, novel: list[dict], novel_sca: list[dict], novel_secrets: list[dict] | None = None,
) -> tuple[str, str | None, int]:
    """Resolve a (possibly truncated) similarity_id prefix against current novel findings.

    Returns (outcome, full_id, match_count):
      ("resolved",  <full id>, 1)  exactly one unambiguous match
      ("not_found", None,      0)  nothing matched
      ("ambiguous", None,      n)  the prefix matches n>1 findings

    It previously returned None for both not-found and ambiguous, so anyone
    hitting a real prefix collision was sent to debug a nonexistent typo. See
    QUAL-17.

    Exact matches always qualify; prefix matches require at least 6 hex
    characters to avoid over-matching on garbage input.
    """
    candidates: set[str] = set()
    is_prefix_ok = len(prefix) >= 6
    for q in novel:
        for f in q.get("files", []):
            sid = f.get("similarity_id", "")
            if sid == prefix or (is_prefix_ok and sid.startswith(prefix)):
                candidates.add(sid)
    for f in novel_sca:
        sid = f.get("similarity_id", "")
        if sid == prefix or (is_prefix_ok and sid.startswith(prefix)):
            candidates.add(sid)
    for f in (novel_secrets or []):
        sid = f.get("similarity_id", "")
        if sid == prefix or (is_prefix_ok and sid.startswith(prefix)):
            candidates.add(sid)
    if len(candidates) == 1:
        return "resolved", next(iter(candidates)), 1
    if not candidates:
        return "not_found", None, 0
    return "ambiguous", None, len(candidates)


def apply_suppression_commands(
    pr_dir: str, clone_url: str, head_branch: str,
    commands: list[tuple[str, str, str, str]],
) -> tuple[str, str]:
    """Write new suppressions to .zagware/suppressions.yaml and push to PR branch.

    Each entry records suppressed_by/suppressed_at (the PR commenter and comment
    timestamp) alongside id/reason, so the platform-side suppression audit trail
    (see collect_suppression_records()) can attribute it exactly.

    Returns (outcome, detail):
      ("applied",      "")        committed and pushed
      ("nothing_todo", "")        every command was already in the file
      ("failed",       <reason>)  the write or push was rejected

    This used to return a bool, and False meant BOTH "already present" and
    "push rejected". main() read False as nothing-to-do, so when
    `contents: write` was absent or branch protection rejected the bot push --
    both common -- the user commented /zagware suppress, the build re-ran, and
    the comment came back byte-identical with the finding still listed and the
    build still red. The only clue was one ERROR line in the job log, and
    since the file was never committed the suppression would never apply on
    any future run either. Callers surface "failed" in the PR comment, which
    is the only surface the requesting user is actually looking at.
    See QUAL-18.
    """
    if not commands:
        return "nothing_todo", ""

    base = Path(pr_dir).resolve()
    supp_path = base / _SUPPRESSIONS_PATH

    # Same symlink + containment guard as _safe_read_suppressions_file, applied
    # before any write: without it a hostile PR's symlinked suppressions.yaml
    # turns an authorized suppress command into a root-level arbitrary write
    # inside the container. Checked BEFORE mkdir too, since an intermediate
    # symlinked .zagware/ directory would otherwise have mkdir(parents=True)
    # silently create paths through it. See SEC-04.
    if supp_path.is_symlink():
        msg = f"{_SUPPRESSIONS_PATH} is a symlink, not a regular file"
        log.error("Refusing to write %s — %s", _SUPPRESSIONS_PATH, msg)
        return "failed", msg
    try:
        resolved_target = supp_path.resolve()
    except OSError as exc:
        log.error("Refusing to write %s: %s", _SUPPRESSIONS_PATH, exc)
        return "failed", str(exc)
    if not resolved_target.is_relative_to(base):
        msg = f"{_SUPPRESSIONS_PATH} resolves outside the scanned repository"
        log.error("Refusing to write %s — %s", _SUPPRESSIONS_PATH, msg)
        return "failed", msg

    supp_path.parent.mkdir(parents=True, exist_ok=True)

    # Read existing suppressions to avoid duplicates
    existing = load_suppressions(pr_dir)
    new_entries = [(sid, reason, author, created_at)
                   for sid, reason, author, created_at in commands if sid not in existing]
    if not new_entries:
        log.info("All suppression commands already in file — nothing to add")
        return "nothing_todo", ""

    # Build YAML entries
    yaml_lines: list[str] = []
    current_text = _safe_read_suppressions_file(pr_dir) or (
        "# Zagware Scanner — Suppressions\n# Auto-managed by /zagware suppress commands\n\n"
    )

    for sid, reason, author, created_at in new_entries:
        safe_reason = reason.replace('\\', '\\\\').replace('"', '\\"')
        yaml_lines.append(f"- id: {sid}")
        yaml_lines.append(f'  reason: "{safe_reason}"')
        yaml_lines.append(f'  suppressed_by: "{author}"')
        if created_at:
            yaml_lines.append(f'  suppressed_at: "{created_at}"')
        yaml_lines.append("")

    new_text = current_text.rstrip() + "\n\n" + "\n".join(yaml_lines)
    try:
        fd = os.open(str(supp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
    except OSError as exc:
        log.error("Refusing to write %s: %s", _SUPPRESSIONS_PATH, exc)
        return "failed", str(exc)

    # Git commit and push. origin is now a credential-free URL (see SEC-07), so
    # the push needs the credential supplied out-of-band the same way the clone
    # did. This is also what clone_url is finally *for*: it was previously an
    # unused positional parameter, a trap in a 4-argument call (QUAL-22).
    _, auth_env = _split_credential(clone_url)
    try:
        _git(["config", "user.email", "zagware-scanner@users.noreply.github.com"], cwd=pr_dir)
        _git(["config", "user.name", "Zagware Scanner"], cwd=pr_dir)
        _git(["add", _SUPPRESSIONS_PATH], cwd=pr_dir)
        _git(["commit", "-m", f"suppress: {len(new_entries)} finding(s) via PR comment"], cwd=pr_dir)
        _git(["push", "origin", head_branch], cwd=pr_dir, env=auth_env)
        log.info("Pushed %d suppression(s) to %s — pipeline will re-run", len(new_entries), head_branch)
        return "applied", ""
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or str(exc)).strip()
        log.error("Failed to push suppressions: %s", detail)
        return "failed", detail

# ── Comment rendering ──────────────────────────────────────────────────────────

def _cell(text, limit: int = 80) -> str:
    """Sanitise one value for interpolation into the PR comment.

    Every value passed here can originate in the pull request under review --
    file names, IaC resource names, lockfile package names, betterleaks rule
    tags -- so the comment the scanner posts is attacker-influenced content
    rendered under the bot's identity. Reviewers treat that comment as the
    authoritative gate output, so forging it is a review-integrity bypass that
    needs no privilege. Four escapes, each closing a specific break-out:

      backtick -> "'"    a backtick escapes the surrounding `code span`; it
                         cannot be escaped *inside* one without changing the
                         fence length, so it is replaced rather than escaped
      < >      -> &lt;   GitHub's comment sanitiser permits <img>, <a>, <b> and
                 &gt;    <details>, so raw angle brackets allow a tracking
                         beacon, or a </details> that escapes the collapsed
                         section and lets forged text (e.g. a fake "No new
                         security findings" line) render as the bot's own
      |        -> \\|     breaks the markdown table structure for the row
      CR / LF  -> space  injects entirely new table rows or markdown blocks

    See SEC-06.
    """
    if text is None:
        return ""
    text = (str(text)
            .replace("\r", " ").replace("\n", " ")
            .replace("`", "'")
            .replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|")
            .strip())
    return text[:limit] + "…" if len(text) > limit else text


_SECRET_PATTERNS = [
    _re.compile(r'(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*\S+', _re.IGNORECASE),
    _re.compile(r'AKIA[0-9A-Z]{16}'),
    _re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'),
    _re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    _re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
]

_SECRET_CATEGORIES = {"secret management"}  # exact KICS category string (verified
                                             # against the pinned rules commit, see
                                             # Dockerfile KICS_RULES_COMMIT) — "Encryption"
                                             # etc. are NOT secret-value-shaped findings


def _redact_value(val, category: str = "") -> str:
    """Mask secret-like values before rendering in comments or writing to artifacts."""
    if not val or not isinstance(val, str):
        return val if val else ""
    if (category or "").strip().lower() in _SECRET_CATEGORIES:
        return "***REDACTED***"
    result = val
    for pat in _SECRET_PATTERNS:
        result = pat.sub("***REDACTED***", result)
    return result


def _redact_kics_results(results: dict) -> dict:
    """Deep-copy KICS results with actual_value and expected_value redacted to
    prevent secret leakage. actual_value gets the full category+pattern check
    (see _redact_value); expected_value is normally a policy statement rather
    than a literal value pulled from the resource, but gets the same regex
    pattern pass as defense-in-depth since some queries do populate it from
    resource content. See SEC-02."""
    import copy
    redacted = copy.deepcopy(results)
    for q in redacted.get("queries", []):
        cat = q.get("category", "")
        for f in q.get("files", []):
            if "actual_value" in f:
                f["actual_value"] = _redact_value(f.get("actual_value", ""), cat)
            if "expected_value" in f:
                f["expected_value"] = _redact_value(f.get("expected_value", ""))
    return redacted


# ── Suppressions ──────────────────────────────────────────────────────────────

_SUPPRESSIONS_PATH = os.environ.get("ZAGWARE_SUPPRESSIONS_FILE", ".zagware/suppressions.yaml")

_MAX_SUPPRESSIONS_FILE_SIZE = 1024 * 1024  # 1 MiB — bounds the read regardless of
                                            # what a hostile symlink target points at


def _safe_read_suppressions_file(scan_dir: str) -> str | None:
    """Read .zagware/suppressions.yaml from *scan_dir*, refusing to follow a
    symlink and refusing to read a path that resolves outside *scan_dir*.
    Returns None if the file doesn't exist or fails either check — callers
    treat None the same as "no suppressions file".

    Git checks out symlinks verbatim, so a hostile PR can commit
    .zagware/suppressions.yaml (or the .zagware directory itself) as a
    symlink to an arbitrary path. Without this guard, a PR-only attacker with
    no other privilege could make the scanner read any file the process can
    reach — its content gets parsed as key:value pairs and the "reason"
    fields get uploaded to the platform (collect_suppression_records) —
    or hang the scan by pointing it at /dev/zero. See SEC-04.
    """
    base = Path(scan_dir).resolve()
    supp_file = base / _SUPPRESSIONS_PATH

    if supp_file.is_symlink():
        log.warning("Refusing to read %s — it is a symlink, not a regular file", _SUPPRESSIONS_PATH)
        return None

    try:
        resolved = supp_file.resolve()
    except OSError as exc:
        log.warning("Could not resolve %s: %s", _SUPPRESSIONS_PATH, exc)
        return None
    if not resolved.is_relative_to(base):
        log.warning("Refusing to read %s — it resolves outside the scanned repository", _SUPPRESSIONS_PATH)
        return None
    if not resolved.exists():
        return None

    # O_NOFOLLOW closes the TOCTOU window between the is_symlink() check above
    # and this open() — if the final path component became a symlink in the
    # meantime, the open fails instead of following it.
    try:
        fd = os.open(str(resolved), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        log.warning("Refusing to read %s: %s", _SUPPRESSIONS_PATH, exc)
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            data = f.read(_MAX_SUPPRESSIONS_FILE_SIZE + 1)
    except OSError as exc:
        log.warning("Could not read %s: %s", _SUPPRESSIONS_PATH, exc)
        return None
    if len(data) > _MAX_SUPPRESSIONS_FILE_SIZE:
        log.warning("%s exceeds %d bytes — refusing to parse (truncated or hostile file?)",
                     _SUPPRESSIONS_PATH, _MAX_SUPPRESSIONS_FILE_SIZE)
        return None
    return data


def _unescape_suppression_reason(s: str) -> str:
    """Reverse the writer's escaping (backslash-then-quote, in that order) --
    a real single-pass unescape, not two independent global .replace() calls,
    which would double-process a literal `\\"` sequence (an escaped backslash
    immediately followed by a literal quote) into the wrong result. See
    QUAL-24: the writer used to escape only quotes, and the reader stripped
    every leading/trailing quote character rather than one matching pair, so
    a reason like `he said "hi"` round-tripped as a mangled, dangling-
    backslash string."""
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in ("\\", '"'):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _strip_inline_comment(val: str) -> str:
    """Drop a trailing `# comment` from a scalar, respecting quotes.

    `- id: abc123  # false positive` previously yielded the id
    `abc123  # false positive`, which then matched nothing. Only a `#` that is
    OUTSIDE any quote and preceded by whitespace starts a comment, so a
    legitimate `reason: "fails on #4 in prod"` survives intact. See QUAL-15.
    """
    in_single = in_double = False
    for i, ch in enumerate(val):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or val[i - 1].isspace():
                return val[:i].rstrip()
    return val


def _parse_suppressions_file(scan_dir: str) -> dict[str, dict]:
    """Parse .zagware/suppressions.yaml into {similarity_id: {reason, added_by, added_at}}.

    A deliberately small line-oriented parser, not full YAML: the scanner is
    stdlib-only by design so the runtime image needs no pip step (see the
    README's Self-hosting section), and PyYAML would break that. The trade-off
    is that it must FAIL LOUDLY rather than silently half-parse — a
    yaml-lint-clean file that this parser only partly understood used to leave
    the finding unsuppressed, the build red, and a plausible-looking
    "Loaded N suppression(s)" in the log with nothing indicating which entries
    were dropped. Every discard is now logged with its line number, and the
    parsed/total counts are reported so a mismatch is visible. See QUAL-15.

    added_by/added_at come from the suppressed_by/suppressed_at fields written by
    apply_suppression_commands() for entries added via /zagware suppress PR comments.
    Entries written by hand (or predating this field) have added_by=added_at=None.
    NOTE for callers: these values are read straight out of a repo-controlled
    file and are therefore UNVERIFIED claims, not evidence — see SEC-10 and
    collect_suppression_records(), which surfaces them as `claimed_by`.
    """
    text = _safe_read_suppressions_file(scan_dir)
    if text is None:
        return {}

    records: dict[str, dict] = {}
    current: dict = {}
    current_line = 0
    blocks_seen = 0

    def _flush() -> None:
        nonlocal blocks_seen
        if not current:
            return
        blocks_seen += 1
        sid = current.get("id")
        if not sid:
            log.warning(
                "Ignoring suppression entry starting at %s line %d: no 'id' field "
                "(keys present: %s)",
                _SUPPRESSIONS_PATH, current_line, ", ".join(sorted(current)) or "none",
            )
            return
        records[sid] = {
            "reason":   current.get("reason", ""),
            "added_by": current.get("suppressed_by"),
            "added_at": current.get("suppressed_at"),
            "expires":  current.get("expires"),
        }

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") or stripped == "-":
            # `-` alone on its own line is valid YAML for a list item whose
            # keys follow on subsequent lines; it previously failed the
            # startswith("- ") test, so those keys silently merged into the
            # PREVIOUS record. See QUAL-15.
            _flush()
            current = {}
            current_line = lineno
            stripped = stripped[2:] if stripped.startswith("- ") else ""
            if not stripped:
                continue
        if ":" not in stripped:
            log.warning("Ignoring unparseable line %d in %s: %r (expected 'key: value')",
                        lineno, _SUPPRESSIONS_PATH, stripped[:80])
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = _strip_inline_comment(val.strip()).strip()
        # Strip exactly one matching outer quote pair -- not
        # .strip('"').strip("'"), which removes *every* leading/trailing
        # occurrence and mangles a reason like `"he said \"hi\""` into
        # `he said \"hi\` with a dangling backslash. Only a double-quoted
        # value gets unescaped (single-quoted values carry no escapes).
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = _unescape_suppression_reason(val[1:-1])
        elif len(val) >= 2 and val[0] == "'" and val[-1] == "'":
            val = val[1:-1]
        elif val[:1] in ("[", "{", ">", "|"):
            # Flow style, block scalars and anchors are valid YAML this parser
            # cannot represent. Refusing loudly beats storing a half-value.
            log.warning(
                "Ignoring %r at %s line %d: flow style, block scalars and anchors are "
                "not supported — use a plain or double-quoted scalar",
                key, _SUPPRESSIONS_PATH, lineno,
            )
            continue
        if key == "similarity_id":
            key = "id"
        current[key] = val
    _flush()

    if blocks_seen != len(records):
        log.warning("Parsed %d of %d suppression entries in %s — %d were skipped; "
                    "see the warnings above",
                    len(records), blocks_seen, _SUPPRESSIONS_PATH, blocks_seen - len(records))
    return records


def load_suppressions(scan_dir: str) -> set[str]:
    """Load suppression similarity IDs from .zagware/suppressions.yaml in the scanned repo.

    Returns a set of similarity_id strings to exclude from new-findings diff.

    Suppressions carrying an `expires:` date (ISO, e.g. "2026-12-31") past
    today are dropped here rather than returned as active — see QUAL-11: the
    field was documented and parsed but never actually enforced, so a
    suppression the user explicitly time-boxed lapsed silently, never. An
    unparseable expires value is not silently swallowed either: it is logged
    and the suppression stays active (the safer default — a malformed date
    should not unexpectedly re-open a finding and fail an unrelated build)
    until the entry is fixed.
    """
    records = _parse_suppressions_file(scan_dir)
    if not records:
        return set()

    today = datetime.now(timezone.utc).date()
    active: set[str] = set()
    expired_count = 0
    for sid, rec in records.items():
        expires = rec.get("expires")
        if expires:
            try:
                expiry_date = datetime.fromisoformat(expires).date()
            except ValueError:
                log.warning(
                    "Suppression %s: unparseable expires date %r — expiry not "
                    "enforced, suppression remains active until this is fixed",
                    sid[:16], expires,
                )
            else:
                if expiry_date < today:
                    expired_count += 1
                    log.info("Suppression %s expired on %s — no longer excluded from new findings",
                             sid[:16], expires)
                    continue
        active.add(sid)

    log.info("Loaded %d suppression(s) from %s (%d expired and dropped)",
             len(active), _SUPPRESSIONS_PATH, expired_count)
    return active


def render_comment(
    base: dict, pr: dict, novel: list[dict], base_label: str, head_label: str,
    collapsible: bool = True,
) -> str:
    """Render the PR comment markdown.

    collapsible=True  — wrap severity sections in <details>/<summary> (GitHub, GitLab).
    collapsible=False — use plain ### headings (Bitbucket, which ignores HTML details).
    """
    total_base = count_findings(base.get("queries", []))
    total_pr   = count_findings(pr.get("queries", []))
    total_new  = count_findings(novel)

    sev_counts: dict[str, int] = {}
    for q in novel:
        s = q.get("severity", "UNKNOWN")
        sev_counts[s] = sev_counts.get(s, 0) + len(q["files"])

    # On GitHub/GitLab/Azure the marker is a hidden HTML comment; on Bitbucket
    # (which strips HTML comments) it is an invisible CommonMark link-reference
    # definition instead. Both are emitted as the FIRST line here, not appended
    # after everything else — appending let the truncation step below cut the
    # marker off any comment over _MAX_COMMENT chars, so post_or_update_comment
    # could never find its own comment on a large Bitbucket PR and duplicated it
    # on every push. See QUAL-05.
    marker_line = _COMMENT_MARKER if collapsible else _BB_COMMENT_MARKER

    L: list[str] = (
        ([marker_line, ""] if marker_line else []) + [
            "## 🏗️ Zagware IaC — Infrastructure Misconfigurations",
            "",
            f"Comparing **`{base_label}`** → **`{head_label}`**",
            "",
            "| | Base branch | This PR | New |",
            "|---|:---:|:---:|:---:|",
            f"| Findings | {total_base} | {total_pr} | **{total_new}** |",
            "",
        ]
    )

    # Show active severity filter so reviewers know what was excluded
    if _MIN_SEVERITY and _MIN_SEVERITY in _SEVERITY_ORDER:
        L.append(f"> 🔎 Severity filter: **{_MIN_SEVERITY} and above** "
                 f"(`ZAGWARE_MIN_SEVERITY={_MIN_SEVERITY}`)")
        L.append("")

    if not novel:
        L.append("✅ **No new security findings introduced by this PR.**")
        L.append("")
    else:
        summary = " &nbsp;·&nbsp; ".join(
            f"{_SEVERITY_EMOJI.get(s, '❓')} **{sev_counts[s]}** {s}"
            for s in _SEVERITY_ORDER + sorted(k for k in sev_counts if k not in _SEVERITY_ORDER)
            if s in sev_counts
        )
        L += [
            f"> ⚠️ **{total_new} new finding(s) introduced by this PR**",
            f"> {summary}",
            "",
        ]

        # Widen past _SEVERITY_ORDER's six known tiers so a KICS severity outside
        # them (custom ZAGWARE_QUERIES_PATH query, missing key, future KICS release)
        # is still rendered instead of silently vanishing — see QUAL-14.
        for sev in _SEVERITY_ORDER + sorted(k for k in sev_counts if k not in _SEVERITY_ORDER):
            # .get("severity", "UNKNOWN") — same default used to build sev_counts
            # above; a bare .get("severity") would compare None to "UNKNOWN" and
            # never match, dropping any query with no severity key at all.
            qs = [q for q in novel if q.get("severity", "UNKNOWN") == sev]
            if not qs:
                continue
            count = sum(len(q["files"]) for q in qs)
            emoji = _SEVERITY_EMOJI.get(sev, "❓")

            # Section header — collapsible on GitHub/GitLab, plain heading on Bitbucket
            if collapsible:
                L += ["<details>",
                      f"<summary>{emoji} <strong>{sev}</strong> — {count} finding(s)</summary>",
                      ""]
            else:
                L += ["---", f"### {emoji} {sev} — {count} finding(s)", ""]

            for q in qs:
                cwe = f" &nbsp;·&nbsp; CWE-{q['cwe']}" if q.get("cwe") else ""
                ref = (f" &nbsp;·&nbsp; [Reference]({q['query_url']})"
                       if q.get("query_url") else "")
                L += [
                    f"#### {q['query_name']}",
                    f"> {q.get('description', '')}",
                    f"> `{q.get('category', '')}` &nbsp;·&nbsp; `{q.get('platform', '')}`{cwe}{ref}",
                    "",
                    "| File | Line | Resource | Issue | Expected | Actual |",
                    "|------|-----:|----------|-------|----------|--------|",
                ]
                for f in q["files"]:
                    # Every cell below is routed through _cell: file_name and
                    # resource_name come straight from the PR's own tree, and
                    # issue_type can embed resource-derived text. See SEC-06.
                    fname    = _cell(f.get("file_name", "—"))
                    resource = _cell(f.get("resource_name") or f.get("resource_type") or "—")
                    L.append(
                        f"| `{fname}` | {_cell(f.get('line', '—'), 12)} | `{resource}`"
                        f" | {_cell(f.get('issue_type', ''))}"
                        f" | {_cell(_redact_value(f.get('expected_value', '')))}"
                        f" | {_cell(_redact_value(f.get('actual_value', ''), q.get('category', '')))} |"
                    )
                L.append("")

            if collapsible:
                L += ["</details>", ""]

    return "\n".join(L)



def render_sca_section(
    base_sca: list[dict] | None, head_sca: list[dict] | None, novel_sca: list[dict],
    collapsible: bool = True,
) -> str:
    """Return the SCA block to append to the PR comment.

    Three outcomes, three renderings. They used to collapse into one silent
    empty string, so "SCA is off", "no manifests were found" and "SCA ran and
    the repo is clean" were indistinguishable. A Go monorepo using only go.mod
    (absent from _SCA_MANIFESTS) showed no SCA section at all and the user
    reasonably concluded there were no dependency vulnerabilities, when in
    fact nothing had been scanned. See QUAL-08.

      SCA disabled                -> "" (the operator turned it off; say nothing)
      enabled, both sides None    -> explicit "no manifests found — skipped"
      anything actually scanned   -> the full table, including the ✅ line, so
                                     coverage is visible even at zero findings

    run_sca_scan returns None for BOTH "disabled" and "no manifests", so the
    two are separated here by consulting _SCA_ENABLED directly rather than by
    over-reading None.
    """
    if not _SCA_ENABLED:
        return ""
    if base_sca is None and head_sca is None:
        return "\n".join([
            "", "---", "## 📦 Zagware SCA — Dependency Vulnerabilities", "",
            "> ℹ️ **No dependency manifests found — SCA skipped.** Nothing was scanned for "
            "dependency vulnerabilities; this is *not* a statement that the dependencies "
            "are clean. Supported manifests: "
            + ", ".join(f"`{m}`" for m in _SCA_MANIFESTS) + ".",
            "",
        ])
    # One side may still be None (the PR added or removed the only manifest);
    # that side genuinely had nothing to scan, so it counts as zero findings.
    base_list = base_sca or []
    head_list = head_sca or []
    by_sev: dict[str, list[dict]] = {}
    for f in novel_sca:
        by_sev.setdefault(f.get("severity", "UNKNOWN"), []).append(f)
    L = [
        "", "---", "## 📦 Zagware SCA — Dependency Vulnerabilities", "",
        "| | Base | This PR | New |",
        "|---|:---:|:---:|:---:|",
        f"| Vulnerabilities | {len(base_list)} | {len(head_list)} | **{len(novel_sca)}** |",
        "",
    ]
    if not novel_sca:
        L.append("✅ **No new dependency vulnerabilities introduced by this PR.**")
        L.append("")
    else:
        summary = " &nbsp;·&nbsp; ".join(
            f"{_SCA_SEVERITY_EMOJI.get(s, '❓')} **{len(by_sev[s])}** {s}"
            for s in _SCA_SEVERITY_ORDER + sorted(k for k in by_sev if k not in _SCA_SEVERITY_ORDER)
            if s in by_sev
        )
        L += [
            f"> ⚠️ **{len(novel_sca)} new vulnerability(ies) introduced by this PR**",
            f"> {summary}", "",
        ]
        # Widen past the known buckets so a future/unrecognised Grype severity
        # string is counted-and-rendered together, never counted-but-invisible.
        for sev in _SCA_SEVERITY_ORDER + sorted(k for k in by_sev if k not in _SCA_SEVERITY_ORDER):
            findings = by_sev.get(sev, [])
            if not findings:
                continue
            emoji = _SCA_SEVERITY_EMOJI.get(sev, "❓")
            if collapsible:
                L += [
                    "<details>",
                    f"<summary>{emoji} <strong>{sev}</strong> — {len(findings)} finding(s)</summary>",
                    "",
                ]
            else:
                L += ["---", f"### {emoji} {sev} — {len(findings)} finding(s)", ""]
            L += [
                "| CVE / Advisory | Package | Installed | Fix | CVSS | KEV |",
                "|---|---|:---:|:---:|:---:|:---:|",
            ]
            for f in sorted(findings, key=lambda x: -(x.get("cvss_score") or 0)):
                vuln_url = f["vuln_urls"][0] if f.get("vuln_urls") else ""
                vuln_id  = _cell(f.get("vulnerability_id", ""), 60)
                cve_cell = f"[{vuln_id}]({vuln_url})" if vuln_url else vuln_id
                fix = ", ".join(f["fix_versions"]) or f["fix_state"]
                cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "—"
                kev  = "🔴 Yes" if f.get("kev_listed") else "No"
                # package_name/version/type all come from a lockfile the PR
                # controls, so they are sanitised like any other PR input.
                pkg  = _cell(f"{f.get('package_name', '')} ({f.get('package_type', '')})")
                L.append(
                    f"| {cve_cell} | `{pkg}` | `{_cell(f.get('package_version', ''), 40)}` "
                    f"| `{_cell(fix, 40)}` | {cvss} | {kev} |"
                )
            if collapsible:
                L += ["", "</details>", ""]
            else:
                L.append("")
    return "\n".join(L)


def render_secrets_section(
    base_secrets: list[dict] | None, head_secrets: list[dict] | None, novel_secrets: list[dict],
    repo_visibility: str, collapsible: bool = True,
) -> str:
    """Return the Secrets block to append to the PR comment. Empty string if no
    secrets data.

    Betterleaks has no severity taxonomy, so unlike the IaC/SCA sections there is
    no per-severity breakdown. Instead, an exposure banner is shown when new
    secrets were found: a "public repo" banner when repo_visibility == "public"
    (a leaked credential there is immediately exposed to the world, the priority
    signal used in place of severity — see Platform.repo_visibility()), or an
    "unknown" banner when visibility could not be determined at all — see
    QUAL-02: ZAGWARE_SECRETS_FAIL_ON_PUBLIC applies conservatively in that case,
    and the comment says so rather than leaving that only in the build log.

    Like the SCA section, this distinguishes three outcomes rather than
    collapsing them into one empty string: both None means secrets scanning is
    disabled (say nothing), otherwise the table renders — including the ✅
    line at zero findings — so coverage is visible. See QUAL-08.

    Never renders the secret value itself — only rule_id/file_path/line/tags/
    validation_status, matching what run_secrets_scan() reads from the report.
    """
    if not _SECRETS_ENABLED:
        return ""
    base_list = base_secrets or []
    head_list = head_secrets or []
    L = [
        "", "---", "## 🔑 Zagware Secrets — Leaked Credentials", "",
        "| | Base | This PR | New |",
        "|---|:---:|:---:|:---:|",
        f"| Findings | {len(base_list)} | {len(head_list)} | **{len(novel_secrets)}** |",
        "",
    ]
    if not novel_secrets:
        L.append("✅ **No new secrets introduced by this PR.**")
        L.append("")
        return "\n".join(L)

    if repo_visibility == "public":
        L += [
            "> 🌐 **PUBLIC REPOSITORY** — any leaked secret here is immediately exposed to the "
            "world. Rotate affected credentials before merging.",
            "",
        ]
    elif repo_visibility == "unknown":
        L += [
            "> ⚠️ **Repository visibility could not be determined** — public-repo rules "
            "(`ZAGWARE_SECRETS_FAIL_ON_PUBLIC`) were applied conservatively for this scan. "
            "Set `ZAGWARE_ASSUME_PRIVATE=true` to opt out.",
            "",
        ]
    L += [f"> 🔴 **{len(novel_secrets)} new secret(s) introduced by this PR**", ""]

    if collapsible:
        L += ["<details>",
              f"<summary>🔑 <strong>Secrets</strong> — {len(novel_secrets)} finding(s)</summary>", ""]
    else:
        L += ["---", f"### 🔑 Secrets — {len(novel_secrets)} finding(s)", ""]
    L += [
        "| Rule | File | Line | Validation |",
        "|---|---|:---:|:---:|",
    ]
    _VALIDATION_CELL = {"valid": "🔴 Valid", "invalid": "⚪ Invalid", "unknown": "❓ Unknown"}
    for f in novel_secrets:
        # rule_id and tags come from betterleaks' config, file_path from the
        # PR's own tree -- all sanitised. See SEC-06.
        tags = ", ".join(f.get("tags") or [])
        rule_cell = _cell(f.get("rule_id", "") + (f" ({tags})" if tags else ""))
        vs_cell = _VALIDATION_CELL.get(f.get("validation_status", "unknown"), "❓ Unknown")
        L.append(f"| `{rule_cell}` | `{_cell(f.get('file_path', ''))}` "
                 f"| {_cell(f.get('line', '—'), 12)} | {vs_cell} |")
    if collapsible:
        L += ["", "</details>"]
    L += [
        "",
        "> ⚠️ Never paste the secret value in a PR comment — rotate the credential, "
        "then remove it from the code.",
    ]
    return "\n".join(L)


def render_suppression_hints(
    novel: list[dict], novel_sca: list[dict], novel_secrets: list[dict] | None = None,
    collapsible: bool = True,
) -> str:
    """Render a collapsible section listing similarity IDs for /zagware suppress commands.

    Covers IaC (novel), SCA (novel_sca), and Secrets (novel_secrets) findings. IDs are
    shown as a 16-char prefix; the scanner resolves prefixes >=6 chars against real
    findings, so the truncated display is always safe to copy-paste.
    """
    items: list[tuple[str, str, str]] = []  # (similarity_id, description, location)
    for q in novel:
        for f in q.get("files", []):
            items.append((
                f.get("similarity_id", ""),
                q.get("query_name", "")[:60],
                f.get("file_name", ""),
            ))
    for f in novel_sca:
        items.append((
            f.get("similarity_id", ""),
            f"{f.get('vulnerability_id', '')} in {f.get('package_name', '')}",
            f.get("file_path", "") or f.get("package_name", ""),
        ))
    for f in (novel_secrets or []):
        items.append((
            f.get("similarity_id", ""),
            f.get("rule_id", ""),
            f.get("file_path", ""),
        ))
    if not items:
        return ""

    L: list[str] = []
    if collapsible:
        L += ["", "<details>", "<summary>📋 Suppress findings</summary>", ""]
    else:
        L += ["", "---", "### 📋 Suppress findings", ""]
    L += [
        "To suppress a finding, comment on this PR:",
        "",
        "```",
        "/zagware suppress <id> <reason>",
        "```",
        "",
        "The id can be the first 6+ characters shown below — no need to copy the full hash.",
        "",
        "**Available IDs from this scan:**",
        "",
    ]
    for sim, desc, loc in items[:100]:
        # desc/loc are finding- and path-derived, i.e. PR-controlled. `short`
        # is a hex similarity_id but is sanitised too rather than trusted on
        # the assumption that it always will be. See SEC-06.
        short = _cell(sim[:16], 16) if sim else "?"
        L.append(f"- `{short}` — {_cell(desc)} (`{_cell(loc)}`)")
    if len(items) > 100:
        L.append(f"\n_… and {len(items) - 100} more (see scan artifacts for full list)_")
    L.append("")
    if collapsible:
        L += ["</details>", ""]
    return "\n".join(L)


# ── Suppression audit trail (platform upload) ───────────────────────────────────

def collect_suppression_records(
    pr_dir: str,
    pr_results: dict,
    head_sca: list[dict] | None,
    head_secrets: list[dict] | None,
    suppressed_ids: set[str],
    just_suppressed: list[tuple[str, str, str, str]],
) -> list[dict]:
    """Build one audit record per currently-active suppression: who added it, when,
    why, and which finding it covers.

    Attribution has exactly ONE verified tier, deliberately:

      1. just_suppressed — a /zagware suppress command the scanner itself
         resolved and pushed in THIS run. The author came from the platform's
         own comment API and the authorization check in
         parse_suppression_commands, so it is evidence.
         -> added_via = "pr_comment", added_by = the verified author.

      2. Everything else — an entry already present in suppressions.yaml. That
         file arrives via a PR the author controls, so its suppressed_by field
         is a self-declared *claim*, not evidence: a contributor can hand-write
         `suppressed_by: "trusted-maintainer"` and previously received a record
         indistinguishable from tier 1.
         -> added_via = "file_unverified", added_by = "unknown",
            claimed_by = the unverified self-declared value (or None).

    The former third tier — `git blame` on suppressions.yaml — has been removed
    rather than relabelled. The scanner clones with --depth=1, so blame
    attributes EVERY line to the single checked-out commit; it credited
    whoever pushed last for suppressions added long before, which is worse than
    no attribution because it looks authoritative. See SEC-10.

    Uploaded to the platform (see upload_suppressions_to_platform) so suppressions
    are auditable by repo/PR/user, and so widely-suppressed findings across many
    repos surface as candidates for tightening the underlying IaC/SCA/Secrets policy.
    """
    finding_info: dict[str, tuple[str, str, str]] = {}
    for q in pr_results.get("queries", []):
        for f in q.get("files", []):
            sid = f.get("similarity_id", "")
            if sid:
                finding_info[sid] = (q.get("query_name", ""), f.get("file_name", ""), "iac")
    for f in (head_sca or []):
        sid = f.get("similarity_id", "")
        if sid:
            finding_info[sid] = (
                f"{f.get('vulnerability_id', '')} in {f.get('package_name', '')}",
                f.get("file_path", "") or f.get("package_name", ""),
                "sca",
            )
    for f in (head_secrets or []):
        sid = f.get("similarity_id", "")
        if sid:
            finding_info[sid] = (f.get("rule_id", ""), f.get("file_path", ""), "secrets")

    file_records = _parse_suppressions_file(pr_dir)
    just_by_id = {sid: (reason, author, created_at)
                  for sid, reason, author, created_at in just_suppressed}

    records: list[dict] = []
    for sid in suppressed_ids:
        finding_name, file_path, category = finding_info.get(sid, (None, None, None))
        claimed_by: str | None = None
        if sid in just_by_id:
            reason, added_by, added_at = just_by_id[sid]
            added_via = "pr_comment"
        else:
            rec = file_records.get(sid, {})
            reason = rec.get("reason") or ""
            added_at = rec.get("added_at")
            # Repo-supplied and therefore unverified — surfaced separately so
            # the platform can render it as a claim rather than a fact, and so
            # an auditor can always tell the two tiers apart. See SEC-10.
            claimed_by = rec.get("added_by")
            added_by = None
            added_via = "file_unverified"
        records.append({
            "category":      category or "unknown",
            "similarity_id": sid,
            "finding_name":  finding_name,
            "file_path":     file_path,
            "reason":        reason,
            "added_by":      added_by or "unknown",
            "claimed_by":    claimed_by,
            "added_via":     added_via,
            "added_at":      added_at or None,
        })
    return records


def upload_suppressions_to_platform(
    platform_url: str, platform_token: str,
    repo: str, pr_number: int | None,
    records: list[dict],
) -> None:
    """Upload the current suppression audit trail to the GTP platform. Non-fatal if
    this fails — the PR comment and exit code never depend on it."""
    if not records:
        return
    try:
        headers = {'Authorization': f'Bearer {platform_token}', 'Content-Type': 'application/json'}
        payload = {
            'repo': repo,
            'pr_number': pr_number,
            'scanner_version': __version__,
            'suppressions': records,
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            f'{platform_url}/api/v1/suppressions/upload',
            data=data, headers=headers, method='POST',
        )
        with _urlopen(req) as resp:
            resp.read()
        log.info('Suppression audit uploaded to platform (%d record(s))', len(records))
    except Exception as e:
        log.warning('Failed to upload suppression audit to platform: %s', e)


# ── Platform upload ────────────────────────────────────────────────────────────

def upload_to_platform(
    platform_url: str,
    platform_token: str,
    repo: str,
    base_branch: str,
    base_sha: str,
    head_branch: str,
    head_sha: str,
    pr_number: int | None,
    base_results: dict,
    head_results: dict,
) -> None:
    """Upload scan results to the GTP platform. Non-fatal if this fails."""
    try:
        headers = {
            'Authorization': f'Bearer {platform_token}',
            'Content-Type': 'application/json',
        }

        def post(payload_dict: dict) -> dict:
            data = json.dumps(payload_dict).encode('utf-8')
            req = urllib.request.Request(
                f'{platform_url}/api/v1/iac/upload',
                data=data,
                headers=headers,
                method='POST',
            )
            with _urlopen(req) as resp:
                return json.loads(resp.read().decode('utf-8'))

        # 1. Upload base scan
        base_payload = {
            'repo': repo,
            'branch': base_branch,
            'commit_sha': base_sha or None,
            'scan_type': 'pr_base' if pr_number else 'branch',
            'pr_number': pr_number,
            'pr_comparison_id': None,
            'scanner_version': __version__,
            'results': base_results,
            'repo_base_url': _repo_base_url() or None,
        }
        base_resp    = post(base_payload)
        base_scan_id = base_resp.get('scan_id')

        # 2. Upload head scan (only for PR scans)
        if pr_number and base_scan_id:
            head_payload = {
                'repo': repo,
                'branch': head_branch,
                'commit_sha': head_sha or None,
                'scan_type': 'pr_head',
                'pr_number': pr_number,
                'pr_comparison_id': base_scan_id,
                'scanner_version': __version__,
                'results': head_results,
                'repo_base_url': _repo_base_url() or None,
            }
            post(head_payload)

        print(f'[zagware] Scan results uploaded to platform (base scan: {base_scan_id})',
              file=sys.stderr)

    except Exception as e:
        print(f'[zagware] Warning: failed to upload scan results to platform: {e}',
              file=sys.stderr)

def upload_sca_to_platform(
    platform_url: str, platform_token: str,
    repo: str, base_branch: str, head_branch: str,
    pr_number: int | None,
    base_findings: list[dict], head_findings: list[dict],
) -> None:
    """Upload SCA results to the GTP platform. Non-fatal if this fails."""
    try:
        headers = {
            'Authorization': f'Bearer {platform_token}',
            'Content-Type': 'application/json',
        }

        def _post(payload: dict) -> dict:
            data = json.dumps(payload).encode('utf-8')
            req  = urllib.request.Request(
                f'{platform_url}/api/v1/sca/upload',
                data=data, headers=headers, method='POST',
            )
            with _urlopen(req) as resp:
                return json.loads(resp.read().decode('utf-8'))

        base_resp    = _post({'repo': repo, 'branch': base_branch,
                              'scan_type': 'pr_base' if pr_number else 'branch',
                              'pr_number': pr_number, 'pr_comparison_id': None,
                              'scanner_name': 'grype', 'findings': base_findings,
                              'repo_base_url': _repo_base_url() or None})
        base_scan_id = base_resp.get('scan_id')
        if pr_number and base_scan_id:
            _post({'repo': repo, 'branch': head_branch,
                   'scan_type': 'pr_head', 'pr_number': pr_number,
                   'pr_comparison_id': base_scan_id,
                   'scanner_name': 'grype', 'findings': head_findings,
                   'repo_base_url': _repo_base_url() or None})
        log.info('SCA results uploaded to platform (base: %s)', base_scan_id)
    except Exception as e:
        log.warning('Failed to upload SCA results to platform: %s', e)

def upload_secrets_to_platform(
    platform_url: str, platform_token: str,
    repo: str, base_branch: str, head_branch: str,
    pr_number: int | None, repo_visibility: str,
    base_findings: list[dict], head_findings: list[dict],
) -> None:
    """Upload secrets scan results to the GTP platform. Non-fatal if this fails."""
    try:
        headers = {
            'Authorization': f'Bearer {platform_token}',
            'Content-Type': 'application/json',
        }

        def _post(payload: dict) -> dict:
            data = json.dumps(payload).encode('utf-8')
            req  = urllib.request.Request(
                f'{platform_url}/api/v1/secrets/upload',
                data=data, headers=headers, method='POST',
            )
            with _urlopen(req) as resp:
                return json.loads(resp.read().decode('utf-8'))

        base_resp = _post({
            'repo': repo, 'branch': base_branch,
            'scan_type': 'pr_base' if pr_number else 'branch',
            'pr_number': pr_number, 'pr_comparison_id': None,
            'scanner_version': __version__,
            'repo_visibility': repo_visibility,
            'repo_base_url': _repo_base_url() or None,
            'findings': base_findings,
        })
        base_scan_id = base_resp.get('scan_id')
        if pr_number and base_scan_id:
            _post({
                'repo': repo, 'branch': head_branch,
                'scan_type': 'pr_head', 'pr_number': pr_number,
                'pr_comparison_id': base_scan_id,
                'scanner_version': __version__,
                'repo_visibility': repo_visibility,
                'repo_base_url': _repo_base_url() or None,
                'findings': head_findings,
            })
        log.info('Secrets results uploaded to platform (base: %s)', base_scan_id)
    except Exception as e:
        log.warning('Failed to upload secrets results to platform: %s', e)

# ── Main ───────────────────────────────────────────────────────────────────────

def _write_artifacts(
    out_dir: str,
    comment: str,
    base_results: dict,
    pr_results: dict,
    base_sca: list[dict] | None,
    head_sca: list[dict] | None,
    novel_sca: list[dict],
    base_secrets: list[dict] | None,
    head_secrets: list[dict] | None,
    novel_secrets: list[dict],
    timings: dict[str, float],
    meta: dict,
) -> None:
    """Write scan evidence to out_dir. Non-fatal: logs warning on any error."""
    try:
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)

        # IaC findings (redacted KICS JSON — actual_value masked to prevent secret leakage)
        (d / "iac-base.json").write_text(
            json.dumps(_redact_kics_results(base_results), indent=2, ensure_ascii=False), encoding="utf-8")
        (d / "iac-head.json").write_text(
            json.dumps(_redact_kics_results(pr_results),  indent=2, ensure_ascii=False), encoding="utf-8")

        # SCA findings (normalized Grype output)
        (d / "sca-base.json").write_text(
            json.dumps(base_sca or [], indent=2, ensure_ascii=False), encoding="utf-8")
        (d / "sca-head.json").write_text(
            json.dumps(head_sca or [], indent=2, ensure_ascii=False), encoding="utf-8")
        (d / "sca-new.json").write_text(
            json.dumps(novel_sca, indent=2, ensure_ascii=False), encoding="utf-8")

        # Secrets findings (redaction unnecessary — run_secrets_scan() never carries
        # the raw secret value in the first place, only rule_id/file_path/line/tags)
        (d / "secrets-base.json").write_text(
            json.dumps(base_secrets or [], indent=2, ensure_ascii=False), encoding="utf-8")
        (d / "secrets-head.json").write_text(
            json.dumps(head_secrets or [], indent=2, ensure_ascii=False), encoding="utf-8")
        (d / "secrets-new.json").write_text(
            json.dumps(novel_secrets, indent=2, ensure_ascii=False), encoding="utf-8")

        # Rendered PR comment (markdown)
        (d / "pr-comment.md").write_text(comment, encoding="utf-8")

        # Timing + metadata summary
        summary = {**meta, "timings_seconds": {k: round(v, 2) for k, v in timings.items()}}
        (d / "summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

        log.info("Artifacts written to %s/ (%d files)",
                 out_dir, len(list(d.iterdir())))
    except Exception as exc:
        log.warning("Failed to write artifacts: %s", exc)


def _secrets_public_gate(repo_visibility: str, has_novel_secrets: bool) -> tuple[bool, str | None]:
    """Decide whether new secrets should force exit_code=1 under
    ZAGWARE_SECRETS_FAIL_ON_PUBLIC, and which reason applies.

    Pure decision function (no I/O, no subprocess, no network) so the
    fail-closed behaviour is unit-testable in isolation from the rest of
    main()'s clone/scan machinery: "unknown" visibility is treated the same
    as "public" (fail closed) unless the operator explicitly opts out via
    ZAGWARE_ASSUME_PRIVATE — a transient API error or missing permission must
    not silently disable this guarantee. See QUAL-02 in REVIEW-2026-07-30.md.

    Returns (should_fail, reason) where reason is "public", "unknown", or None.
    """
    if not _SECRETS_FAIL_ON_PUBLIC or not has_novel_secrets:
        return False, None
    if repo_visibility == "public":
        return True, "public"
    if repo_visibility == "unknown" and not _ASSUME_PRIVATE:
        return True, "unknown"
    return False, None


def main() -> int:
    t_start = time.perf_counter()
    log.info("Zagware IaC Scanner starting")

    # Detect platform
    platform: Platform | None = next(
        (p for p in _PLATFORMS if p.detected()), None
    )
    if platform is None:
        log.error(
            "No supported CI platform detected. "
            "Expected one of: GITHUB_ACTIONS=true, GITLAB_CI=true, "
            "BITBUCKET_BUILD_NUMBER, or TF_BUILD=True"
        )
        track_scan_failed("unknown", "", "no_platform_detected")
        return 1
    log.info("Platform: %s", platform.name())
    if _MIN_SEVERITY:
        below = _severities_below()
        if not below and _MIN_SEVERITY not in _SEVERITY_ORDER:
            log.error("Invalid ZAGWARE_MIN_SEVERITY='%s' — must be one of: %s",
                      _MIN_SEVERITY, ", ".join(_SEVERITY_ORDER))
            track_scan_failed(platform.name(), platform.repo(), "invalid_config")
            return 1
        log.info("Severity filter: %s and above (excluding %s)",
                 _MIN_SEVERITY, ", ".join(below) if below else "nothing")
    if _FAIL_ON_NEW:
        log.info("ZAGWARE_FAIL_ON_NEW=true — build will fail on new findings")

    # A PR context is a hard precondition: the scanner's entire output is a
    # diff of the head against the base. Checked BEFORE clone_url() or
    # base_branch(), because those are exactly what blew up differently on
    # each platform -- an empty --branch on GitHub, an unhandled KeyError on
    # GitLab/Bitbucket, and on Azure a silent fallback to the literal "main"
    # that produced a permanently green build diffing main against itself.
    # See QUAL-09.
    if not platform.is_pr_pipeline():
        log.error(
            "Not a pull/merge request pipeline — the scanner compares a PR against its "
            "base branch and has nothing to diff here. Detected platform: %s. "
            "Run it on a pull_request / merge_request trigger.", platform.name(),
        )
        track_scan_failed(platform.name(), platform.repo(), "not_a_pr_pipeline")
        return 1

    try:
        clone_url   = platform.clone_url()
        base_branch = platform.base_branch()
        head_branch = platform.head_branch()
    except KeyError as exc:
        # Name the missing variable instead of surfacing a bare KeyError.
        log.error("Required %s environment variable is not set: %s",
                  platform.name(), exc.args[0] if exc.args else exc)
        track_scan_failed(platform.name(), platform.repo(), "missing_env_var")
        return 1
    log.info("Repository: %s", clone_url.split("@", 1)[-1])  # redact credentials
    log.info("Base → %s  |  Head → %s", base_branch, head_branch)

    _has_platform = bool(os.environ.get('ZAGWARE_PLATFORM_URL')) and bool(os.environ.get('ZAGWARE_PLATFORM_TOKEN'))
    track_scan_started(
        platform.name(), platform.repo(), platform.pr_number() is not None,
        _SCA_ENABLED, _has_platform, _MIN_SEVERITY, _FAIL_ON_NEW, _SECRETS_ENABLED,
    )

    timings: dict[str, float] = {}

    with tempfile.TemporaryDirectory() as tmp:
        base_dir  = f"{tmp}/base"
        pr_dir    = f"{tmp}/pr"
        base_json = f"{tmp}/base.json"
        pr_json   = f"{tmp}/pr.json"

        # ── Clone ────────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        log.info("Cloning base branch '%s'…", base_branch)
        try:
            clone_branch(clone_url, base_branch, base_dir)
        except subprocess.CalledProcessError as exc:
            log.error("Clone failed for base branch: %s", exc.stderr)
            track_scan_failed(platform.name(), platform.repo(), "clone")
            return 1

        log.info("Cloning PR branch '%s'…", head_branch)
        try:
            clone_branch(clone_url, head_branch, pr_dir)
        except subprocess.CalledProcessError:
            log.debug("Branch clone failed — attempting SHA checkout")
            try:
                clone_and_checkout_sha(clone_url, base_branch, head_branch, pr_dir)
            except subprocess.CalledProcessError as exc:
                log.error("Clone failed for PR branch/SHA: %s", exc.stderr)
                track_scan_failed(platform.name(), platform.repo(), "clone")
                return 1
        timings["clone"] = time.perf_counter() - t0

        # ── Load existing suppressions from PR branch ────────────────────────
        suppressed_ids = load_suppressions(pr_dir)

        # ── IaC scan ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        log.info("Scanning base branch…")
        try:
            base_results = run_scan(base_dir, base_json)
        except RuntimeError as exc:
            log.error("IaC scan failed for base branch: %s", exc)
            track_scan_failed(platform.name(), platform.repo(), "iac_scan")
            return 1
        base_count   = count_findings(base_results.get("queries", []))
        log.info("Base: %d finding(s)", base_count)
        timings["iac_base"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        log.info("Scanning PR branch…")
        try:
            pr_results = run_scan(pr_dir, pr_json)
        except RuntimeError as exc:
            log.error("IaC scan failed for PR branch: %s", exc)
            track_scan_failed(platform.name(), platform.repo(), "iac_scan")
            return 1
        pr_count   = count_findings(pr_results.get("queries", []))
        log.info("PR:   %d finding(s)", pr_count)
        timings["iac_head"] = time.perf_counter() - t0

        # ── Platform upload (IaC) ─────────────────────────────────────────────
        # Validated, not just read: an http:// URL would put the bearer token
        # on the wire in cleartext. A rejected URL returns "" so every
        # `if _platform_url and _platform_token` guard below skips cleanly and
        # the scan itself is unaffected. See SEC-05.
        _platform_url   = _validate_platform_url(
            os.environ.get('ZAGWARE_PLATFORM_URL', '').rstrip('/'))
        _platform_token = os.environ.get('ZAGWARE_PLATFORM_TOKEN', '')
        if _platform_url and _platform_token:
            t0 = time.perf_counter()
            upload_to_platform(
                _platform_url, _platform_token,
                platform.repo(),
                base_branch, platform.base_sha(), head_branch, platform.head_sha(),
                platform.pr_number(),
                _redact_kics_results(base_results), _redact_kics_results(pr_results),
            )
            timings["platform_upload_iac"] = time.perf_counter() - t0

        # ── SCA ──────────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        try:
            base_sca = run_sca_scan(base_dir, tmp, "base")
        except ScanFailure as exc:
            log.error("SCA scan failed for base branch: %s", exc)
            track_scan_failed(platform.name(), platform.repo(), "sca_scan")
            return 1
        timings["sca_base"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        try:
            head_sca = run_sca_scan(pr_dir, tmp, "pr")
        except ScanFailure as exc:
            log.error("SCA scan failed for PR branch: %s", exc)
            track_scan_failed(platform.name(), platform.repo(), "sca_scan")
            return 1
        timings["sca_head"] = time.perf_counter() - t0

        # (novel_sca computed later in the Diff section, after suppression commands resolve)

        if _platform_url and _platform_token and (base_sca is not None or head_sca is not None):
            t0 = time.perf_counter()
            upload_sca_to_platform(
                _platform_url, _platform_token,
                platform.repo(),
                base_branch, head_branch,
                platform.pr_number(),
                base_sca or [], head_sca or [],
            )
            timings["platform_upload_sca"] = time.perf_counter() - t0

        # ── Secrets (betterleaks) ───────────────────────────────────────────────
        t0 = time.perf_counter()
        try:
            base_secrets = run_secrets_scan(base_dir, tmp, "base")
        except ScanFailure as exc:
            log.error("Secrets scan failed for base branch: %s", exc)
            track_scan_failed(platform.name(), platform.repo(), "secrets_scan")
            return 1
        timings["secrets_base"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        try:
            head_secrets = run_secrets_scan(pr_dir, tmp, "pr")
        except ScanFailure as exc:
            log.error("Secrets scan failed for PR branch: %s", exc)
            track_scan_failed(platform.name(), platform.repo(), "secrets_scan")
            return 1
        timings["secrets_head"] = time.perf_counter() - t0

        # Only pay for the visibility lookup (an API call on GitHub/Bitbucket/Azure)
        # when secrets scanning actually ran.
        repo_visibility = "unknown"
        if base_secrets is not None or head_secrets is not None:
            repo_visibility = platform.repo_visibility()
            if repo_visibility == "public":
                log.warning("Repository visibility: PUBLIC — leaked secrets here are immediately exposed")
            else:
                log.info("Repository visibility: %s", repo_visibility)

        # (novel_secrets computed later in the Diff section, after suppression commands resolve)

        if _platform_url and _platform_token and (base_secrets is not None or head_secrets is not None):
            t0 = time.perf_counter()
            upload_secrets_to_platform(
                _platform_url, _platform_token,
                platform.repo(),
                base_branch, head_branch,
                platform.pr_number(), repo_visibility,
                base_secrets or [], head_secrets or [],
            )
            timings["platform_upload_secrets"] = time.perf_counter() - t0

        # ── Diff ─────────────────────────────────────────────────────────────
        novel     = new_findings(base_results, pr_results, suppressed_ids)
        novel_sca = new_sca_findings(base_sca, head_sca, suppressed_ids)
        novel_secrets = new_secrets_findings(base_secrets, head_secrets, suppressed_ids)

        # ── Check for interactive suppression commands in PR comments ────────
        # Resolve against THIS scan's novel findings (both IaC and SCA), apply,
        # then recompute novel/novel_sca so the same run reflects the result —
        # relying on the push to auto-retrigger doesn't work (GITHUB_TOKEN pushes
        # don't fire new workflow runs on GitHub).
        just_suppressed: list[tuple[str, str, str, str]] = []  # (id, reason, author, created_at)
        suppression_failure = ""  # non-empty -> surfaced in the comment (QUAL-18)
        if platform.pr_number() is not None:
            try:
                comments = _filter_authorized_comments(platform.read_pr_comments())
                commands = parse_suppression_commands(comments)
                resolved: list[tuple[str, str, str, str]] = []
                for raw_id, reason, author, created_at in commands:
                    outcome, full_id, n = resolve_suppression_id(
                        raw_id, novel, novel_sca, novel_secrets)
                    if outcome == "resolved":
                        resolved.append((full_id, reason, author, created_at))
                    elif outcome == "ambiguous":
                        # Distinct from not-found: the user needs more
                        # characters, not a different id. See QUAL-17.
                        log.warning(
                            "Suppress id '%s' is ambiguous — matches %d findings; "
                            "use more characters", raw_id, n,
                        )
                    elif not any(s.startswith(raw_id) for s in suppressed_ids):
                        # Compare by PREFIX: the comment displays 16-char
                        # prefixes and tells users 6+ is enough, while
                        # suppressed_ids holds full 64-char hashes. The old
                        # `raw_id not in suppressed_ids` was therefore never
                        # true for a copy-pasted id, so an already-suppressed
                        # finding logged this warning on every run forever --
                        # 12 suppressions meant 12 spurious WARNINGs per push,
                        # burying the real ones at the same level. See QUAL-17.
                        log.warning(
                            "Suppress command '%s' doesn't match any current finding "
                            "(already fixed or a bad id)", raw_id,
                        )
                if resolved:
                    log.info("Resolved %d suppression command(s)", len(resolved))
                    outcome, detail = apply_suppression_commands(
                        pr_dir, clone_url, head_branch, resolved)
                    if outcome == "applied":
                        suppressed_ids |= {sid for sid, _, _, _ in resolved}
                        just_suppressed = resolved
                        track_suppression_applied(platform.name(), platform.repo(), len(resolved))
                        novel     = new_findings(base_results, pr_results, suppressed_ids)
                        novel_sca = new_sca_findings(base_sca, head_sca, suppressed_ids)
                        novel_secrets = new_secrets_findings(base_secrets, head_secrets, suppressed_ids)
                        log.info("Applied — recomputed: %d IaC new, %d SCA new, %d Secrets new",
                                 count_findings(novel), len(novel_sca), len(novel_secrets))
                    elif outcome == "failed":
                        # Surfaced in the comment below, not just the log: the
                        # requesting user is looking at the PR, and a silent
                        # failure here is indistinguishable from the feature
                        # being broken. See QUAL-18.
                        suppression_failure = detail
            except Exception as exc:
                log.warning("Failed to process suppression commands: %s", exc)

        new_count = count_findings(novel)
        log.info("New:  %d finding(s)", new_count)
        if suppressed_ids:
            log.info("Suppressed: %d finding(s) (see .zagware/suppressions.yaml)", len(suppressed_ids))
            if _platform_url and _platform_token:
                t0 = time.perf_counter()
                suppression_records = collect_suppression_records(
                    pr_dir, pr_results, head_sca, head_secrets, suppressed_ids, just_suppressed,
                )
                upload_suppressions_to_platform(
                    _platform_url, _platform_token,
                    platform.repo(), platform.pr_number(),
                    suppression_records,
                )
                timings["platform_upload_suppressions"] = time.perf_counter() - t0

        comment = ""
        if suppression_failure:
            # The PR comment is the only surface the requesting user is
            # looking at. Without this the comment came back byte-identical
            # and they concluded the feature was broken. See QUAL-18.
            comment += (
                f"> ⚠️ **Could not record suppression(s)** — the push to "
                f"`{_cell(head_branch, 60)}` was rejected: {_cell(suppression_failure, 300)}\n"
                f">\n"
                f"> Grant the job `contents: write`, check branch protection, or add the "
                f"entries to `.zagware/suppressions.yaml` manually. **The suppression was "
                f"NOT saved and will not apply on future runs.**\n\n"
            )
        if just_suppressed:
            ids_str = ", ".join(f"`{sid[:16]}`" for sid, _, _, _ in just_suppressed[:5])
            comment += (
                f"> ✅ **{len(just_suppressed)} finding(s) suppressed** via `/zagware suppress` "
                f"— {ids_str} — committed to `.zagware/suppressions.yaml`\n\n"
            )
        comment += render_comment(
            base_results, pr_results, novel,
            platform.base_label(), platform.head_label(),
            collapsible=platform.supports_html_details(),
        )
        comment += render_sca_section(
            base_sca, head_sca, novel_sca,
            collapsible=platform.supports_html_details(),
        )
        comment += render_secrets_section(
            base_secrets, head_secrets, novel_secrets,
            repo_visibility,
            collapsible=platform.supports_html_details(),
        )
        if platform.supports_interactive_suppression():
            comment += render_suppression_hints(
                novel, novel_sca, novel_secrets,
                collapsible=platform.supports_html_details(),
            )

        # Single attribution footer for the whole comment (not per-section) — a
        # blank line always precedes "---" here so it can never be misread as a
        # CommonMark Setext heading underline for the preceding line's text.
        comment += (
            "\n\n---\n<sub>Zagware Scanner &nbsp;·&nbsp; "
            "[zagware/zagware-scanner](https://github.com/zagware/zagware-scanner)</sub>"
        )
        # (No Bitbucket marker append here -- render_comment already emits
        # _BB_COMMENT_MARKER as the FIRST line for non-collapsible platforms,
        # so it survives the truncation below. See QUAL-05.)

        # Truncate the combined comment (IaC + SCA + Secrets) to platform limit
        if len(comment) > _MAX_COMMENT:
            note = "\n\n> ⚠️ _Comment truncated — run locally for full output._"
            comment = comment[: _MAX_COMMENT - len(note)] + note

        # ── Save artifacts ────────────────────────────────────────────────────
        timings["total"] = time.perf_counter() - t_start
        meta = {
            "repo":        platform.repo(),
            "base_branch": base_branch,
            "head_branch": head_branch,
            "pr_number":   platform.pr_number(),
            "repo_visibility": repo_visibility,
            "iac_base_findings": base_count,
            "iac_head_findings": pr_count,
            "iac_new_findings":  count_findings(novel),
            "sca_base_findings": len(base_sca)  if base_sca  is not None else None,
            "sca_head_findings": len(head_sca)  if head_sca  is not None else None,
            "sca_new_findings":  len(novel_sca),
            "secrets_base_findings": len(base_secrets) if base_secrets is not None else None,
            "secrets_head_findings": len(head_secrets) if head_secrets is not None else None,
            "secrets_new_findings":  len(novel_secrets),
        }
        _write_artifacts(
            _OUTPUT_DIR, comment,
            base_results, pr_results,
            base_sca, head_sca, novel_sca,
            base_secrets, head_secrets, novel_secrets,
            timings, meta,
        )

        # ── Print timing summary ──────────────────────────────────────────────
        log.info("Timings:")
        labels = {
            "clone":                "  Clone",
            "iac_base":             "  IaC base",
            "iac_head":             "  IaC head",
            "sca_base":             "  SCA base (Syft+Grype)",
            "sca_head":             "  SCA head (Syft+Grype)",
            "secrets_base":         "  Secrets base (betterleaks)",
            "secrets_head":         "  Secrets head (betterleaks)",
            "platform_upload_iac":          "  Platform upload (IaC)",
            "platform_upload_sca":          "  Platform upload (SCA)",
            "platform_upload_secrets":      "  Platform upload (Secrets)",
            "platform_upload_suppressions": "  Platform upload (Suppressions)",
            "total":                "  Total",
        }
        for key, label in labels.items():
            if key in timings:
                log.info("%s: %.1fs", label, timings[key])

        # ── Post comment ──────────────────────────────────────────────────────
        if platform.pr_number() is not None:
            try:
                platform.post_or_update_comment(comment)
            except Exception as exc:
                log.error("Failed to post comment: %s", exc)
                track_scan_failed(platform.name(), platform.repo(), "comment_post")
                return 1
        else:
            log.info("No PR detected — skipping comment post")

    # ── Fail-on-new gate (IaC + SCA + Secrets combined) ───────────────────────
    new_total  = new_count + len(novel_sca) + len(novel_secrets)
    exit_code  = 1 if (_FAIL_ON_NEW and new_total > 0) else 0
    if exit_code:
        log.warning("Exiting 1 — %d new finding(s) (ZAGWARE_FAIL_ON_NEW=true)", new_total)
    # Public-repo secrets are always fail-worthy regardless of ZAGWARE_FAIL_ON_NEW —
    # betterleaks has no severity to gate on, so repo visibility is the priority
    # signal instead, and a leaked credential in a public repo is urgent by definition.
    # "unknown" visibility is treated the same as "public" (fail closed) unless the
    # operator explicitly opts out via ZAGWARE_ASSUME_PRIVATE — a transient API
    # error or missing permission must not silently disable this guarantee. See
    # QUAL-02. (This elif is independent of the ZAGWARE_FAIL_ON_NEW warning above
    # so both reasons are visible when a public/unknown repo also has new IaC/SCA
    # findings — see QUAL-29.)
    _, reason = _secrets_public_gate(repo_visibility, bool(novel_secrets))
    if reason == "public":
        exit_code = 1
        log.warning("Exiting 1 — %d new secret(s) in a PUBLIC repository (ZAGWARE_SECRETS_FAIL_ON_PUBLIC=true)",
                     len(novel_secrets))
    elif reason == "unknown":
        exit_code = 1
        log.warning(
            "Exiting 1 — %d new secret(s) and repository visibility could not be determined; "
            "ZAGWARE_SECRETS_FAIL_ON_PUBLIC=true applies conservatively. Set ZAGWARE_ASSUME_PRIVATE=true "
            "to opt out (e.g. air-gapped installs where visibility can never be resolved).",
            len(novel_secrets))

    track_scan_completed(
        platform.name(), platform.repo(), timings.get("total", 0.0),
        new_count, len(novel_sca), True, (base_sca is not None or head_sca is not None),
        bool(suppressed_ids), exit_code,
        secrets_new=len(novel_secrets), secrets_scanned=(base_secrets is not None or head_secrets is not None),
    )

    log.info("Done.")
    return exit_code


# Exit codes:
#   0 — scan completed, nothing gated the merge
#   1 — scan completed and a policy gate fired (ZAGWARE_FAIL_ON_NEW, public-repo
#       secrets), or a handled scanner failure occurred
#   2 — the scanner itself crashed unexpectedly. Kept distinct from 1 so an
#       operator can tell "your PR has findings" from "the tool broke"; before
#       QUAL-04 an unhandled exception exited 1 via the traceback path with no
#       telemetry and no way to distinguish the two.
_EXIT_CRASH = 2

def _run_cli() -> int:
    """Process entrypoint wrapper. Converts an unhandled exception into
    _EXIT_CRASH *and* still flushes telemetry, instead of dying on the
    traceback before telemetry_flush() ever runs. Kept as a named function
    rather than inline under `if __name__ == "__main__"` so the backstop
    itself is directly testable. See QUAL-04."""
    try:
        exit_code = main()
    except Exception as exc:  # noqa: BLE001 -- deliberate top-level backstop
        # log.exception keeps the traceback available for debugging; the
        # difference is that the process now exits through the flush below.
        log.exception("Scanner crashed unexpectedly: %s: %s", type(exc).__name__, exc)
        try:
            track_scan_failed("unknown", "", "unhandled")
        except Exception:
            pass  # a broken telemetry path must not mask the original crash
        exit_code = _EXIT_CRASH
    telemetry_flush()  # bounded wait for in-flight telemetry — never blocks indefinitely
    return exit_code


if __name__ == "__main__":
    sys.exit(_run_cli())
