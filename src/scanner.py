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
import json
import logging
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
import hashlib

# ── Internal constants ─────────────────────────────────────────────────────────

_SCANNER_BIN   = os.environ.get("_ZAGWARE_SCANNER_BIN", "/usr/local/bin/kics")
_QUERIES_PATH  = os.environ.get("ZAGWARE_QUERIES_PATH",  "/opt/iac-rules/assets/queries")
_COMMENT_MARKER    = "<!-- zagware-iac-scanner -->"          # GitHub / GitLab (hidden HTML comment)
_BB_COMMENT_MARKER = "[zagware-iac-scanner]: https://github.com/zagware/iac-scanner"  # Bitbucket (invisible link ref)
_MAX_COMMENT   = 60_000
_FAIL_ON_NEW   = os.environ.get("ZAGWARE_FAIL_ON_NEW", "false").lower() == "true"
_EXCLUDE_PATHS = os.environ.get("ZAGWARE_EXCLUDE_PATHS", ".git")
_MIN_SEVERITY  = os.environ.get("ZAGWARE_MIN_SEVERITY", "").upper().strip()

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TRACE"]
_SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW":      "🔵", "INFO": "⚪", "TRACE":   "⚫",
}

# ── SCA (Grype) constants ──────────────────────────────────────────────────────
_SCA_ENABLED      = os.environ.get("ZAGWARE_SCA_ENABLED", "true").lower() != "false"
_GRYPE_BIN        = os.environ.get("_ZAGWARE_GRYPE_BIN",  "/usr/local/bin/grype")
_SYFT_BIN         = os.environ.get("_ZAGWARE_SYFT_BIN",   "/usr/local/bin/syft")
_SCA_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]
_SCA_SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "NEGLIGIBLE": "⚪"}
_SCA_MANIFESTS = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.sum", "Cargo.lock",
    "requirements.txt", "Pipfile.lock", "poetry.lock",
    "Gemfile.lock", "pom.xml", "build.gradle",
    "composer.lock", "packages.lock.json",
]

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

logging.basicConfig(
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.DEBUG if os.environ.get("ZAGWARE_DEBUG") else logging.INFO,
)
log = logging.getLogger("zagware")


# ── HTTP helper (stdlib only, no pip deps) ─────────────────────────────────────

def _http(method: str, url: str, data: dict | None = None, headers: dict | None = None) -> dict | list:
    body = json.dumps(data).encode() if data is not None else None
    req  = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
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

    def repo(self) -> str:
        """Full repository name (owner/repo or similar). Empty string if unavailable."""
        return ''

    def pr_number(self) -> int | None:
        """PR/MR number as an integer, or None if not a PR pipeline."""
        return None


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
        return os.environ["GITHUB_BASE_REF"]

    def head_branch(self) -> str:
        return os.environ.get("GITHUB_HEAD_REF") or os.environ["GITHUB_SHA"]

    def base_label(self) -> str:
        return os.environ.get("GITHUB_BASE_REF", "base")

    def head_label(self) -> str:
        return os.environ.get("GITHUB_HEAD_REF", "PR branch")

    def repo(self) -> str:
        return os.environ.get("GITHUB_REPOSITORY", "")

    def pr_number(self) -> int | None:
        val = os.environ.get("PR_NUMBER", "").strip()
        return int(val) if val else None

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

    def pr_number(self) -> int | None:
        val = os.environ.get("CI_MERGE_REQUEST_IID", "").strip()
        return int(val) if val else None

    def _headers(self) -> dict:
        # PRIVATE-TOKEN header works for both PATs and project/group access tokens.
        return {"PRIVATE-TOKEN": self._api_token}

    def post_or_update_comment(self, body: str) -> None:
        mr  = os.environ["CI_MERGE_REQUEST_IID"]
        api = f"{self._server}/api/v4/projects/{self._project_id}/merge_requests/{mr}/notes"

        notes = _http("GET", f"{api}?per_page=100", headers=self._headers())
        assert isinstance(notes, list)
        existing_id = next(
            (n["id"] for n in notes if _COMMENT_MARKER in n.get("body", "")), None
        )

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

    def pr_number(self) -> int | None:
        val = os.environ.get("BITBUCKET_PR_ID", "").strip()
        return int(val) if val else None

    def _headers(self) -> dict:
        # Atlassian API tokens require HTTP Basic auth: email:token
        creds = base64.b64encode(f"{self._email}:{self._api_token}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    def post_or_update_comment(self, body: str) -> None:
        pr  = os.environ["BITBUCKET_PR_ID"]
        api = (f"https://api.bitbucket.org/2.0/repositories"
               f"/{self._workspace}/{self._slug}/pullrequests/{pr}/comments")

        data     = _http("GET", f"{api}?pagelen=100", headers=self._headers())
        assert isinstance(data, dict)
        existing = next(
            (c["id"] for c in data.get("values", [])
             if _BB_COMMENT_MARKER in c.get("content", {}).get("raw", "")
             or "## Zagware IaC Scanner" in c.get("content", {}).get("raw", "")),
            None,
        )
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
        return (os.environ.get("SYSTEM_PULLREQUEST_TARGETBRANCH", "main")
                .replace("refs/heads/", ""))

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

    def pr_number(self) -> int | None:
        val = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID", "").strip()
        return int(val) if val else None

    def _headers(self) -> dict:
        creds = base64.b64encode(f":{self._token}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    def post_or_update_comment(self, body: str) -> None:
        pr  = os.environ["SYSTEM_PULLREQUEST_PULLREQUESTID"]
        api = (f"{self._org_url}/{self._project}/_apis/git"
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

        if existing_thread and existing_comment:
            url = f"{api}/threads/{existing_thread}/comments/{existing_comment}{ver}"
            _http("PATCH", url, {"content": body}, self._headers())
            log.info("Updated ADO comment on thread %d, PR #%s", existing_thread, pr)
        else:
            payload = {
                "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
                "status":   1,
            }
            _http("POST", f"{api}/threads{ver}", payload, self._headers())
            log.info("Posted ADO thread on PR #%s", pr)


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
        return f'{collection}/{project}/_git/{repo_name}' if all([collection, project, repo_name]) else ''
    return ''


# ── Git helpers ────────────────────────────────────────────────────────────────

def _git(args: list[str], cwd: str | None = None) -> None:
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, ["git"] + args, result.stdout, result.stderr
        )


def clone_branch(url: str, branch: str, dest: str) -> None:
    """Shallow-clone a single branch."""
    _git(["clone", "--depth=1", "--quiet", "--no-tags",
          "--branch", branch, url, dest])


def clone_and_checkout_sha(url: str, base_branch: str, sha: str, dest: str) -> None:
    """Clone base branch then fetch and checkout a specific SHA."""
    _git(["clone", "--depth=1", "--quiet", "--no-tags",
          "--branch", base_branch, url, dest])
    _git(["fetch", "--depth=1", "origin", sha], cwd=dest)
    _git(["checkout", sha], cwd=dest)


# ── Scan ───────────────────────────────────────────────────────────────────────

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
        "--exclude-paths", _EXCLUDE_PATHS,
        "--disable-full-descriptions",
        "--no-progress",
        "--ci",
    ]
    # Apply severity threshold: exclude findings below ZAGWARE_MIN_SEVERITY from both
    # base and PR scans so the diff only operates on in-scope severities.
    below = _severities_below()
    if below:
        cmd += ["--exclude-severities", ",".join(below)]

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=path)
    if result.returncode not in (0, 50):
        log.warning("Scanner returned code %d", result.returncode)
        if result.stderr:
            log.debug("stderr: %s", result.stderr[:800])

    try:
        with open(output_json) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        log.warning("Could not read scan output (%s) — returning empty results", exc)
        return {"queries": []}


# ── Diff ───────────────────────────────────────────────────────────────────────

def _base_sim_ids(results: dict) -> set[str]:
    return {
        f["similarity_id"]
        for q in results.get("queries", [])
        for f in q.get("files", [])
    }


def new_findings(base: dict, pr: dict) -> list[dict]:
    """Return queries from *pr* containing only findings absent from *base*."""
    base_sims = _base_sim_ids(base)
    sev_rank  = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    out: list[dict] = []
    for q in pr.get("queries", []):
        novel = [f for f in q.get("files", []) if f["similarity_id"] not in base_sims]
        if novel:
            out.append({**q, "files": novel})
    out.sort(key=lambda q: sev_rank.get(q.get("severity", ""), 99))
    return out


def count_findings(queries: list[dict]) -> int:
    return sum(len(q.get("files", [])) for q in queries)


# ── SCA (Grype) ────────────────────────────────────────────────────────────────

def _sca_sim_id(vuln_id: str, pkg_name: str, pkg_version: str) -> str:
    return hashlib.sha256(f"{vuln_id}:{pkg_name}:{pkg_version}".encode()).hexdigest()


def _has_sca_manifests(path: str) -> bool:
    p = Path(path)
    for m in _SCA_MANIFESTS:
        if next(p.rglob(m), None):
            return True
    return False


def _run_syft(path: str, sbom_out: str) -> bool:
    try:
        r = subprocess.run(
            [_SYFT_BIN, "scan", f"dir:{path}", "-o", f"syft-json={sbom_out}", "--quiet"],
            capture_output=True, text=True, timeout=180,
        )
        return r.returncode == 0 and Path(sbom_out).exists()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug("Syft unavailable: %s", e)
        return False


def _run_grype(sbom_path: str, grype_out: str) -> bool:
    try:
        r = subprocess.run(
            [_GRYPE_BIN, f"sbom:{sbom_path}", "-o", "json", "--quiet"],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode == 0 and r.stdout:
            Path(grype_out).write_text(r.stdout)
            return True
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug("Grype unavailable: %s", e)
        return False


def run_sca_scan(path: str, tmp_dir: str, label: str) -> list[dict]:
    """Run Syft+Grype SCA scan. Returns list of normalised finding dicts."""
    if not _SCA_ENABLED:
        return []
    if not _has_sca_manifests(path):
        log.debug("SCA: no manifest files in %s — skipping", label)
        return []
    sbom_out  = f"{tmp_dir}/sbom_{label}.json"
    grype_out = f"{tmp_dir}/grype_{label}.json"
    log.info("SCA: running Syft on %s...", label)
    if not _run_syft(path, sbom_out):
        log.warning("SCA: Syft failed for %s", label)
        return []
    log.info("SCA: running Grype on %s...", label)
    if not _run_grype(sbom_out, grype_out):
        log.warning("SCA: Grype failed for %s", label)
        return []
    try:
        data = json.loads(Path(grype_out).read_text())
    except Exception as e:
        log.warning("SCA: could not read Grype output: %s", e)
        return []
    findings: list[dict] = []
    for match in data.get("matches", []):
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
                cvss = float(b); break
        epss_list = vuln.get("epss", [])
        epss = float(epss_list[0]["epss"]) if epss_list else None
        fix  = vuln.get("fix", {})
        locs = artifact.get("locations", [])
        mdet = match.get("matchDetails", [])
        urls = list(vuln.get("urls") or [])
        for adv in vuln.get("advisories") or []:
            u = adv.get("url") or adv.get("link") or ""
            if u and u not in urls:
                urls.append(u)
        findings.append({
            "vulnerability_id": vuln_id,
            "data_source":      vuln.get("dataSource") or "",
            "namespace":        vuln.get("namespace")  or "",
            "severity":         (vuln.get("severity") or "UNKNOWN").upper(),
            "cvss_score":       cvss,
            "epss_score":       epss,
            "kev_listed":       vuln.get("kev") is not None,
            "risk_score":       vuln.get("riskScore"),
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
    log.info("SCA %s: %d finding(s)", label, len(findings))
    return findings


def new_sca_findings(base: list[dict], head: list[dict]) -> list[dict]:
    base_sims = {f["similarity_id"] for f in base}
    return [f for f in head if f["similarity_id"] not in base_sims]

# ── Comment rendering ──────────────────────────────────────────────────────────

def _cell(text: str, limit: int = 80) -> str:
    text = text.replace("|", "\\|").replace("\n", " ").strip()
    return text[:limit] + "…" if len(text) > limit else text


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

    # On GitHub/GitLab the HTML comment is hidden; on Bitbucket it renders as text.
    # For Bitbucket we omit it from the top and embed an invisible CommonMark link
    # reference definition at the bottom instead.
    marker_line = _COMMENT_MARKER if collapsible else ""

    L: list[str] = (
        ([marker_line, ""] if marker_line else []) + [
            "## Zagware IaC Scanner",
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
    else:
        summary = " &nbsp;·&nbsp; ".join(
            f"{_SEVERITY_EMOJI[s]} **{sev_counts[s]}** {s}"
            for s in _SEVERITY_ORDER if s in sev_counts
        )
        L += [
            f"> ⚠️ **{total_new} new finding(s) introduced by this PR**",
            f"> {summary}",
            "",
        ]

        for sev in _SEVERITY_ORDER:
            qs = [q for q in novel if q.get("severity") == sev]
            if not qs:
                continue
            count = sum(len(q["files"]) for q in qs)
            emoji = _SEVERITY_EMOJI[sev]

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
                    fname    = f["file_name"]
                    resource = f.get("resource_name") or f.get("resource_type") or "—"
                    L.append(
                        f"| `{fname}` | {f['line']} | `{resource}`"
                        f" | {f.get('issue_type', '')}"
                        f" | {_cell(f.get('expected_value', ''))}"
                        f" | {_cell(f.get('actual_value', ''))} |"
                    )
                L.append("")

            if collapsible:
                L += ["</details>", ""]

    footer = [
        "---",
        "<sub>Zagware IaC Scanner &nbsp;·&nbsp; "
        "[zagware/iac-scanner](https://github.com/zagware/iac-scanner)</sub>",
    ]
    # Bitbucket: append invisible CommonMark link-reference definition as the comment marker
    if not collapsible:
        footer.append(_BB_COMMENT_MARKER)
    L += footer

    body = "\n".join(L)
    if len(body) > _MAX_COMMENT:
        note = "\n\n> ⚠️ _Comment truncated — run locally for full output._"
        body = body[: _MAX_COMMENT - len(note)] + note
    return body



def render_sca_section(
    base_sca: list[dict], head_sca: list[dict], novel_sca: list[dict],
) -> str:
    """Return the SCA block to append to the PR comment. Empty string if no SCA data."""
    if not head_sca and not base_sca:
        return ""
    by_sev: dict[str, list[dict]] = {}
    for f in novel_sca:
        by_sev.setdefault(f.get("severity", "UNKNOWN"), []).append(f)
    L = [
        "", "---", "## 📦 Zagware SCA — Dependency Vulnerabilities", "",
        "| | Base | This PR | New |",
        "|---|:---:|:---:|:---:|",
        f"| Vulnerabilities | {len(base_sca)} | {len(head_sca)} | **{len(novel_sca)}** |",
        "",
    ]
    if not novel_sca:
        L.append("✅ **No new dependency vulnerabilities introduced by this PR.**")
    else:
        summary = " &nbsp;·&nbsp; ".join(
            f"{_SCA_SEVERITY_EMOJI.get(s, '❓')} **{len(by_sev[s])}** {s}"
            for s in _SCA_SEVERITY_ORDER if s in by_sev
        )
        L += [
            f"> ⚠️ **{len(novel_sca)} new vulnerability(ies) introduced by this PR**",
            f"> {summary}", "",
        ]
        for sev in _SCA_SEVERITY_ORDER:
            findings = by_sev.get(sev, [])
            if not findings:
                continue
            emoji = _SCA_SEVERITY_EMOJI.get(sev, "❓")
            L += [
                "<details>",
                f"<summary>{emoji} <strong>{sev}</strong> — {len(findings)} finding(s)</summary>",
                "",
                "| CVE / Advisory | Package | Installed | Fix | CVSS | KEV |",
                "|---|---|:---:|:---:|:---:|:---:|",
            ]
            for f in sorted(findings, key=lambda x: -(x.get("cvss_score") or 0)):
                vuln_url = f["vuln_urls"][0] if f.get("vuln_urls") else ""
                cve_cell = (f"[{f['vulnerability_id']}]({vuln_url})"
                            if vuln_url else f["vulnerability_id"])
                fix = ", ".join(f["fix_versions"]) or f["fix_state"]
                cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "—"
                kev  = "🔴 Yes" if f.get("kev_listed") else "No"
                pkg  = f"{f['package_name']} ({f['package_type']})"
                L.append(
                    f"| {cve_cell} | `{pkg}` | `{f['package_version']}` "
                    f"| `{fix}` | {cvss} | {kev} |"
                )
            L += ["", "</details>", ""]
    return "\n".join(L)


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
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))

        # 1. Upload base scan
        base_payload = {
            'repo': repo,
            'branch': base_branch,
            'commit_sha': base_sha or None,
            'scan_type': 'pr_base' if pr_number else 'branch',
            'pr_number': pr_number,
            'pr_comparison_id': None,
            'scanner_version': 'unknown',
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
                'scanner_version': 'unknown',
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
            with urllib.request.urlopen(req, timeout=30) as resp:
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

# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
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
        return 1
    log.info("Platform: %s", platform.name())
    if _MIN_SEVERITY:
        below = _severities_below()
        log.info("Severity filter: %s and above (excluding %s)",
                 _MIN_SEVERITY, ", ".join(below) if below else "nothing")
    if _FAIL_ON_NEW:
        log.info("ZAGWARE_FAIL_ON_NEW=true — build will fail on new findings")

    clone_url   = platform.clone_url()
    base_branch = platform.base_branch()
    head_branch = platform.head_branch()
    log.info("Repository: %s", clone_url.split("@", 1)[-1])  # redact credentials
    log.info("Base → %s  |  Head → %s", base_branch, head_branch)

    with tempfile.TemporaryDirectory() as tmp:
        base_dir    = f"{tmp}/base"
        pr_dir      = f"{tmp}/pr"
        base_json   = f"{tmp}/base.json"
        pr_json     = f"{tmp}/pr.json"

        # ── Clone ────────────────────────────────────────────────────────────

        log.info("Cloning base branch '%s'…", base_branch)
        try:
            clone_branch(clone_url, base_branch, base_dir)
        except subprocess.CalledProcessError as exc:
            log.error("Clone failed for base branch: %s", exc.stderr)
            return 1

        log.info("Cloning PR branch '%s'…", head_branch)
        try:
            clone_branch(clone_url, head_branch, pr_dir)
        except subprocess.CalledProcessError:
            # head_branch might be a SHA rather than a branch name
            log.debug("Branch clone failed — attempting SHA checkout")
            try:
                clone_and_checkout_sha(clone_url, base_branch, head_branch, pr_dir)
            except subprocess.CalledProcessError as exc:
                log.error("Clone failed for PR branch/SHA: %s", exc.stderr)
                return 1

        # ── Scan ─────────────────────────────────────────────────────────────

        log.info("Scanning base branch…")
        base_results = run_scan(base_dir, base_json)
        base_count   = count_findings(base_results.get("queries", []))
        log.info("Base: %d finding(s)", base_count)

        log.info("Scanning PR branch…")
        pr_results   = run_scan(pr_dir, pr_json)
        pr_count     = count_findings(pr_results.get("queries", []))
        log.info("PR:   %d finding(s)", pr_count)

        # ── Upload to GTP platform if configured ─────────────────────────────

        _platform_url   = os.environ.get('ZAGWARE_PLATFORM_URL', '').rstrip('/')
        _platform_token = os.environ.get('ZAGWARE_PLATFORM_TOKEN', '')
        if _platform_url and _platform_token:
            upload_to_platform(
                _platform_url,
                _platform_token,
                platform.repo(),
                base_branch,
                '',
                head_branch,
                '',
                platform.pr_number(),
                base_results,
                pr_results,
            )

        # ── SCA ─────────────────────────────────────────────────────────────
        base_sca  = run_sca_scan(base_dir, tmp, "base")
        head_sca  = run_sca_scan(pr_dir,  tmp, "pr")
        novel_sca = new_sca_findings(base_sca, head_sca)
        log.info("SCA new: %d finding(s)", len(novel_sca))

        if _platform_url and _platform_token and (base_sca or head_sca):
            upload_sca_to_platform(
                _platform_url, _platform_token,
                platform.repo(),
                base_branch, head_branch,
                platform.pr_number(),
                base_sca, head_sca,
            )

        # ── Diff ─────────────────────────────────────────────────────────────

        novel     = new_findings(base_results, pr_results)
        new_count = count_findings(novel)
        log.info("New:  %d finding(s)", new_count)

        # ── Render ───────────────────────────────────────────────────────────

        comment = render_comment(
            base_results, pr_results, novel,
            platform.base_label(),
            platform.head_label(),
            collapsible=platform.supports_html_details(),
        )
        comment += render_sca_section(base_sca, head_sca, novel_sca)

        # ── Post ─────────────────────────────────────────────────────────────

        try:
            platform.post_or_update_comment(comment)
        except Exception as exc:
            log.error("Failed to post comment: %s", exc)
            return 1

    if _FAIL_ON_NEW and new_count > 0:
        log.warning("Exiting 1 — %d new finding(s) (ZAGWARE_FAIL_ON_NEW=true)", new_count)
        return 1

    log.info("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
