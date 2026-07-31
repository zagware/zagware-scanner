"""Tests for SUP-11/SUP-16/SUP-09: retire the long-lived org-wide PAT in
favour of GITHUB_TOKEN, stop over-granting promote.yml `contents: write`,
and put a second-party gate + team ownership on the publish path.

SUP-11: secrets.GH_PAT_PACKAGES (a classic PAT, org-wide write:packages)
authenticated GHCR logins in publish.yml, promote.yml, and audit.yml, and was
embedded directly in curl command text in promote.yml (readable via
/proc/*/cmdline and landing in the rendered run script on disk). The
justification -- GITHUB_TOKEN cannot create a package under the org
namespace the first time -- stopped applying once the package existed.
audit.yml only ever needed anonymous read access to a public package.

SUP-16: promote.yml declared `contents: write` with a comment claiming it
was needed to "commit README updates" and "open issues" -- neither true; no
step writes repository contents, and opening issues is covered separately by
`issues: write`. Combined with a mutable actions/github-script ref and a
write-capable PAT in the same job, this was a real over-grant.

SUP-09: publish.yml had no `environment:` key -- no required reviewer, no
second-party gate on the path that produces every cosign-signed,
SLSA-attested, :latest-tagged image. CODEOWNERS named a single individual
account rather than a team.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(path: str) -> dict:
    return yaml.safe_load((REPO_ROOT / path).read_text())


class TestNoLongLivedPATRemains:
    @pytest.mark.parametrize("workflow", [
        ".github/workflows/publish.yml",
        ".github/workflows/promote.yml",
        ".github/workflows/audit.yml",
    ])
    def test_workflow_never_references_gh_pat_packages(self, workflow):
        """Checks for functional usage (secrets.GH_PAT_PACKAGES), not mere
        mentions of the retired name in an explanatory comment."""
        # The assertion previously grepped the raw file, so it also fired on a
        # comment -- contradicting the docstring above. Documenting the retired
        # PAT as the fallback is deliberate (see publish.yml's header); using it
        # is what must not come back.
        live = "\n".join(
            line for line in (REPO_ROOT / workflow).read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "secrets.GH_PAT_PACKAGES" not in live, (
            f"{workflow} still references the retired long-lived PAT -- see SUP-11"
        )


class TestNoSecretInterpolatedIntoCommandText:
    def test_promote_yml_curl_uses_env_not_inline_interpolation(self):
        """The curl call must read its token from an env var, not from a
        ${{ secrets.* }} expression interpolated directly into command
        text (which lands in the rendered run script on disk and in
        /proc/*/cmdline)."""
        doc = _load(".github/workflows/promote.yml")
        steps = doc["jobs"]["promote"]["steps"]
        step = next(s for s in steps if s.get("name") == "Resolve latest tag digest and age")
        assert "env" in step and any("GITHUB_TOKEN" in v for v in step["env"].values())
        assert "${{ secrets." not in step["run"], (
            "a secret expression must not be interpolated directly into the run script"
        )
        assert "$GH_TOKEN" in step["run"]


class TestAuditYmlHasNoCredential:
    def test_audit_yml_never_logs_in_to_ghcr(self):
        """A public image needs no authentication to inspect/pull."""
        doc = _load(".github/workflows/audit.yml")
        steps = doc["jobs"]["audit"]["steps"]
        assert not any(s.get("name") == "Log in to GHCR" for s in steps)
        assert not any("login-action" in str(s.get("uses", "")) for s in steps)


class TestPromoteYmlContentsPermission:
    def test_contents_permission_is_read_not_write(self):
        doc = _load(".github/workflows/promote.yml")
        perms = doc["jobs"]["promote"]["permissions"]
        assert perms["contents"] == "read", (
            "no step in promote.yml writes repository contents -- see SUP-16"
        )


class TestPublishYmlReleaseGate:
    def test_build_sign_push_job_has_environment_gate(self):
        doc = _load(".github/workflows/publish.yml")
        job = doc["jobs"]["build-sign-push"]
        assert job.get("environment") == "release", (
            "publish.yml must gate behind an environment with a required "
            "reviewer -- see SUP-09"
        )


class TestCodeownersReferencesATeam:
    def test_codeowners_names_a_team_not_an_individual(self):
        text = (REPO_ROOT / ".github/CODEOWNERS").read_text()
        owner_lines = [
            l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        assert owner_lines, "CODEOWNERS has no active rule"
        for line in owner_lines:
            owners = line.split()[1:]
            for owner in owners:
                assert "/" in owner, (
                    f"CODEOWNERS entry {owner!r} is an individual account, not an "
                    f"org/team (org/team refs contain '/') -- see SUP-09"
                )
