"""Tests for SUP-02/SUP-19: publish.yml's workflow_dispatch tag input must
reject the reserved promotion-channel tags (:stable, :secure) and any
malformed/injected value, and the automatic :latest advancement must only
happen on the real tag-push trigger, never on a manual dispatch.

SUP-02: a dispatch with input `stable` or `secure` used to push a freshly
built, zero-day-old, never-CVE-scanned image directly onto the exact tags
promote.yml exists to protect, voiding the 14-day cooling period and CVE gate.
The unconditional `type=raw,value=latest` metadata-action tag also meant a
dispatch republishing an older version silently rolled :latest backwards.

SUP-19: INPUT_TAG was written unquoted into $GITHUB_OUTPUT with no
validation -- a newline would inject arbitrary extra step outputs. The same
allowlist that rejects reserved tags also closes this.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _extract_run_block(workflow_path: str, step_name: str) -> str:
    doc = yaml.safe_load((REPO_ROOT / workflow_path).read_text())
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == step_name:
                assert "run" in step, f"step {step_name!r} has no run: block"
                return step["run"]
    raise AssertionError(f"step {step_name!r} not found in {workflow_path}")


def _run_set_image_tag(input_tag: str, event_name: str, tmp_path: Path,
                       refresh_version: str = "") -> subprocess.CompletedProcess:
    script = _extract_run_block(".github/workflows/publish.yml", "Set image tag")
    # The step takes everything it needs through its own `env:` block, so the
    # shipped bash carries no GH expressions at all and runs here verbatim.
    # Anything that has to be interpolated into the script text is a value that
    # cannot be tested without paraphrasing it -- which is how SUP-19 survived.
    assert "${{" not in script, f"this step must not interpolate GH expressions into bash:\n{script}"

    gh_output = tmp_path / "GITHUB_OUTPUT"
    gh_output.touch()
    env = dict(os.environ)
    env["INPUT_TAG"] = input_tag
    env["EVENT_NAME"] = event_name
    env["REFRESH_VERSION"] = refresh_version
    env["GITHUB_OUTPUT"] = str(gh_output)
    env["GITHUB_REF_NAME"] = "v2.9.0"

    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
    )
    proc.gh_output = gh_output.read_text()
    return proc


def _output_named(gh_output: str, name: str) -> str:
    """Read a step output back out of a $GITHUB_OUTPUT file written in the
    heredoc delimiter form GitHub documents for untrusted values -- the form
    SUP-19 requires instead of a single `name=...` line. Returns "" when
    nothing was written."""
    lines = gh_output.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"{name}<<"):
            delim = line.split("<<", 1)[1]
            body = []
            for rest in lines[i + 1:]:
                if rest == delim:
                    return "\n".join(body)
                body.append(rest)
            raise AssertionError(f"unterminated heredoc in GITHUB_OUTPUT:\n{gh_output}")
    return ""


def _output_value(gh_output: str) -> str:
    return _output_named(gh_output, "value")


class TestRejectsReservedTags:
    @pytest.mark.parametrize("reserved", ["stable", "secure"])
    def test_dispatch_onto_stable_or_secure_is_rejected(self, reserved, tmp_path):
        proc = _run_set_image_tag(reserved, "workflow_dispatch", tmp_path)
        assert proc.returncode != 0
        assert "Refusing to dispatch" in (proc.stdout + proc.stderr)
        assert proc.gh_output == ""  # nothing written -- no downstream tag push

    def test_push_event_is_never_subject_to_the_dispatch_check(self, tmp_path):
        """The reserved-tag check only applies to workflow_dispatch; a real
        tag push must be completely unaffected."""
        proc = _run_set_image_tag("", "push", tmp_path)
        assert proc.returncode == 0, proc.stderr
        assert _output_value(proc.gh_output) == "2.9.0"


class TestRejectsMalformedInput:
    @pytest.mark.parametrize("bad_input", [
        "latest\nvalue=stable",  # SUP-19: newline injection into GITHUB_OUTPUT
        "; rm -rf /",
        "2.1.0; echo pwned",
        "v2.1.0",  # a 'v' prefix is not the accepted format
        "",
        "2.1",  # not X.Y.Z
    ])
    def test_malformed_dispatch_input_is_rejected(self, bad_input, tmp_path):
        proc = _run_set_image_tag(bad_input, "workflow_dispatch", tmp_path)
        assert proc.returncode != 0
        assert proc.gh_output == ""


class TestAcceptsValidInput:
    @pytest.mark.parametrize("good_input", ["latest", "2.1.0", "10.20.30"])
    def test_valid_dispatch_input_is_accepted(self, good_input, tmp_path):
        proc = _run_set_image_tag(good_input, "workflow_dispatch", tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _output_value(proc.gh_output) == good_input


class TestLatestTagConditionalOnPushEvent:
    """Direct YAML-level check: the metadata-action tags block must only
    advance :latest on the real push trigger, not on workflow_dispatch."""

    def test_latest_tag_entry_is_conditional_on_push(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
        steps = doc["jobs"]["build-sign-push"]["steps"]
        meta_step = next(s for s in steps if s.get("name") == "Docker metadata")
        tags_block = meta_step["with"]["tags"]
        latest_lines = [l for l in tags_block.splitlines() if "value=latest" in l]
        assert latest_lines, "expected a type=raw,value=latest tag entry"
        for line in latest_lines:
            assert "enable=" in line, (
                f"the :latest tag entry must be conditional (enable=...), not unconditional: {line!r}"
            )
            assert "event_name == 'push'" in line or 'event_name == "push"' in line


class TestWeeklyRefreshTagging:
    """The scheduled base refresh rebuilds an existing release on a current
    base. It must advance :latest -- that is the whole point, it is what
    promote.yml scans -- while leaving :<version> alone, because the README
    calls that tag immutable per release and consumers pin it."""

    def test_refresh_publishes_a_dated_tag_not_the_bare_version(self, tmp_path):
        proc = _run_set_image_tag("", "schedule", tmp_path, refresh_version="3.3.0")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        image_tag = _output_named(proc.gh_output, "image_tag")
        assert image_tag != "3.3.0", (
            "a refresh must not republish over :3.3.0 -- that tag is documented "
            "as immutable per release"
        )
        assert re.fullmatch(r"3\.3\.0-\d{8}", image_tag), image_tag

    def test_refresh_keeps_the_clean_semver_as_the_version_label(self, tmp_path):
        """promote.yml reads org.opencontainers.image.version off the digest to
        decide whose cooling clock applies, and that label is set from `value`.
        A dated tag with a dated label would orphan the rebuild from its
        release and fail the gate closed."""
        proc = _run_set_image_tag("", "schedule", tmp_path, refresh_version="3.3.0")
        assert _output_value(proc.gh_output) == "3.3.0"

    def test_refresh_rejects_a_non_semver_version(self, tmp_path):
        proc = _run_set_image_tag("", "schedule", tmp_path, refresh_version="main")
        assert proc.returncode != 0
        assert proc.gh_output == ""

    def test_latest_advances_on_schedule_as_well_as_push(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
        steps = doc["jobs"]["build-sign-push"]["steps"]
        meta_step = next(s for s in steps if s.get("name") == "Docker metadata")
        latest_lines = [l for l in meta_step["with"]["tags"].splitlines()
                        if "value=latest" in l]
        assert latest_lines
        for line in latest_lines:
            assert "event_name == 'schedule'" in line, (
                "the weekly refresh has to move :latest or promote.yml never "
                f"sees the rebuilt digest: {line!r}"
            )
            assert "workflow_dispatch" not in line, (
                "SUP-02: a manual dispatch must still never advance :latest"
            )


class TestRefreshTargetIsConstrained:
    """The scheduled path has no required reviewer, so what it is allowed to
    build is the control. Tags are outside branch protection."""

    def _steps(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
        return doc["jobs"]["build-sign-push"]["steps"]

    def test_refresh_builds_the_release_tag_not_the_default_branch(self):
        checkout = next(s for s in self._steps() if "actions/checkout" in str(s.get("uses", "")))
        ref = checkout["with"]["ref"]
        assert "steps.refresh.outputs.tag" in ref, (
            "a scheduled rebuild must check out the release tag, otherwise it "
            "would ship whatever has since landed on main with no review"
        )

    def test_refresh_requires_the_tag_to_be_reachable_from_main(self):
        step = next((s for s in self._steps()
                     if s.get("name") == "Verify the refresh target is reachable from main"), None)
        assert step is not None, (
            "nothing stops a git tag being moved off the reviewed branch, and "
            "the unattended refresh path is the one with no human to notice"
        )
        assert "merge-base --is-ancestor" in step["run"]
        assert step.get("if", "").strip() == "github.event_name == 'schedule'"

    def test_scheduled_runs_use_a_separate_environment(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
        environment = doc["jobs"]["build-sign-push"]["environment"]
        assert "schedule" in environment and "release" in environment, (
            "release publishes must keep the reviewed 'release' environment "
            f"(SUP-09); only the refresh may bypass it: {environment!r}"
        )
