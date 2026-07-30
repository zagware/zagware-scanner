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


def _run_set_image_tag(input_tag: str, event_name: str, tmp_path: Path) -> subprocess.CompletedProcess:
    script = _extract_run_block(".github/workflows/publish.yml", "Set image tag")
    # Resolve the two GH expressions this step references, the way the
    # Actions runner would before handing the script to bash.
    resolved = script.replace(
        '"${{ github.event_name }}"', f'"{event_name}"'
    ).replace(
        "${GITHUB_REF_NAME#v}", "2.9.0"  # only exercised on the push path
    )
    assert "${{" not in resolved, f"unresolved GH expression left in script:\n{resolved}"

    gh_output = tmp_path / "GITHUB_OUTPUT"
    gh_output.touch()
    env = dict(os.environ)
    env["INPUT_TAG"] = input_tag
    env["GITHUB_OUTPUT"] = str(gh_output)
    env["GITHUB_REF_NAME"] = "v2.9.0"

    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", resolved],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
    )
    proc.gh_output = gh_output.read_text()
    return proc


def _output_value(gh_output: str) -> str:
    """Read the `value` step output back out of a $GITHUB_OUTPUT file written
    in the heredoc delimiter form GitHub documents for untrusted values -- the
    form SUP-19 requires instead of a single `value=...` line. Returns "" when
    nothing was written."""
    lines = gh_output.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("value<<"):
            delim = line.split("<<", 1)[1]
            body = []
            for rest in lines[i + 1:]:
                if rest == delim:
                    return "\n".join(body)
                body.append(rest)
            raise AssertionError(f"unterminated heredoc in GITHUB_OUTPUT:\n{gh_output}")
    return ""


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
