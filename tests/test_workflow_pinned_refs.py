"""Tests for SUP-13: the mutable-tag-ref guard in ci.yml must catch a
mutable `uses: foo@vN` ref anywhere in this repo's workflows or composite
actions, not just in publish.yml -- and actions/github-script must actually
be pinned to a commit SHA in every workflow that uses it.

Before the fix the guard was `grep -E 'uses: .*@v[0-9]' .github/workflows/publish.yml`
-- one file -- while promote.yml and audit.yml both shipped
`uses: actions/github-script@v7`, a repointable tag running in jobs holding
packages/contents/issues/id-token write permissions and (in promote.yml)
GH_PAT_PACKAGES in the same job environment. publish.yml's own header claims
"All GitHub Actions are pinned to immutable commit SHAs" -- untrue for the
repo as a whole.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _extract_run_block(workflow_path: str, step_name: str) -> str:
    """Pull the literal `run:` script text for a named step out of a workflow
    YAML -- this is the actual shipped bash, not a paraphrase of it."""
    doc = yaml.safe_load((REPO_ROOT / workflow_path).read_text())
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == step_name:
                assert "run" in step, f"step {step_name!r} has no run: block"
                return step["run"]
    raise AssertionError(f"step {step_name!r} not found in {workflow_path}")


class TestCiMutableRefGuard:
    STEP = "Check for common issues"

    def test_real_repo_passes_the_guard(self):
        """The guard's own claim, exercised against the real repo tree."""
        script = _extract_run_block(".github/workflows/ci.yml", self.STEP)
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Lint checks passed" in proc.stdout

    def test_catches_mutable_ref_in_a_workflow_other_than_publish_yml(self, tmp_path):
        """Anchor regression: before the fix the guard only ever grepped
        publish.yml, so a mutable ref in any other workflow (promote.yml,
        audit.yml, a future one) passed silently."""
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "actions").mkdir(parents=True)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "scanner.py").write_text("# clean\n")
        (tmp_path / ".github" / "workflows" / "publish.yml").write_text(
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
        )
        (tmp_path / ".github" / "workflows" / "some-other-workflow.yml").write_text(
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/github-script@v7\n"
        )
        script = _extract_run_block(".github/workflows/ci.yml", self.STEP)
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=tmp_path, capture_output=True, text=True, timeout=15,
        )
        assert proc.returncode != 0
        assert "mutable tag ref" in (proc.stdout + proc.stderr)

    def test_catches_mutable_ref_in_a_composite_action(self, tmp_path):
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "actions" / "some-action").mkdir(parents=True)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "scanner.py").write_text("# clean\n")
        (tmp_path / ".github" / "actions" / "some-action" / "action.yml").write_text(
            "runs:\n  using: composite\n  steps:\n"
            "    - uses: some/nested-action@v2\n"
        )
        script = _extract_run_block(".github/workflows/ci.yml", self.STEP)
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=tmp_path, capture_output=True, text=True, timeout=15,
        )
        assert proc.returncode != 0
        assert "mutable tag ref" in (proc.stdout + proc.stderr)

    def test_pinned_shas_with_version_comments_do_not_false_positive(self, tmp_path):
        """The correct, already-used-everywhere-else pattern
        (`uses: owner/repo@<sha> # vN`) must not itself trip the guard."""
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "actions").mkdir(parents=True)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "scanner.py").write_text("# clean\n")
        (tmp_path / ".github" / "workflows" / "clean.yml").write_text(
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
            "      - uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7\n"
        )
        script = _extract_run_block(".github/workflows/ci.yml", self.STEP)
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=tmp_path, capture_output=True, text=True, timeout=15,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


class TestGithubScriptIsPinnedInEveryWorkflow:
    """Direct YAML-level regression for the review's exact defect: two
    specific workflows shipped an unpinned actions/github-script@v7."""

    @pytest.mark.parametrize("workflow,job_name", [
        (".github/workflows/audit.yml", "audit"),
        (".github/workflows/promote.yml", "promote"),
    ])
    def test_github_script_step_is_pinned_to_a_commit_sha(self, workflow, job_name):
        doc = yaml.safe_load((REPO_ROOT / workflow).read_text())
        github_script_steps = [
            s for s in doc["jobs"][job_name]["steps"]
            if str(s.get("uses", "")).startswith("actions/github-script@")
        ]
        assert github_script_steps, f"expected a github-script step in {workflow}"
        for step in github_script_steps:
            ref = step["uses"].split("@", 1)[1]
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), (
                f"{workflow}: actions/github-script must be pinned to a 40-char commit SHA, "
                f"got {ref!r}"
            )
