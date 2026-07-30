"""Integration tests for SUP-01/SUP-03/SUP-04: the CVE-gating bash embedded in
audit.yml / promote.yml / publish.yml must fail CLOSED (non-zero exit, no
fabricated count) whenever Grype cannot produce a trustworthy answer, and
must compute the real HIGH/CRITICAL count when it can.

These extract the *actual* `run:` block text from the YAML (not a
reimplementation of the logic in Python) and execute it with `bash -eo
pipefail`, matching GitHub Actions' own default shell invocation, against a
fake `grype` binary planted first on PATH. This is the only way to verify the
shipped bash without a full local Actions runner (`act`, not available here) —
see tests/README.md.

Anchor regression this whole file exists to prevent: before the fix, the real
publish.yml self-scan step completed in 3ms and printed "0" because `grype`
was never installed on the runner (see REVIEW-2026-07-30.md, Verified
evidence #1). A script that can print a fabricated "0"/"999" must never pass
these tests again.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DIGEST_RE = re.compile(r"\$\{\{\s*steps\.\w+\.outputs\.digest\s*\}\}")
TEST_DIGEST = "sha256:" + "ab" * 32


def _extract_run_block(workflow_path: str, step_name: str) -> str:
    """Pull the literal `run:` script text for a named step out of a workflow
    YAML — this is the actual shipped bash, not a paraphrase of it."""
    doc = yaml.safe_load((REPO_ROOT / workflow_path).read_text())
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == step_name:
                assert "run" in step, f"step {step_name!r} has no run: block"
                return step["run"]
    raise AssertionError(f"step {step_name!r} not found in {workflow_path}")


def _resolve_gh_expressions(script: str) -> str:
    """Substitute the `${{ steps.X.outputs.digest }}` GitHub Actions expression
    with a literal test value, the way the Actions runner would before handing
    the script to bash. Every step under test only ever references .digest."""
    resolved = DIGEST_RE.sub(TEST_DIGEST, script)
    assert "${{" not in resolved, f"unresolved GH expression left in script:\n{resolved}"
    return resolved


def _write_fake_grype(bin_dir: Path, script_body: str) -> None:
    fake = bin_dir / "grype"
    fake.write_text(f"#!/bin/sh\n{script_body}\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run_bash_step(script: str, tmp_path: Path, fake_grype_body: str) -> subprocess.CompletedProcess:
    """Execute `script` the way GitHub Actions executes a run: step with the
    default shell (bash -eo pipefail {0}) on a Linux runner, with a fake
    `grype` shadowing the real one on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    _write_fake_grype(bin_dir, fake_grype_body)

    gh_output = tmp_path / "GITHUB_OUTPUT"
    gh_output.touch()
    gh_summary = tmp_path / "GITHUB_STEP_SUMMARY"
    gh_summary.touch()

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["GITHUB_OUTPUT"] = str(gh_output)
    env["GITHUB_STEP_SUMMARY"] = str(gh_summary)

    resolved = _resolve_gh_expressions(script)
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", resolved],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
    )
    proc.gh_output = gh_output.read_text()
    proc.gh_summary = gh_summary.read_text()
    return proc


def _parse_output(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


CLEAN_GRYPE = 'echo \'{"matches": []}\''
VULNERABLE_GRYPE = textwrap.dedent("""\
    echo '{"matches": [
      {"vulnerability": {"id": "CVE-2099-0001", "severity": "Critical"}},
      {"vulnerability": {"id": "CVE-2099-0002", "severity": "High"}},
      {"vulnerability": {"id": "CVE-2099-0003", "severity": "Low"}}
    ]}'
""")
MISSING_BINARY_GRYPE = "echo 'grype: command not found' >&2; exit 127"
GARBAGE_OUTPUT_GRYPE = "echo 'not json at all' ; exit 0"


@pytest.mark.integration
class TestAuditYmlScanStep:
    STEP = "Scan with Grype"

    def test_clean_image_reports_zero_and_succeeds(self, tmp_path):
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, CLEAN_GRYPE)
        assert proc.returncode == 0, proc.stderr
        assert _parse_output(proc.gh_output)["high_count"] == "0"

    def test_vulnerable_image_reports_real_count_and_succeeds(self, tmp_path):
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VULNERABLE_GRYPE)
        assert proc.returncode == 0, proc.stderr
        assert _parse_output(proc.gh_output)["high_count"] == "2"  # 1 Critical + 1 High

    def test_missing_grype_binary_fails_closed_not_zero(self, tmp_path):
        """The exact real-world bug this fix targets: grype absent -> the step
        must fail, and MUST NOT write high_count=0."""
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, MISSING_BINARY_GRYPE)
        assert proc.returncode != 0
        assert "high_count" not in _parse_output(proc.gh_output)

    def test_garbage_grype_output_fails_closed(self, tmp_path):
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, GARBAGE_OUTPUT_GRYPE)
        assert proc.returncode != 0
        assert "high_count" not in _parse_output(proc.gh_output)


@pytest.mark.integration
class TestPromoteYmlScanStep:
    STEP = "Scan image for CVEs (Grype)"

    def test_clean_image_allows_promotion(self, tmp_path):
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, CLEAN_GRYPE)
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["high_count"] == "0"
        assert out["scan_failed"] == "false"

    def test_vulnerable_image_blocks_promotion_with_real_count(self, tmp_path):
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VULNERABLE_GRYPE)
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["high_count"] == "2"
        assert out["scan_failed"] == "true"

    def test_missing_grype_binary_fails_the_step_instead_of_reporting_999(self, tmp_path):
        """Anchor regression for SUP-03: the old code's `|| echo "999"`
        fallback would have set scan_failed=true with a fabricated count,
        which (once cooling elapsed) filed a fresh GitHub issue every single
        day forever. The fixed step must fail the step itself instead."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, MISSING_BINARY_GRYPE)
        assert proc.returncode != 0
        out = _parse_output(proc.gh_output)
        assert "high_count" not in out
        assert "scan_failed" not in out

    def test_garbage_grype_output_fails_the_step(self, tmp_path):
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, GARBAGE_OUTPUT_GRYPE)
        assert proc.returncode != 0


@pytest.mark.integration
class TestPublishYmlSelfScanStep:
    STEP = "Self-scan image with Grype"

    def test_clean_image_writes_clean_summary(self, tmp_path):
        script = _extract_run_block(".github/workflows/publish.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, CLEAN_GRYPE)
        assert proc.returncode == 0, proc.stderr
        assert "No HIGH/CRITICAL vulnerabilities found" in proc.gh_summary

    def test_vulnerable_image_writes_warning_summary_but_step_still_advisory(self, tmp_path):
        script = _extract_run_block(".github/workflows/publish.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VULNERABLE_GRYPE)
        assert proc.returncode == 0, proc.stderr
        assert "2 HIGH/CRITICAL vulnerabilities found" in proc.gh_summary

    def test_missing_grype_binary_reports_unknown_not_a_fabricated_clean_scan(self, tmp_path):
        """Anchor regression for SUP-04: the old step wrote a hardcoded
        "No HIGH/CRITICAL vulnerabilities found" into every release's step
        summary regardless of whether grype ran. The fixed step must say
        UNKNOWN, never assert a clean scan that didn't happen."""
        script = _extract_run_block(".github/workflows/publish.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, MISSING_BINARY_GRYPE)
        assert proc.returncode == 0  # advisory: exits 0 even on scan failure
        assert "UNKNOWN" in proc.gh_summary
        assert "No HIGH/CRITICAL vulnerabilities found" not in proc.gh_summary

    def test_garbage_output_reports_unknown(self, tmp_path):
        script = _extract_run_block(".github/workflows/publish.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, GARBAGE_OUTPUT_GRYPE)
        assert proc.returncode == 0
        assert "UNKNOWN" in proc.gh_summary
