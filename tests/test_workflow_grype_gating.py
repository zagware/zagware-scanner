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
was never installed on the runner (see the 2026-07-30 audit, Verified
evidence #1). A script that can print a fabricated "0"/"999" must never pass
these tests again.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import textwrap
from datetime import datetime
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


def _run_bash_step(script: str, tmp_path: Path, fake_grype_body: str,
                   env_overrides: dict | None = None) -> subprocess.CompletedProcess:
    """Execute `script` the way GitHub Actions executes a run: step with the
    default shell (bash -eo pipefail {0}) on a Linux runner, with a fake
    `grype` shadowing the real one on PATH.

    `env_overrides` stands in for the step's own `env:` block, which the
    extracted run text does not carry -- HAS_NEWER reaches the gate that way
    precisely so the script stays free of ${{ }} and remains executable here."""
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
    env.update(env_overrides or {})

    resolved = _resolve_gh_expressions(script)
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", resolved],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
    )
    proc.gh_output = gh_output.read_text()
    proc.gh_summary = gh_summary.read_text()
    return proc


# What the "Check whether a newer release exists" step hands the gate.
ALL_ON_LATEST = '{"syft":false,"grype":false,"betterleaks":false,"osv-scanner":false}'
SYFT_BEHIND = '{"syft":true,"grype":false,"betterleaks":false,"osv-scanner":false}'


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


def _match(cve: str, severity: str, pkg: str, owner: str, fix: str) -> str:
    """One Grype match, shaped the way the real presenter emits it."""
    return json.dumps({
        "vulnerability": {"id": cve, "severity": severity, "fix": {"state": fix}},
        "artifact": {"name": pkg, "version": "1.0.0",
                     "locations": [{"path": owner}]},
    })


def _grype_stub(*matches: str) -> str:
    return "cat <<'EOF'\n" + json.dumps({"matches": [json.loads(m) for m in matches]}) + "\nEOF"


# Findings a base re-pin or a Dockerfile version bump would clear: an OS
# package from the Wolfi base, and Go stdlib inside kics -- which this repo
# compiles itself, so its toolchain is a pin we control.
ACTIONABLE_GRYPE = _grype_stub(
    _match("CVE-2099-1001", "High", "libcrypto3", "/usr/lib/libcrypto.so.3", "fixed"),
    _match("GO-2099-1002", "High", "stdlib", "/usr/local/bin/kics", "fixed"),
)

# Go stdlib inside VENDOR-built binaries. Grype calls these fixed because Go
# published the patch, but no pin we own applies it -- only Anchore's and
# betterleaks' next release does. Reported, never blocking; this is the exact
# class that kept :stable from ever existing under the old raw-count gate.
VENDOR_STDLIB_GRYPE = _grype_stub(
    _match("GO-2099-2001", "High", "stdlib", "/usr/bin/syft", "fixed"),
    _match("GO-2099-2002", "High", "stdlib", "/usr/local/bin/osv-scanner", "fixed"),
)

# A vendored MODULE (not stdlib) inside a vendor binary. A newer upstream
# release of that tool clears it, so bumping our pin is a real remedy and it
# must block -- this is what actually happened with go-git in Syft v1.51.0.
VENDOR_MODULE_GRYPE = _grype_stub(
    _match("GHSA-2099-3001", "High", "github.com/go-git/go-git/v5", "/usr/bin/syft", "fixed"),
)

# No fix exists anywhere: the containerd advisories in kics, patched only in a
# containerd/v2 module path kics does not use.
UNFIXABLE_GRYPE = _grype_stub(
    _match("GO-2099-4001", "Critical", "github.com/containerd/containerd",
           "/usr/local/bin/kics", ""),
)

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

    def test_actionable_findings_are_counted_as_actionable(self, tmp_path):
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        out = _parse_output(_run_bash_step(script, tmp_path, ACTIONABLE_GRYPE).gh_output)
        assert out["high_count"] == "2"
        assert out["fixable_count"] == "2"
        assert out["actionable_count"] == "2"

    def test_vendor_stdlib_is_reported_but_not_actionable(self, tmp_path):
        """Reported in the total AND in fixable -- the audit never hides a
        finding -- but it must not raise a weekly alert nobody here can close."""
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        out = _parse_output(_run_bash_step(script, tmp_path, VENDOR_STDLIB_GRYPE).gh_output)
        assert out["high_count"] == "2"
        assert out["fixable_count"] == "2"
        assert out["actionable_count"] == "0"

    def test_unfixable_finding_is_reported_but_not_actionable(self, tmp_path):
        script = _extract_run_block(".github/workflows/audit.yml", self.STEP)
        out = _parse_output(_run_bash_step(script, tmp_path, UNFIXABLE_GRYPE).gh_output)
        assert out["high_count"] == "1"
        assert out["fixable_count"] == "0"
        assert out["actionable_count"] == "0"

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

    def test_unfixable_findings_do_not_block_promotion(self, tmp_path):
        """VULNERABLE_GRYPE carries no fix data at all. It is real, it is
        counted, and it must not block: no version of anything closes it."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VULNERABLE_GRYPE)
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["high_count"] == "2"
        assert out["blocking_count"] == "0"
        assert out["scan_failed"] == "false"

    def test_actionable_findings_block_promotion(self, tmp_path):
        """An OS package we can re-pin and stdlib in the binary we compile
        ourselves: both have a remedy on our side, so both must block."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, ACTIONABLE_GRYPE)
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["high_count"] == "2"
        assert out["fixable_count"] == "2"
        assert out["blocking_count"] == "2"
        assert out["scan_failed"] == "true"
        assert "libcrypto3" in proc.stdout, "the log must name each blocking finding"
        assert "kics" in proc.stdout

    def test_vendor_stdlib_does_not_block_promotion(self, tmp_path):
        """The regression this whole gate change exists for: 32 of the 50
        critical/high in the 2026-08-25 image were exactly this shape, and a
        raw-count gate meant :stable could never be published at all."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VENDOR_STDLIB_GRYPE)
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["high_count"] == "2"
        assert out["fixable_count"] == "2", "still reported as fixable, just not ours"
        assert out["blocking_count"] == "0"
        assert out["scan_failed"] == "false"

    def test_vendor_module_blocks_when_a_newer_release_exists(self, tmp_path):
        """Not stdlib, and Syft has shipped a newer version: bumping the pin is
        a real remedy, so the gate must demand it. Without this, 'vendor binary'
        would become a blanket exemption. This is the go-git case that Syft
        v1.51.0 actually cleared."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VENDOR_MODULE_GRYPE,
                              {"HAS_NEWER": SYFT_BEHIND})
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["blocking_count"] == "1"
        assert out["scan_failed"] == "true"

    def test_vendor_module_does_not_block_when_already_on_latest(self, tmp_path):
        """The 35-day case. GO-2026-5970 (x/text) published 2026-07-14 and no
        betterleaks release carried the fix until 1.8.1 on 2026-08-18. While we
        are on the newest release there is no pin to bump, so demanding one is
        the same unsatisfiable gate that kept :stable from ever existing."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VENDOR_MODULE_GRYPE,
                              {"HAS_NEWER": ALL_ON_LATEST})
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["high_count"] == "1"
        assert out["fixable_count"] == "1", "still reported as fixable upstream"
        assert out["blocking_count"] == "0"
        assert out["scan_failed"] == "false"

    def test_our_own_findings_block_regardless_of_upstream_releases(self, tmp_path):
        """The remedy probe must not leak into the classes we control. OS
        packages and kics are ours whatever Anchore has or has not shipped."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, ACTIONABLE_GRYPE,
                              {"HAS_NEWER": ALL_ON_LATEST})
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["blocking_count"] == "2"
        assert out["scan_failed"] == "true"

    def test_vendor_stdlib_never_blocks_even_when_behind(self, tmp_path):
        """Syft v1.51.1 shipped 2026-08-27, fourteen days after Go 1.26.6, and
        is still built with go1.26.3 carrying all seven stdlib advisories. A
        newer release existing does not mean a newer toolchain, so stdlib stays
        exempt or the gate closes on a bump that would not help."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VENDOR_STDLIB_GRYPE,
                              {"HAS_NEWER": SYFT_BEHIND})
        assert proc.returncode == 0, proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["blocking_count"] == "0"
        assert out["scan_failed"] == "false"

    def test_missing_probe_output_withholds_the_vendor_module_block(self, tmp_path):
        """No HAS_NEWER at all means no evidence a remedy exists. Withhold the
        block rather than invent one -- inventing is the fabricated-answer class
        SUP-01 removed from these gates."""
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        proc = _run_bash_step(script, tmp_path, VENDOR_MODULE_GRYPE)
        assert proc.returncode == 0, proc.stderr
        assert _parse_output(proc.gh_output)["blocking_count"] == "0"

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


PREDICATE_EXPR_MAP = {
    "steps.latest.outputs.digest": TEST_DIGEST,
    "steps.latest.outputs.previous_stable_digest": "sha256:" + "cd" * 32,
    "steps.latest.outputs.age_days": "17",
    "steps.scan.outputs.high_count": "28",
    "steps.scan.outputs.fixable_count": "25",
    "steps.scan.outputs.blocking_count": "0",
    "github.server_url": "https://github.com",
    "github.repository": "zagware/zagware-scanner",
    "github.run_id": "123456789",
}


def _resolve_predicate_expressions(script: str) -> str:
    """Substitute the wider set of `${{ ... }}` expressions the "Build
    promotion predicate" step references (steps.*.outputs.* plus github.*),
    the way the Actions runner would before handing the script to bash."""
    resolved = script
    for expr, value in PREDICATE_EXPR_MAP.items():
        resolved = re.sub(r"\$\{\{\s*" + re.escape(expr) + r"\s*\}\}", value, resolved)
    assert "${{" not in resolved, f"unresolved GH expression left in script:\n{resolved}"
    return resolved


def _run_predicate_step(script: str, tmp_path: Path) -> subprocess.CompletedProcess:
    """Execute the predicate-building step's bash directly -- it shells out
    only to jq/date, no fake binary needed."""
    resolved = _resolve_predicate_expressions(script)
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", resolved],
        cwd=tmp_path, capture_output=True, text=True, timeout=15,
    )


@pytest.mark.integration
class TestPromoteYmlPredicateStep:
    """SUP-05: actions/attest requires predicate-type (always required) and
    exactly one of predicate/predicate-path (both required). Before the fix,
    promote.yml's "Attest promotion" step supplied neither, so the workflow
    re-tagged and signed :stable/:secure and then failed red at attestation
    -- tags moved, run failed. This locks in (1) the shipped bash that builds
    the predicate JSON, and (2) that the attest step's own `with:` block
    actually declares the two required inputs."""

    STEP = "Build promotion predicate"

    def test_produces_valid_predicate_json(self, tmp_path):
        script = _extract_run_block(".github/workflows/promote.yml", self.STEP)
        predicate_path = Path("/tmp/promotion-predicate.json")
        predicate_path.unlink(missing_ok=True)
        proc = _run_predicate_step(script, tmp_path)
        assert proc.returncode == 0, proc.stderr
        predicate = json.loads(predicate_path.read_text())
        assert predicate["digest"] == TEST_DIGEST
        assert predicate["promotedTags"] == ["stable", "secure"]
        assert predicate["sourceTag"] == "latest"
        # real ints, not the string forms the GH expressions resolve to
        assert predicate["coolingPeriodDays"] == 17
        # The signed record keeps all three numbers. A promoted digest that
        # carried 28 critical/high must say so; what promotion asserts is that
        # none of them were ours to close, not that there were none.
        assert predicate["cveScan"] == {
            "tool": "grype",
            "highOrCriticalCount": 28,
            "fixableCount": 25,
            "actionableCount": 0,
        }
        assert predicate["workflowRun"] == (
            "https://github.com/zagware/zagware-scanner/actions/runs/123456789"
        )
        # a real timestamp, not a literal unresolved expression
        datetime.fromisoformat(predicate["promotedAt"].replace("Z", "+00:00"))
        predicate_path.unlink(missing_ok=True)

    def test_attest_step_declares_required_predicate_inputs(self):
        """Direct regression for the review's exact defect: predicate-type is
        a required input to actions/attest and neither it nor
        predicate/predicate-path was ever supplied."""
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/promote.yml").read_text())
        steps = doc["jobs"]["promote"]["steps"]
        attest_step = next(s for s in steps if s.get("name") == "Attest promotion")
        with_block = attest_step.get("with", {})
        assert with_block.get("predicate-type"), "predicate-type is required by actions/attest"
        has_predicate = bool(with_block.get("predicate"))
        has_predicate_path = bool(with_block.get("predicate-path"))
        assert has_predicate != has_predicate_path, (
            "actions/attest requires exactly one of predicate or predicate-path"
        )


class TestVendorBinaryListIsSingleSourced:
    """promote.yml and audit.yml each declare VENDOR_BINARIES, and the two
    gates only agree on what "actionable" means while the lists are identical.
    Same test-enforced-duplication arrangement install-grype uses for the Grype
    pin: the copy is allowed, the drift is not.

    The membership itself is load-bearing, not cosmetic. A name added here is
    exempted from blocking on stdlib findings forever, so the list must contain
    exactly the binaries somebody else builds and signs -- never kics, which
    this repo compiles from source and whose toolchain is ours to re-pin."""

    LIST_RE = re.compile(r"VENDOR_BINARIES='(\[[^']*\])'")

    def _list(self, workflow: str) -> list[str]:
        text = (REPO_ROOT / workflow).read_text()
        found = self.LIST_RE.findall(text)
        assert len(found) == 1, f"{workflow} must declare VENDOR_BINARIES exactly once"
        return json.loads(found[0])

    def test_both_gates_declare_the_same_vendor_binaries(self):
        assert (self._list(".github/workflows/promote.yml")
                == self._list(".github/workflows/audit.yml"))

    def test_list_is_exactly_the_externally_built_binaries(self):
        assert self._list(".github/workflows/promote.yml") == [
            "syft", "grype", "betterleaks", "osv-scanner",
        ]

    def test_kics_is_never_exempt(self):
        """kics is built here, from source, with a Go toolchain pinned in the
        Dockerfile -- every stdlib CVE it carries is closed by editing
        GO_VERSION. Exempting it would silence the one class of stdlib finding
        this repo can actually fix."""
        for workflow in (".github/workflows/promote.yml", ".github/workflows/audit.yml"):
            assert "kics" not in self._list(workflow)
