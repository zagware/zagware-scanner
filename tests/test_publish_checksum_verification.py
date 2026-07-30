"""Tests for SUP-07/SUP-08: publish.yml's version/checksum verify steps must
read from the Dockerfile's own ARG defaults (single source of truth, no
duplicated literals) and must fail closed if the Dockerfile's pinned checksum
disagrees with the asset line inside the cosign-verified checksums.txt.

Before the fix, cosign verify-blob only proved checksums.txt itself was
authentic -- SYFT_CHECKSUM/GRYPE_CHECKSUM/BETTERLEAKS_CHECKSUM were
hand-typed literals duplicated in both publish.yml and the Dockerfile, never
cross-checked against the signed manifest either published under Dockerfile
verified against Dockerfile's own values. A transcription error or a value
copied from the wrong release would have gone undetected while still
printing "checksums.txt is real" -- exercised end-to-end here against the
REAL cosign binary and REAL upstream release artifacts, not a fake.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    import subprocess
    _HAS_COSIGN = shutil.which("cosign") is not None
except Exception:
    _HAS_COSIGN = False


def _extract_run_block(step_name: str) -> str:
    doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
    for step in doc["jobs"]["build-sign-push"]["steps"]:
        if step.get("name") == step_name:
            assert "run" in step
            return step["run"]
    raise AssertionError(f"step {step_name!r} not found")


def _dockerfile_env() -> dict[str, str]:
    """Parse the Dockerfile's own ARG defaults exactly the way the "Read
    pinned versions from Dockerfile" step's `sed -n 's/^ARG //p'` does."""
    env: dict[str, str] = {}
    for line in (REPO_ROOT / "Dockerfile").read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("ARG ") and "=" in stripped:
            key, _, value = stripped[4:].partition("=")
            env[key.strip()] = value.strip()
    return env


class TestSedExtractsAllPinnedValues:
    """The literal command the 'Read pinned versions from Dockerfile' step
    runs, checked against the real Dockerfile."""

    def test_sed_command_matches_the_shipped_step(self):
        script = _extract_run_block("Read pinned versions from Dockerfile")
        assert script.strip() == 'sed -n \'s/^ARG //p\' Dockerfile >> "$GITHUB_ENV"'

    def test_extracts_every_checksum_and_version_ARG(self):
        import os

        proc = subprocess.run(
            ["sed", "-n", "s/^ARG //p", "Dockerfile"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        )
        extracted = dict(
            line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
        )
        for name in ("KICS_VERSION", "KICS_CHECKSUM", "SYFT_VERSION", "SYFT_CHECKSUM",
                      "GRYPE_VERSION", "GRYPE_CHECKSUM", "BETTERLEAKS_VERSION",
                      "BETTERLEAKS_CHECKSUM"):
            assert name in extracted, f"{name} missing from sed extraction"


class TestBuildArgsRemoved:
    def test_build_and_push_step_has_no_build_args(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
        steps = doc["jobs"]["build-sign-push"]["steps"]
        build_step = next(s for s in steps if s.get("name", "").startswith("Build and push"))
        assert "build-args" not in build_step["with"], (
            "build-args duplicates the Dockerfile's own ARG defaults -- see SUP-08"
        )


@pytest.mark.integration
@pytest.mark.skipif(not _HAS_COSIGN, reason="cosign binary not available")
class TestChecksumVerificationAgainstRealUpstream:
    """Runs the REAL shipped bash against the REAL cosign binary and REAL
    upstream release artifacts (network required) -- not a reimplementation,
    not a fake. Exercises the fail-closed cross-check by deliberately
    corrupting the Dockerfile's pinned checksum in a scratch copy."""

    def _run_verify_step(self, step_name: str, env_overrides: dict, tmp_path: Path):
        import os

        script = _extract_run_block(step_name)
        env = dict(os.environ)
        env.update(_dockerfile_env())
        env.update(env_overrides)
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
        )

    def test_syft_checksum_matches_real_signed_manifest(self, tmp_path):
        proc = self._run_verify_step("Verify Syft release signature", {}, tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Dockerfile's pinned SYFT_CHECKSUM matches the signed manifest" in proc.stdout

    def test_grype_checksum_matches_real_signed_manifest(self, tmp_path):
        proc = self._run_verify_step("Verify Grype release signature", {}, tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Dockerfile's pinned GRYPE_CHECKSUM matches the signed manifest" in proc.stdout

    def test_betterleaks_checksum_matches_real_signed_manifest(self, tmp_path):
        proc = self._run_verify_step("Verify Betterleaks release signature", {}, tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Dockerfile's pinned BETTERLEAKS_CHECKSUM matches the signed manifest" in proc.stdout

    def test_a_wrong_pinned_checksum_fails_closed(self, tmp_path):
        """Anchor: a Dockerfile transcription error must break the build,
        not silently pass because the file itself was authentic."""
        proc = self._run_verify_step(
            "Verify Syft release signature",
            {"SYFT_CHECKSUM": "0" * 64},
            tmp_path,
        )
        assert proc.returncode != 0
        assert "does not match the signed manifest" in (proc.stdout + proc.stderr)
