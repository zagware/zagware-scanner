"""Tests for SUP-12: promote.yml must verify the :latest digest actually
carries a valid keyless signature from THIS repo's publish workflow before
re-tagging it to :stable/:secure, and must not waste two redundant Rekor
signing entries re-signing a digest publish.yml already signed.

Before the fix, promote.yml installed cosign but never called `cosign
verify` -- promotion was gated solely on tag age and a CVE count, so if the
:latest pointer were ever moved by anything other than publish.yml (the
workflow_dispatch hole SUP-02 closed, or a compromised credential), nothing
would stop that digest from being promoted to :stable and :secure. The
redundant "Sign promoted tags" step then signed a digest that was already
signed by publish.yml -- cosign signatures are keyed to the digest, not the
tag, so this only ever added noise to the Rekor log.

Exercises the REAL shipped bash against the REAL cosign binary and REAL
public keyless-signed/unsigned images -- not a reimplementation.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
_HAS_COSIGN = shutil.which("cosign") is not None


def _extract_run_block(step_name: str) -> str:
    doc = yaml.safe_load((REPO_ROOT / ".github/workflows/promote.yml").read_text())
    for step in doc["jobs"]["promote"]["steps"]:
        if step.get("name") == step_name:
            assert "run" in step
            return step["run"]
    raise AssertionError(f"step {step_name!r} not found")


class TestSignStepRemoved:
    def test_no_sign_promoted_tags_step_remains(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/promote.yml").read_text())
        names = [s.get("name") for s in doc["jobs"]["promote"]["steps"]]
        assert "Sign promoted tags" not in names, (
            "cosign signatures are keyed to the digest, not the tag -- "
            "publish.yml already signed this digest. See SUP-12."
        )


class TestVerifyStepGatesPromotion:
    def test_verify_step_exists_before_promote_step(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/promote.yml").read_text())
        steps = doc["jobs"]["promote"]["steps"]
        names = [s.get("name") for s in steps]
        assert "Verify :latest image signature" in names
        verify_idx = names.index("Verify :latest image signature")
        promote_idx = names.index("Promote to stable and secure")
        assert verify_idx < promote_idx, (
            "the signature verify step must run before promotion, or a bad "
            "digest could already be re-tagged before the check fires"
        )

    def test_verify_step_has_no_continue_on_error(self):
        """A failed cosign verify must fail the whole job (blocking every
        later step), not be swallowed."""
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/promote.yml").read_text())
        steps = doc["jobs"]["promote"]["steps"]
        step = next(s for s in steps if s.get("name") == "Verify :latest image signature")
        assert step.get("continue-on-error") is not True

    def test_verify_step_uses_repo_identity_regexp_and_oidc_issuer(self):
        script = _extract_run_block("Verify :latest image signature")
        assert "--certificate-identity-regexp" in script
        assert "github.com/zagware/zagware-scanner" in script
        assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in script


@pytest.mark.integration
@pytest.mark.skipif(not _HAS_COSIGN, reason="cosign binary not available")
class TestVerifyAgainstRealCosign:
    """The real shipped bash, run against real public images, with the
    image ref and identity substituted via env (the script only ever
    references IMAGE_REF built from a GH expression plus the hardcoded
    zagware identity -- we override both at execution time)."""

    def _run(self, image_ref: str, identity_regexp: str, oidc_issuer: str, tmp_path: Path):
        script = _extract_run_block("Verify :latest image signature")
        script = script.replace(
            'IMAGE_REF="ghcr.io/zagware/zagware-scanner@${{ steps.latest.outputs.digest }}"',
            f'IMAGE_REF="{image_ref}"',
        ).replace(
            '"^https://github.com/zagware/zagware-scanner/.+$"',
            f'"{identity_regexp}"',
        ).replace(
            "https://token.actions.githubusercontent.com",
            oidc_issuer,
        )
        assert "${{" not in script
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=tmp_path, capture_output=True, text=True, timeout=60,
        )

    def test_succeeds_for_a_real_matching_signature(self, tmp_path):
        proc = self._run(
            "ghcr.io/sigstore/cosign/cosign:v2.2.0",
            "^keyless@projectsigstore\\.iam\\.gserviceaccount\\.com$",
            "https://accounts.google.com",
            tmp_path,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Signature verified" in proc.stdout

    def test_fails_closed_for_a_real_signature_with_wrong_identity(self, tmp_path):
        """The exact SUP-12 scenario: a real signature exists, but not from
        the identity the caller expects -- must fail, not pass because
        *some* signature was present."""
        proc = self._run(
            "ghcr.io/sigstore/cosign/cosign:v2.2.0",
            "^https://github.com/zagware/zagware-scanner/.+$",
            "https://token.actions.githubusercontent.com",
            tmp_path,
        )
        assert proc.returncode != 0
        assert "Signature verified" not in proc.stdout

    def test_fails_closed_for_an_unsigned_image(self, tmp_path):
        proc = self._run(
            "ghcr.io/anchore/grype:latest",
            "^https://github.com/zagware/zagware-scanner/.+$",
            "https://token.actions.githubusercontent.com",
            tmp_path,
        )
        assert proc.returncode != 0
        assert "Signature verified" not in proc.stdout
