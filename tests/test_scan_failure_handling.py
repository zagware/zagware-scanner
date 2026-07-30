"""Tests for QUAL-01 (SCA/Secrets tool failure must raise, not return "zero
findings") and QUAL-02 (unknown repo visibility must fail closed under
ZAGWARE_SECRETS_FAIL_ON_PUBLIC, not silently disable the gate).

Anchor regression both defend against: before the fix, a missing/crashed
Syft, Grype, or betterleaks binary made run_sca_scan()/run_secrets_scan()
return [] — indistinguishable from "scanned successfully, found nothing" —
so the PR comment asserted "No new findings" while nothing was actually
scanned. This is the same failure shape independently proven live in this
repo's own CI workflows (grype never installed on the runner — see
REVIEW-2026-07-30.md Verified evidence #1).
"""
from __future__ import annotations

import json

import pytest

import scanner


# ── QUAL-01: ScanFailure, not [] ────────────────────────────────────────────

class TestScanFailureIsARuntimeError:
    def test_scan_failure_subclasses_runtime_error(self):
        """Existing `except RuntimeError` handlers (if any remain anywhere)
        must keep working — this is a deliberate, not incidental, hierarchy."""
        assert issubclass(scanner.ScanFailure, RuntimeError)

    def test_run_scan_raises_scan_failure_on_unreadable_output(self, tmp_path, monkeypatch):
        """run_scan (IaC/KICS) already had this contract — pin that it now
        raises the shared ScanFailure type specifically, not a bare
        RuntimeError, so all three scanners are catchable uniformly."""
        class _FakeCompletedProcess:
            returncode = 0
            stderr = ""

        monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: _FakeCompletedProcess())
        missing_output = str(tmp_path / "does-not-exist.json")
        with pytest.raises(scanner.ScanFailure):
            scanner.run_scan(str(tmp_path), missing_output)


class TestRunScaScanRaisesOnToolFailure:
    def _touch_manifest(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")

    def test_raises_scan_failure_when_syft_fails(self, tmp_path, monkeypatch):
        self._touch_manifest(tmp_path)
        monkeypatch.setattr(scanner, "_run_syft", lambda path, out: False)
        with pytest.raises(scanner.ScanFailure, match="Syft failed"):
            scanner.run_sca_scan(str(tmp_path), str(tmp_path), "base")

    def test_raises_scan_failure_when_grype_fails(self, tmp_path, monkeypatch):
        self._touch_manifest(tmp_path)
        monkeypatch.setattr(scanner, "_run_syft", lambda path, out: True)
        monkeypatch.setattr(scanner, "_run_grype", lambda sbom, out: False)
        with pytest.raises(scanner.ScanFailure, match="Grype failed"):
            scanner.run_sca_scan(str(tmp_path), str(tmp_path), "base")

    def test_raises_scan_failure_when_grype_output_unparseable(self, tmp_path, monkeypatch):
        self._touch_manifest(tmp_path)
        monkeypatch.setattr(scanner, "_run_syft", lambda path, out: True)

        def _fake_grype(sbom, out):
            Path = scanner.Path
            Path(out).write_text("not valid json {{{")
            return True
        monkeypatch.setattr(scanner, "_run_grype", _fake_grype)
        with pytest.raises(scanner.ScanFailure, match="could not read Grype output"):
            scanner.run_sca_scan(str(tmp_path), str(tmp_path), "base")

    def test_returns_empty_list_when_genuinely_clean(self, tmp_path, monkeypatch):
        """The positive control: a real successful scan with zero matches
        must still return [] — QUAL-01 does not remove the legitimate
        "scanned clean" outcome, only the confusable failure-as-clean one."""
        self._touch_manifest(tmp_path)
        monkeypatch.setattr(scanner, "_run_syft", lambda path, out: True)

        def _fake_grype(sbom, out):
            scanner.Path(out).write_text(json.dumps({"matches": []}))
            return True
        monkeypatch.setattr(scanner, "_run_grype", _fake_grype)
        result = scanner.run_sca_scan(str(tmp_path), str(tmp_path), "base")
        assert result == []

    def test_returns_none_when_disabled(self, tmp_path, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCA_ENABLED="false")
        assert mod.run_sca_scan(str(tmp_path), str(tmp_path), "base") is None

    def test_returns_none_when_no_manifests(self, tmp_path):
        assert scanner.run_sca_scan(str(tmp_path), str(tmp_path), "base") is None


class TestRunSecretsScanRaisesOnToolFailure:
    def test_raises_scan_failure_when_binary_missing(self, tmp_path, monkeypatch):
        def _raise_not_found(*a, **k):
            raise FileNotFoundError("betterleaks: no such file")
        monkeypatch.setattr(scanner.subprocess, "run", _raise_not_found)
        with pytest.raises(scanner.ScanFailure, match="unavailable"):
            scanner.run_secrets_scan(str(tmp_path), str(tmp_path), "base")

    def test_raises_scan_failure_on_timeout(self, tmp_path, monkeypatch):
        def _raise_timeout(*a, **k):
            raise scanner.subprocess.TimeoutExpired(cmd="betterleaks", timeout=300)
        monkeypatch.setattr(scanner.subprocess, "run", _raise_timeout)
        with pytest.raises(scanner.ScanFailure, match="unavailable"):
            scanner.run_secrets_scan(str(tmp_path), str(tmp_path), "base")

    def test_raises_scan_failure_when_report_unreadable(self, tmp_path, monkeypatch):
        class _FakeCompletedProcess:
            returncode = 0
            stderr = ""
            stdout = ""
        monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: _FakeCompletedProcess())
        # out_json is never written by the fake subprocess call -> unreadable
        with pytest.raises(scanner.ScanFailure, match="could not read betterleaks output"):
            scanner.run_secrets_scan(str(tmp_path), str(tmp_path), "base")

    def test_returns_empty_list_when_genuinely_clean(self, tmp_path, monkeypatch):
        """betterleaks writes literal JSON `null` for zero findings — this
        MUST still resolve to [] (clean), not a failure."""
        class _FakeCompletedProcess:
            returncode = 0
            stderr = ""
            stdout = ""

        def _fake_run(cmd, **kwargs):
            out_json = cmd[cmd.index("--report-path") + 1]
            scanner.Path(out_json).write_text("null")
            return _FakeCompletedProcess()

        monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
        result = scanner.run_secrets_scan(str(tmp_path), str(tmp_path), "base")
        assert result == []

    def test_returns_none_when_disabled(self, tmp_path, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_ENABLED="false")
        assert mod.run_secrets_scan(str(tmp_path), str(tmp_path), "base") is None


# ── QUAL-02: fail closed on unknown visibility ──────────────────────────────

class TestSecretsPublicGate:
    def test_public_repo_with_new_secrets_fails(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="true")
        should_fail, reason = mod._secrets_public_gate("public", True)
        assert should_fail is True
        assert reason == "public"

    def test_unknown_visibility_with_new_secrets_fails_closed_by_default(self, reload_scanner):
        """The core QUAL-02 fix: 'unknown' is NOT a silent pass."""
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="true", ZAGWARE_ASSUME_PRIVATE=None)
        should_fail, reason = mod._secrets_public_gate("unknown", True)
        assert should_fail is True
        assert reason == "unknown"

    def test_unknown_visibility_opt_out_via_assume_private(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="true", ZAGWARE_ASSUME_PRIVATE="true")
        should_fail, reason = mod._secrets_public_gate("unknown", True)
        assert should_fail is False
        assert reason is None

    def test_private_repo_never_fails(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="true")
        should_fail, reason = mod._secrets_public_gate("private", True)
        assert should_fail is False

    def test_internal_repo_never_fails(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="true")
        should_fail, reason = mod._secrets_public_gate("internal", True)
        assert should_fail is False

    def test_no_novel_secrets_never_fails_regardless_of_visibility(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="true")
        for vis in ("public", "unknown", "private"):
            should_fail, reason = mod._secrets_public_gate(vis, False)
            assert should_fail is False, vis

    def test_gate_disabled_never_fails_even_on_public(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="false")
        should_fail, reason = mod._secrets_public_gate("public", True)
        assert should_fail is False


class TestRepoVisibilityLogsWarningNotDebug:
    """The except-block log level must be visible at default INFO — a
    missing permission or transient API error must not vanish silently the
    way log.debug would (invisible unless ZAGWARE_DEBUG=1)."""

    def test_github_visibility_failure_logs_warning(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("GITHUB_TOKEN", "t")
        monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
        gh = scanner.GitHub()
        monkeypatch.setattr(scanner, "_http", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        with caplog.at_level(logging.WARNING, logger="zagware"):
            result = gh.repo_visibility()
        assert result == "unknown"
        assert any("Could not determine repo visibility" in r.message for r in caplog.records)


class TestRenderSecretsSectionVisibilityBanners:
    def _findings(self):
        return [{"rule_id": "generic-api-key", "file_path": "config.py", "line": 10,
                  "tags": [], "validation_status": "unknown", "similarity_id": "a" * 64}]

    def test_public_banner_shown(self):
        out = scanner.render_secrets_section(None, self._findings(), self._findings(), "public")
        assert "PUBLIC REPOSITORY" in out

    def test_unknown_banner_shown_with_assume_private_hint(self):
        out = scanner.render_secrets_section(None, self._findings(), self._findings(), "unknown")
        assert "could not be determined" in out
        assert "ZAGWARE_ASSUME_PRIVATE" in out

    def test_private_repo_shows_neither_banner(self):
        out = scanner.render_secrets_section(None, self._findings(), self._findings(), "private")
        assert "PUBLIC REPOSITORY" not in out
        assert "could not be determined" not in out

    def test_internal_repo_shows_neither_banner(self):
        out = scanner.render_secrets_section(None, self._findings(), self._findings(), "internal")
        assert "PUBLIC REPOSITORY" not in out
        assert "could not be determined" not in out
