"""Tests for QUAL-04: a KICS timeout or a missing KICS binary must surface as
a caught ScanFailure, not an unhandled traceback.

Before the fix, run_scan called
`subprocess.run(cmd, ..., timeout=600)` with no try. The only try/except in
the function wraps the *output file* read below it, so subprocess.TimeoutExpired
(after a hardcoded 600s) and FileNotFoundError (bad _ZAGWARE_SCANNER_BIN, or a
PATH/mount problem in the image) both propagated. main() catches only
RuntimeError, and __main__ had no handler at all -- so the process died on the
traceback, telemetry_flush() never ran, track_scan_failed was never sent, and
the resulting exit was indistinguishable from ZAGWARE_FAIL_ON_NEW legitimately
blocking the merge.

_run_syft/_run_grype/run_secrets_scan all already caught
(FileNotFoundError, subprocess.TimeoutExpired); the IaC path was the outlier,
and the only one whose timeout is long enough to be hit in normal use.
"""
from __future__ import annotations

import subprocess

import pytest

import scanner


class TestEnvInt:
    """_SCAN_TIMEOUT's parser: same fail-safe contract as _env_bool."""

    def test_unset_uses_default(self, monkeypatch):
        monkeypatch.delenv("X_TIMEOUT", raising=False)
        assert scanner._env_int("X_TIMEOUT", 600) == 600

    def test_empty_uses_default(self, monkeypatch):
        monkeypatch.setenv("X_TIMEOUT", "")
        assert scanner._env_int("X_TIMEOUT", 600) == 600

    def test_valid_value_is_used(self, monkeypatch):
        monkeypatch.setenv("X_TIMEOUT", "1800")
        assert scanner._env_int("X_TIMEOUT", 600) == 1800

    def test_whitespace_is_trimmed(self, monkeypatch):
        monkeypatch.setenv("X_TIMEOUT", "  900  ")
        assert scanner._env_int("X_TIMEOUT", 600) == 900

    def test_garbage_falls_back_and_warns(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("X_TIMEOUT", "ten minutes")
        with caplog.at_level(logging.WARNING):
            assert scanner._env_int("X_TIMEOUT", 600) == 600
        assert "not an integer" in caplog.text

    def test_below_minimum_falls_back_and_warns(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("X_TIMEOUT", "0")
        with caplog.at_level(logging.WARNING):
            assert scanner._env_int("X_TIMEOUT", 600) == 600
        assert "below the minimum" in caplog.text

    def test_negative_falls_back(self, monkeypatch):
        monkeypatch.setenv("X_TIMEOUT", "-5")
        assert scanner._env_int("X_TIMEOUT", 600) == 600


class TestScanTimeoutIsConfigurable:
    def test_default_is_600(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCAN_TIMEOUT=None)
        assert mod._SCAN_TIMEOUT == 600

    def test_env_override_is_honoured(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCAN_TIMEOUT="1800")
        assert mod._SCAN_TIMEOUT == 1800

    def test_configured_value_is_passed_to_subprocess(self, reload_scanner, monkeypatch, tmp_path):
        """The knob must actually reach subprocess.run -- a constant that is
        read but not threaded through would be worse than no knob at all."""
        mod = reload_scanner(ZAGWARE_SCAN_TIMEOUT="1234")
        captured = {}

        def _fake_run(cmd, **kwargs):
            captured.update(kwargs)
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

        monkeypatch.setattr(mod.subprocess, "run", _fake_run)
        with pytest.raises(mod.ScanFailure):
            mod.run_scan(str(tmp_path), str(tmp_path / "out.json"))
        assert captured["timeout"] == 1234


class TestKicsTimeoutIsCaught:
    def test_timeout_raises_scanfailure_not_timeoutexpired(self, monkeypatch, tmp_path):
        """The exact QUAL-04 bug: TimeoutExpired escaped run_scan entirely."""
        def _fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 600))

        monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
        with pytest.raises(scanner.ScanFailure) as ei:
            scanner.run_scan(str(tmp_path), str(tmp_path / "out.json"))
        msg = str(ei.value)
        assert "NOT 'no findings'" in msg
        assert "ZAGWARE_SCAN_TIMEOUT" in msg, "the error must name the knob that fixes it"

    def test_scanfailure_is_a_runtimeerror_so_main_catches_it(self):
        """main() guards run_scan with `except RuntimeError`; ScanFailure must
        remain a subclass or the new raise would still escape."""
        assert issubclass(scanner.ScanFailure, RuntimeError)


class TestMissingKicsBinaryIsCaught:
    def test_missing_binary_raises_scanfailure(self, monkeypatch, tmp_path):
        def _fake_run(cmd, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", cmd[0])

        monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
        with pytest.raises(scanner.ScanFailure) as ei:
            scanner.run_scan(str(tmp_path), str(tmp_path / "out.json"))
        msg = str(ei.value)
        assert "NOT 'no findings'" in msg
        assert "_ZAGWARE_SCANNER_BIN" in msg, "the error must name the override to check"

    def test_missing_binary_does_not_leak_filenotfounderror(self, monkeypatch, tmp_path):
        """FileNotFoundError specifically must not escape: the output-file
        handler below also catches FileNotFoundError, so a naive fix could
        mask a missing binary as 'output not readable'. These must stay
        distinguishable."""
        def _fake_run(cmd, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", cmd[0])

        monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
        with pytest.raises(scanner.ScanFailure) as ei:
            scanner.run_scan(str(tmp_path), str(tmp_path / "out.json"))
        assert "binary not found" in str(ei.value)
        assert "output not readable" not in str(ei.value)


class TestTopLevelCrashHandler:
    """_run_cli() must convert an unhandled exception into a distinct exit
    code AND still flush telemetry, rather than dying on the traceback before
    telemetry_flush() ever runs."""

    def test_crash_exit_code_is_distinct_from_policy_failure(self):
        assert scanner._EXIT_CRASH == 2
        assert scanner._EXIT_CRASH != 1, "a crash must not look like a policy gate firing"

    def test_clean_run_passes_the_exit_code_through(self, monkeypatch):
        monkeypatch.setattr(scanner, "main", lambda: 0)
        assert scanner._run_cli() == 0

    def test_policy_failure_exit_code_is_preserved(self, monkeypatch):
        """A legitimate exit 1 from main() must NOT be rewritten to 2."""
        monkeypatch.setattr(scanner, "main", lambda: 1)
        assert scanner._run_cli() == 1

    def test_unhandled_exception_becomes_crash_exit_code(self, monkeypatch):
        def _boom():
            raise ValueError("simulated crash")

        monkeypatch.setattr(scanner, "main", _boom)
        assert scanner._run_cli() == scanner._EXIT_CRASH

    def test_unhandled_exception_is_logged_with_traceback(self, monkeypatch, caplog):
        import logging

        def _boom():
            raise ValueError("simulated crash")

        monkeypatch.setattr(scanner, "main", _boom)
        with caplog.at_level(logging.ERROR):
            scanner._run_cli()
        assert "crashed unexpectedly" in caplog.text
        assert "ValueError" in caplog.text
        assert "simulated crash" in caplog.text

    def test_telemetry_is_flushed_even_when_main_crashes(self, monkeypatch):
        """The whole point of QUAL-04's backstop: before it, the traceback
        killed the process before telemetry_flush() ran."""
        flushed = []
        monkeypatch.setattr(scanner, "telemetry_flush", lambda *a, **k: flushed.append(True))
        monkeypatch.setattr(scanner, "main", lambda: (_ for _ in ()).throw(ValueError("boom")))
        scanner._run_cli()
        assert flushed == [True]

    def test_scan_failed_telemetry_is_sent_on_crash(self, monkeypatch):
        sent = []
        monkeypatch.setattr(scanner, "track_scan_failed",
                             lambda p, r, stage: sent.append(stage))
        monkeypatch.setattr(scanner, "main", lambda: (_ for _ in ()).throw(ValueError("boom")))
        scanner._run_cli()
        assert sent == ["unhandled"]

    def test_broken_telemetry_does_not_mask_the_crash(self, monkeypatch):
        """If track_scan_failed itself raises, the process must still exit 2
        rather than surfacing the telemetry error in place of the real one."""
        def _bad_track(*a, **k):
            raise RuntimeError("telemetry backend down")

        monkeypatch.setattr(scanner, "track_scan_failed", _bad_track)
        monkeypatch.setattr(scanner, "main", lambda: (_ for _ in ()).throw(ValueError("boom")))
        assert scanner._run_cli() == scanner._EXIT_CRASH
