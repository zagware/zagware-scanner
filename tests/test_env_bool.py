"""Tests for QUAL-19: unified boolean env-var parsing.

Before the fix, five mutually incompatible conventions coexisted:
  - ZAGWARE_FAIL_ON_NEW            .lower() == "true"   -> "1"/"yes"/"on" all false
  - ZAGWARE_SCA_ENABLED            .lower() != "false"  -> "0"/"no"/"off" all true
  - ZAGWARE_SECRETS_ENABLED        .lower() != "false"  -> same bug
  - ZAGWARE_SECRETS_FAIL_ON_PUBLIC .lower() != "false"  -> "0" could never disable it
  - ZAGWARE_ASSUME_PRIVATE         .lower() == "true"   -> same bug as FAIL_ON_NEW
  - ZAGWARE_DEBUG                  bare truthiness      -> "false"/"0"/"no" all enable it
  - ZAGWARE_TELEMETRY              5-word off vocabulary (the most correct one)
  - ZAGWARE_TELEMETRY_INCLUDE_REPO_NAME  3-word on vocabulary

All eight now route through one _env_bool() helper with one shared vocabulary
(true: 1/true/yes/on; false: 0/false/no/off/disabled -- disabled is kept so
ZAGWARE_TELEMETRY=disabled, already documented at README.md, keeps working).
"""
from __future__ import annotations

import logging

import pytest

import scanner


class TestEnvBoolVocabulary:
    """Direct unit tests of the helper itself."""

    @pytest.mark.parametrize("value", ["1", "true", "True", " TRUE ", "yes", "YES", "on", "On"])
    def test_true_synonyms(self, monkeypatch, value):
        monkeypatch.setenv("X", value)
        assert scanner._env_bool("X", False) is True

    @pytest.mark.parametrize("value", ["0", "false", "False", " FALSE ", "no", "NO", "off", "OFF", "disabled", "Disabled"])
    def test_false_synonyms(self, monkeypatch, value):
        monkeypatch.setenv("X", value)
        assert scanner._env_bool("X", True) is False

    def test_unset_uses_default(self, monkeypatch):
        monkeypatch.delenv("X", raising=False)
        assert scanner._env_bool("X", True) is True
        assert scanner._env_bool("X", False) is False

    def test_empty_string_uses_default(self, monkeypatch):
        monkeypatch.setenv("X", "")
        assert scanner._env_bool("X", True) is True

    def test_garbage_value_falls_back_to_default_and_warns(self, monkeypatch, caplog):
        monkeypatch.setenv("X", "maybe")
        with caplog.at_level(logging.WARNING):
            result = scanner._env_bool("X", True)
        assert result is True
        assert "not a recognised boolean value" in caplog.text
        assert "X" in caplog.text


class TestFailOnNewAcceptsCiIdiomaticValues:
    """QUAL-19's headline example: ZAGWARE_FAIL_ON_NEW=1 must actually turn
    the gate on, not silently leave it off."""

    def test_fail_on_new_1_enables_the_gate(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_FAIL_ON_NEW="1")
        assert mod._FAIL_ON_NEW is True

    def test_fail_on_new_yes_enables_the_gate(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_FAIL_ON_NEW="yes")
        assert mod._FAIL_ON_NEW is True

    def test_fail_on_new_true_with_trailing_whitespace_enables_the_gate(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_FAIL_ON_NEW="True ")
        assert mod._FAIL_ON_NEW is True

    def test_unset_defaults_to_off(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_FAIL_ON_NEW=None)
        assert mod._FAIL_ON_NEW is False


class TestDebugRequiresAnExplicitFalseValue:
    """QUAL-19's other headline example: ZAGWARE_DEBUG=false must NOT enable
    debug logging (bare truthiness treated any non-empty string as on)."""

    def test_debug_false_does_not_enable_debug(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_DEBUG="false")
        assert mod._DEBUG is False

    def test_debug_0_does_not_enable_debug(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_DEBUG="0")
        assert mod._DEBUG is False

    def test_debug_true_enables_debug(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_DEBUG="true")
        assert mod._DEBUG is True

    def test_debug_1_enables_debug(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_DEBUG="1")
        assert mod._DEBUG is True


class TestSecretsFailOnPublicCanActuallyBeDisabled:
    """Before the fix, only the exact string "false" could turn this off --
    "0" (the most natural CI-boolean spelling) silently left it enabled."""

    def test_0_disables_the_gate(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="0")
        assert mod._SECRETS_FAIL_ON_PUBLIC is False

    def test_off_disables_the_gate(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC="off")
        assert mod._SECRETS_FAIL_ON_PUBLIC is False

    def test_unset_defaults_to_enabled(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_FAIL_ON_PUBLIC=None)
        assert mod._SECRETS_FAIL_ON_PUBLIC is True


class TestScaAndSecretsEnabledCanActuallyBeDisabled:
    def test_sca_enabled_0_disables_sca(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCA_ENABLED="0")
        assert mod._SCA_ENABLED is False

    def test_sca_enabled_no_disables_sca(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCA_ENABLED="no")
        assert mod._SCA_ENABLED is False

    def test_secrets_enabled_off_disables_secrets(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_ENABLED="off")
        assert mod._SECRETS_ENABLED is False


class TestTelemetryVocabularyIsPreservedAsTheCanonicalOne:
    """ZAGWARE_TELEMETRY's original 5-word off-vocabulary (including
    "disabled", documented nowhere else but already accepted) must keep
    working exactly as before -- it became the shared vocabulary, not the
    other way around."""

    def test_off_disables_telemetry(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_TELEMETRY="off")
        assert mod._TELEMETRY_ENABLED is False

    def test_disabled_disables_telemetry(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_TELEMETRY="disabled")
        assert mod._TELEMETRY_ENABLED is False

    def test_unset_defaults_to_enabled(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_TELEMETRY=None)
        assert mod._TELEMETRY_ENABLED is True

    def test_send_telemetry_event_short_circuits_when_disabled(self, reload_scanner, monkeypatch):
        mod = reload_scanner(ZAGWARE_TELEMETRY="off")
        calls = []
        monkeypatch.setattr(mod.threading, "Thread", lambda *a, **k: calls.append((a, k)) or None)
        mod._send_telemetry_event("scan_started", {})
        assert calls == []


class TestAssumePrivateAcceptsCiIdiomaticValues:
    def test_assume_private_1_is_true(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_ASSUME_PRIVATE="1")
        assert mod._ASSUME_PRIVATE is True

    def test_unset_defaults_to_false(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_ASSUME_PRIVATE=None)
        assert mod._ASSUME_PRIVATE is False
