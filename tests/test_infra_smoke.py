"""Smoke tests for the test infrastructure itself — run first to catch a
broken fixture before it produces confusing failures elsewhere."""
from __future__ import annotations

import scanner


def test_scanner_module_imports():
    assert scanner.__version__


def test_reload_scanner_applies_env(reload_scanner):
    mod = reload_scanner(ZAGWARE_MIN_SEVERITY="HIGH")
    assert mod._MIN_SEVERITY == "HIGH"


def test_reload_scanner_restores_defaults_across_tests(default_scanner):
    # If test_reload_scanner_applies_env's HIGH value leaked, this would fail.
    assert default_scanner._MIN_SEVERITY == ""


def test_reload_scanner_handles_bool_env(reload_scanner):
    mod = reload_scanner(ZAGWARE_FAIL_ON_NEW="true")
    assert mod._FAIL_ON_NEW is True
    mod = reload_scanner(ZAGWARE_FAIL_ON_NEW="false")
    assert mod._FAIL_ON_NEW is False
