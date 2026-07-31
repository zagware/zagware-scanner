"""Shared pytest fixtures for the zagware-scanner test suite.

scanner.py snapshots every ZAGWARE_* environment variable into a module-level
constant at import time (this is itself QUAL-19/QUAL-20 — see
the 2026-07-30 audit). Until that is refactored into a proper config object,
tests that need a non-default config MUST reload the module rather than
relying on os.environ mutation alone, or the constants will not reflect the
new values.

`reload_scanner` gives tests an explicit, deterministic way to do that without
depending on pytest's cross-fixture teardown ordering (monkeypatch's own
teardown races with a naive yield-fixture reload — see the docstring below
for why this fixture snapshots os.environ manually instead).
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import scanner  # noqa: E402  (must follow sys.path mutation)


@pytest.fixture
def reload_scanner():
    """Return a function that reloads `scanner` under a given env, and restores
    the real environment + a default-config reload when the test ends.

    Usage:
        def test_x(reload_scanner):
            mod = reload_scanner(ZAGWARE_MIN_SEVERITY="HIGH")
            assert mod._MIN_SEVERITY == "HIGH"

    Deliberately does NOT use monkeypatch: monkeypatch's undo-env-vars
    finalizer runs AFTER a dependent fixture's own yield-teardown (fixture
    teardown is reverse-of-setup, and a fixture that *depends on* monkeypatch
    tears down before monkeypatch itself). A naive `importlib.reload(scanner)`
    in this fixture's own teardown would therefore run while the test's env
    vars are still set, leaving the module reloaded with stale config for
    whichever test runs next. Snapshotting os.environ directly sidesteps the
    ordering question entirely.
    """
    original_env = dict(os.environ)

    def _reload(**env: str | None) -> "scanner":
        for key, value in env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return importlib.reload(scanner)

    yield _reload

    os.environ.clear()
    os.environ.update(original_env)
    importlib.reload(scanner)


@pytest.fixture
def default_scanner(reload_scanner):
    """The scanner module freshly reloaded under default (unset) ZAGWARE_* env."""
    return reload_scanner(
        ZAGWARE_MIN_SEVERITY=None,
        ZAGWARE_FAIL_ON_NEW=None,
        ZAGWARE_SCA_ENABLED=None,
        ZAGWARE_SECRETS_ENABLED=None,
        ZAGWARE_SECRETS_FAIL_ON_PUBLIC=None,
        ZAGWARE_EXCLUDE_PATHS=None,
        ZAGWARE_TELEMETRY=None,
        ZAGWARE_DEBUG=None,
    )


@pytest.fixture
def fake_http(monkeypatch):
    """Install a fake in place of scanner._http and return an installer function.

    Usage:
        def test_x(fake_http):
            calls = fake_http(lambda method, url, data, headers: {"ok": True})
            ...
            assert calls[0]["url"] == "https://api.github.com/..."

    This is the real seam between platform-adapter logic (URL/header
    construction, pagination, response parsing) and the network — scanner.py
    uses stdlib urllib in _http(), so `requests`-transport-mocking libraries
    (responses/httpretty) cannot intercept it; patching _http itself is both
    simpler and matches the module's own boundary.
    """

    def _install(responder):
        calls: list[dict] = []

        def _fake(method, url, data=None, headers=None):
            calls.append({"method": method, "url": url, "data": data, "headers": headers})
            return responder(method, url, data, headers)

        monkeypatch.setattr(scanner, "_http", _fake)
        return calls

    return _install


def load_fixture(name: str) -> str:
    """Read a fixture file's raw text content by filename under tests/fixtures/."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def load_json_fixture(name: str):
    import json

    return json.loads(load_fixture(name))
