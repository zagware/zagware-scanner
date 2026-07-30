"""Tests for SUP-14: `betterleaks` must be included in ci.yml's binary check,
and CI must actually exercise the scanner rather than just proving scanner.py
parses and the four binaries exist.

Before this fix, `.github/workflows/ci.yml` consisted entirely of:
py_compile x2, two greps, a docker build, and an `[ -x "$bin" ]` existence
check that never included betterleaks (added in v2.8.0). Nothing ran
`--version`/`version` on any engine, nothing invoked kics/syft/grype/
betterleaks with real input, and the 232-test pytest suite this review built
was never wired into CI at all -- a tag push could ship a scanner that
imports cleanly and crashes on every real code path.

The docker-dependent "Smoke test" step itself is not re-executed here (these
tests must not require a Docker daemon); instead this file (1) pins the exact
shipped content of every SUP-14-relevant step via YAML extraction, and (2)
executes the venv-setup + pytest step for real, since that step needs no
Docker at all and is directly exercisable.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _steps() -> list[dict]:
    doc = yaml.safe_load(CI_YML.read_text())
    steps = []
    for job in doc["jobs"].values():
        steps.extend(job["steps"])
    return steps


def _step(name: str) -> dict:
    for step in _steps():
        if step.get("name") == name:
            return step
    raise AssertionError(f"step {name!r} not found in ci.yml")


class TestBinaryExistenceCheckIncludesBetterleaks:
    def test_betterleaks_is_checked(self):
        run = _step("Verify binaries exist")["run"]
        assert "/usr/local/bin/betterleaks" in run

    def test_all_four_engines_are_checked(self):
        run = _step("Verify binaries exist")["run"]
        for path in ("/usr/local/bin/kics", "/usr/bin/syft", "/usr/bin/grype",
                      "/usr/local/bin/betterleaks"):
            assert path in run, f"{path} missing from the binary existence check"


class TestSmokeTestExercisesRealEngines:
    """YAML-level pins on the smoke-test step's shipped content -- Docker
    itself is not invoked here (see module docstring)."""

    def test_step_exists(self):
        assert _step("Smoke test — run each engine against a real, known-bad fixture")

    def test_every_engine_version_is_checked(self):
        run = _step("Smoke test — run each engine against a real, known-bad fixture")["run"]
        for cmd in ("kics version", "syft version", "grype version", "betterleaks version"):
            assert cmd in run

    def test_kics_query_tree_emptiness_is_guarded(self):
        """SUP-14 explicitly named an empty KICS query tree as a silent
        failure mode existence-only checks miss."""
        run = _step("Smoke test — run each engine against a real, known-bad fixture")["run"]
        assert "query tree looks empty" in run

    def test_kics_invocation_matches_run_scan_flags(self):
        """The smoke test must exercise the exact flags src/scanner.py's
        run_scan() uses, not a hand-rolled alternative invocation."""
        scanner_src = (REPO_ROOT / "src" / "scanner.py").read_text()
        run = _step("Smoke test — run each engine against a real, known-bad fixture")["run"]
        for flag in ("--queries-path", "--report-formats", "--exclude-paths",
                     "--disable-full-descriptions", "--no-progress", "--ci"):
            assert flag in scanner_src
            assert flag in run

    def test_each_engine_result_is_asserted_non_empty(self):
        run = _step("Smoke test — run each engine against a real, known-bad fixture")["run"]
        assert "KICS found 0 findings" in run
        assert "Syft found 0 packages" in run
        assert "Grype found 0 vulnerabilities" in run
        assert "betterleaks found 0 secrets" in run

    def test_fixtures_are_written_before_they_are_scanned(self):
        run = _step("Smoke test — run each engine against a real, known-bad fixture")["run"]
        write_idx = run.index("> main.tf")
        scan_idx = run.index("kics scan")
        assert write_idx < scan_idx


class TestUnitTestSuiteIsWiredIntoCi:
    """The highest-value part of SUP-14: the 232-test pytest suite built
    across this review must actually run in CI, not just exist on disk."""

    def test_pytest_step_exists_before_the_docker_build(self):
        names = [s.get("name") for s in _steps()]
        assert "Run unit test suite" in names
        assert names.index("Run unit test suite") < names.index("Set up Docker Buildx")

    def test_venv_setup_step_installs_test_requirements(self):
        run = _step("Set up test venv")["run"]
        assert "requirements-test.txt" in run

    def test_pytest_step_actually_runs_the_full_suite(self):
        run = _step("Run unit test suite")["run"]
        assert "pytest tests/" in run

    @pytest.mark.integration
    def test_venv_and_pytest_steps_actually_work(self, tmp_path):
        """Executes the two real, shipped commands -- not a paraphrase --
        against a throwaway venv in an isolated copy of the whole repo tree
        (never the real REPO_ROOT, whose own .venv this test process may be
        running under right now). The full tree is needed because many other
        test modules read README.md/workflow YAML relative to their own
        REPO_ROOT, same as this file does."""
        import shutil

        repo_copy = tmp_path / "repo"
        shutil.copytree(
            REPO_ROOT, repo_copy,
            # Exclude this file itself -- without it, the nested pytest run
            # would rediscover and re-invoke this very test, which computes
            # its own REPO_ROOT relative to __file__ and would recurse into
            # an unbounded chain of copies.
            ignore=shutil.ignore_patterns(
                ".git", ".venv", ".pytest_cache", "__pycache__", "test_ci_smoke_test.py",
            ),
        )

        venv_step = _step("Set up test venv")["run"]
        pytest_step = _step("Run unit test suite")["run"]
        script = venv_step + "\n" + pytest_step + "\n"
        proc = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
            cwd=repo_copy, capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert " passed" in proc.stdout
        assert "failed" not in proc.stdout


class TestDockerignoreCoversNewCiArtifacts:
    """The CI job now creates .venv on the runner before the docker build
    step in the same job; it must not bloat the build context."""

    def test_venv_is_dockerignored(self):
        text = (REPO_ROOT / ".dockerignore").read_text()
        assert ".venv" in text.splitlines()

    def test_tests_dir_is_dockerignored(self):
        text = (REPO_ROOT / ".dockerignore").read_text()
        assert "tests" in text.splitlines()
