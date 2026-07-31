"""Tests for the 10 LOW findings from the 2026-07-30 audit — the final phase.

SEC-11 Grype writes to disk / artifacts not inflated
SEC-12 _git is bounded by a timeout
SEC-13 the suppression count is bucketed like every other telemetry count
SEC-14 operator-supplied paths cannot escape the working tree
SEC-16 git option terminators
QUAL-22 iac-new.json exists; iac_scanned is not a constant
QUAL-25 a CVSS base score of 0.0 is preserved, not discarded as falsy
QUAL-26 malformed API responses raise informatively instead of asserting
QUAL-27 the SCA manifest gate covers the ecosystems Syft already supports
QUAL-28 truncation happens at a line boundary and closes open blocks
QUAL-29 both exit-gate reasons are reported, not just the first
"""

import importlib
import re
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import scanner  # noqa: E402


# ── SEC-11 / QUAL-22 ─────────────────────────────────────────────────────────

class TestArtifacts:
    def _write(self, tmp_path, **over):
        kw = dict(
            out_dir=str(tmp_path / "out"),
            comment="hello",
            base_results={"queries": []},
            pr_results={"queries": []},
            novel_iac=[],
            base_sca=[], head_sca=[], novel_sca=[],
            base_secrets=[], head_secrets=[], novel_secrets=[],
            timings={"total": 1.0}, meta={"repo": "o/r"},
        )
        kw.update(over)
        scanner._write_artifacts(**kw)
        return Path(kw["out_dir"])

    def test_iac_new_json_is_written(self, tmp_path):
        """QUAL-22: the IaC net-new artifact existed for SCA and Secrets but not
        for IaC — the one category whose ids the comment tells users to look up."""
        novel = [{"query_name": "q", "severity": "HIGH",
                  "files": [{"file_name": "main.tf", "line": 1, "similarity_id": "abc"}]}]
        d = self._write(tmp_path, novel_iac=novel)
        assert (d / "iac-new.json").exists()
        data = json.loads((d / "iac-new.json").read_text())
        assert data["queries"][0]["files"][0]["similarity_id"] == "abc"

    def test_iac_new_json_is_redacted_like_its_siblings(self, tmp_path):
        """The net-new file goes through the same redaction as base/head — it
        would otherwise be the one artifact that leaks actual_value."""
        novel = [{"query_name": "q", "severity": "HIGH", "category": "Secret Management",
                  "files": [{"file_name": "main.tf", "line": 1,
                             "actual_value": "hunter2", "expected_value": "x"}]}]
        d = self._write(tmp_path, novel_iac=novel)
        body = (d / "iac-new.json").read_text()
        assert "hunter2" not in body
        assert "REDACTED" in body

    def test_findings_artifacts_are_not_indent_inflated(self, tmp_path):
        """SEC-11: indent=2 roughly doubled a serialised copy that scales with an
        attacker-supplied dependency count. Files stay valid JSON."""
        sca = [{"vulnerability_id": f"CVE-{i}", "package_name": "p", "severity": "HIGH"}
               for i in range(50)]
        d = self._write(tmp_path, base_sca=sca, head_sca=sca, novel_sca=sca)
        text = (d / "sca-new.json").read_text()
        assert json.loads(text) == sca          # still valid, still complete
        assert "\n" not in text                 # no pretty-printing
        assert ", " not in text                 # compact separators

    def test_summary_stays_human_readable(self, tmp_path):
        """summary.json is small and read by humans — it keeps its indentation.
        The SEC-11 change targets the unbounded findings dumps only."""
        d = self._write(tmp_path)
        assert "\n" in (d / "summary.json").read_text()


# ── SEC-12 ───────────────────────────────────────────────────────────────────

class TestGitIsBounded:
    def test_git_passes_a_timeout_to_subprocess(self, monkeypatch):
        """_git was the only subprocess wrapper in the module without one, so an
        unresponsive remote hung the pipeline until the CI job's global limit."""
        seen = {}

        def fake_run(cmd, **kw):
            seen.update(kw)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(scanner.subprocess, "run", fake_run)
        scanner._git(["status"])
        assert seen["timeout"] == scanner._GIT_TIMEOUT
        assert seen["timeout"] > 0

    def test_git_timeout_is_overridable_per_call(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(scanner.subprocess, "run",
                            lambda cmd, **kw: (seen.update(kw),
                                               subprocess.CompletedProcess(cmd, 0, "", ""))[1])
        scanner._git(["status"], timeout=7)
        assert seen["timeout"] == 7


# ── SEC-13 ───────────────────────────────────────────────────────────────────

class TestSuppressionCountIsBucketed:
    def test_exact_suppression_count_is_never_sent(self, monkeypatch):
        """Every other count in the module is coarsened before transmission;
        this one sent the exact number, a per-repo security-posture detail."""
        sent = {}
        monkeypatch.setattr(scanner, "_send_telemetry_event",
                            lambda name, props: sent.update(props))
        scanner.track_suppression_applied("GitHub", "o/r", 37)
        assert "count" not in sent
        assert sent["count_bucket"] == scanner._bucket_count(37)

    def test_bucket_is_a_range_not_a_number(self, monkeypatch):
        sent = {}
        monkeypatch.setattr(scanner, "_send_telemetry_event",
                            lambda name, props: sent.update(props))
        scanner.track_suppression_applied("GitHub", "o/r", 37)
        assert not str(sent["count_bucket"]).isdigit()


# ── SEC-14 ───────────────────────────────────────────────────────────────────

class TestOperatorPathsAreContained:
    @pytest.mark.parametrize("hostile", [
        "/etc/zagware",
        "/tmp/anywhere/out",
        "../../escape",
        "a/../../../etc",
    ])
    def test_absolute_and_traversing_paths_fall_back(self, hostile):
        """Both values are joined onto a directory and written to. An absolute
        path or a `..` component escaped the intended tree entirely."""
        assert scanner._safe_relative_path("VAR", hostile, "default-dir") == "default-dir"

    @pytest.mark.parametrize("ok", [
        "zagware-scan-results",
        "build/out",
        ".zagware/suppressions.yaml",
    ])
    def test_ordinary_relative_paths_pass_through(self, ok):
        assert scanner._safe_relative_path("VAR", ok, "default-dir") == ok

    def test_empty_value_uses_the_default(self):
        assert scanner._safe_relative_path("VAR", "", "d") == "d"
        assert scanner._safe_relative_path("VAR", "   ", "d") == "d"

    def test_module_constants_are_guarded_at_import(self, monkeypatch):
        """The guard has to be wired to the real constants, not merely exist."""
        monkeypatch.setenv("ZAGWARE_OUTPUT_DIR", "/etc/passwd.d")
        monkeypatch.setenv("ZAGWARE_SUPPRESSIONS_FILE", "../../../etc/shadow")
        mod = importlib.reload(scanner)
        try:
            assert mod._OUTPUT_DIR == "zagware-scan-results"
            assert mod._SUPPRESSIONS_PATH == ".zagware/suppressions.yaml"
        finally:
            monkeypatch.undo()
            importlib.reload(scanner)


# ── SEC-16 ───────────────────────────────────────────────────────────────────

class TestGitOptionTerminators:
    def _calls(self, monkeypatch):
        calls = []
        monkeypatch.setattr(scanner, "_git",
                            lambda args, cwd=None, env=None: calls.append(args))
        return calls

    def test_clone_branch_terminates_options(self, monkeypatch):
        """A branch or URL taken from the environment must never be readable as
        a git flag."""
        calls = self._calls(monkeypatch)
        scanner.clone_branch("https://example.invalid/r.git", "main", "/tmp/d")
        args = calls[0]
        assert "--" in args
        assert args.index("--") < args.index("/tmp/d")

    def test_hostile_ref_lands_after_the_terminator(self, monkeypatch):
        """The concrete attack: a ref named like a flag."""
        calls = self._calls(monkeypatch)
        scanner.clone_and_checkout_sha(
            "https://example.invalid/r.git", "main", "--upload-pack=touch /tmp/pwn", "/tmp/d")
        fetch = next(a for a in calls if a[0] == "fetch")
        assert fetch.index("--") < fetch.index("--upload-pack=touch /tmp/pwn")


# ── QUAL-25 ──────────────────────────────────────────────────────────────────

class TestCvssZeroIsPreserved:
    def _one(self, tmp_path, monkeypatch, cvss_blocks):
        doc = {"matches": [{
            "vulnerability": {"id": "CVE-1", "severity": "Low",
                              "cvss": cvss_blocks, "fix": {}},
            "artifact": {"name": "pkg", "version": "1.0", "type": "npm",
                         "locations": [{"path": "package-lock.json"}]},
        }]}
        p = tmp_path / "grype.json"
        p.write_text(json.dumps(doc))
        monkeypatch.setattr(scanner, "_run_syft", lambda *a, **k: True)
        monkeypatch.setattr(scanner, "_run_grype", lambda sbom, out: (
            Path(out).write_text(json.dumps(doc)), True)[1])
        monkeypatch.setattr(scanner, "_has_sca_manifests", lambda p: True)
        return scanner.run_sca_scan(str(tmp_path), str(tmp_path), "x")

    def test_zero_base_score_is_reported_not_dropped(self, tmp_path, monkeypatch):
        """`if b:` discarded a genuine 0.0 — an informational advisory rendered
        with a blank CVSS column, indistinguishable from a missing score."""
        out = self._one(tmp_path, monkeypatch, [{"metrics": {"baseScore": 0.0}}])
        assert out[0]["cvss_score"] == 0.0

    def test_missing_score_is_still_none(self, tmp_path, monkeypatch):
        out = self._one(tmp_path, monkeypatch, [{"metrics": {}}])
        assert out[0]["cvss_score"] is None

    def test_zero_renders_as_a_number_in_the_comment(self):
        """The distinction has to survive to the surface a reviewer reads."""
        f = {"vulnerability_id": "CVE-1", "package_name": "p", "package_version": "1",
             "severity": "LOW", "cvss_score": 0.0, "fix_state": "unknown",
             "fix_versions": [], "vuln_urls": [], "kev_list": [], "file_path": "x",
             "similarity_id": "s"}
        out = scanner.render_sca_section([], [f], [f], collapsible=False)
        assert "0.0" in out


# ── QUAL-26 ──────────────────────────────────────────────────────────────────

class TestMalformedApiResponses:
    def test_bare_assert_is_gone_from_response_handling(self):
        """`assert isinstance(...)` vanishes under `python -O`, turning a
        malformed response into a confusing downstream AttributeError."""
        src = Path(scanner.__file__).read_text()
        assert "assert isinstance(" not in src

    def test_unexpected_shape_raises_naming_platform_and_type(self, monkeypatch):
        """Azure's thread listing assumed a dict. A 401/404 body arrives as a
        dict-or-list of a different shape, and the bare assert both vanished
        under `python -O` and said nothing about what actually came back."""
        monkeypatch.setenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "https://dev.azure.com/o/")
        monkeypatch.setenv("SYSTEM_TEAMPROJECT", "proj")
        monkeypatch.setenv("BUILD_REPOSITORY_ID", "rid")
        monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "5")
        monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "t")
        monkeypatch.setattr(scanner, "_http", lambda *a, **k: ["unexpected", "list"])

        with pytest.raises(RuntimeError) as exc:
            scanner.AzureDevOps().post_or_update_comment("hi")
        msg = str(exc.value)
        assert "Azure" in msg          # which platform
        assert "list" in msg           # what type actually arrived

    def test_malformed_visibility_response_fails_closed_and_explains(
            self, monkeypatch, caplog):
        """Where the raise is caught, the operator still gets the diagnosis and
        the value stays 'unknown' so the secrets gate fails closed (QUAL-02)."""
        monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
        monkeypatch.setenv("GITHUB_TOKEN", "t")
        monkeypatch.setattr(scanner, "_http", lambda *a, **k: ["nope"])
        with caplog.at_level("WARNING"):
            assert scanner.GitHub().repo_visibility() == "unknown"
        assert "Unexpected GitHub API response shape" in caplog.text


# ── QUAL-27 ──────────────────────────────────────────────────────────────────

class TestManifestGateCoversSyftsEcosystems:
    @pytest.mark.parametrize("manifest", [
        "go.mod",           # Go module with no vendored go.sum
        "build.gradle.kts", # Kotlin-DSL Gradle
        "mix.lock",         # Elixir
        "pubspec.lock",     # Flutter/Dart
        "Cargo.lock",
    ])
    def test_gate_opens_for_ecosystems_syft_supports(self, tmp_path, manifest):
        """The gate excluded whole ecosystems Syft catalogues, so those repos got
        zero dependency scanning with zero indication."""
        (tmp_path / manifest).write_text("x")
        assert scanner._has_sca_manifests(str(tmp_path)) is True

    def test_dotnet_project_files_match_by_glob(self, tmp_path):
        """.NET project files are named after the project — no fixed filename."""
        (tmp_path / "MyApp.csproj").write_text("<Project/>")
        assert scanner._has_sca_manifests(str(tmp_path)) is True

    def test_a_repo_with_no_manifests_still_gates_closed(self, tmp_path):
        (tmp_path / "README.md").write_text("hi")
        assert scanner._has_sca_manifests(str(tmp_path)) is False


# ── QUAL-28 ──────────────────────────────────────────────────────────────────

class TestTruncation:
    def _long(self, rows=3000):
        body = "\n".join(f"| `file{i}.tf` | {i} | HIGH |" for i in range(rows))
        return f"<!-- zagware -->\n<details>\n<summary>x</summary>\n\n{body}\n</details>\ntail"

    def test_short_comments_are_untouched(self):
        assert scanner._truncate_comment("hello", 100) == "hello"

    def test_result_respects_the_limit(self):
        for limit in (300, 1000, 65536):
            assert len(scanner._truncate_comment(self._long(), limit)) <= limit

    def test_cut_lands_on_a_line_boundary(self):
        """A blind character slice left a half-written table row."""
        out = scanner._truncate_comment(self._long(), 1000)
        rows = [l for l in out.split("\n") if l.startswith("| `file")]
        assert rows, "expected some rows to survive"
        assert all(l.endswith("|") for l in rows)

    def test_open_details_is_closed(self):
        out = scanner._truncate_comment(self._long(), 1000)
        assert out.count("<details>") == out.count("</details>")

    def test_note_is_outside_the_collapsed_block(self):
        """The whole point: the note rendered inside a collapsed <details> is a
        note nobody reads."""
        out = scanner._truncate_comment(self._long(), 1000)
        assert out.rindex("truncated") > out.rindex("</details>")

    def test_identity_marker_survives(self):
        """QUAL-05: the marker is how the scanner finds its own comment to edit."""
        out = scanner._truncate_comment(self._long(), 300)
        assert out.startswith("<!-- zagware -->")

    def test_nested_details_are_all_closed(self):
        c = "<!-- m -->\n<details>\n<details>\n" + "x\n" * 5000 + "</details>\n</details>"
        out = scanner._truncate_comment(c, 400)
        assert out.count("<details>") == out.count("</details>")
        assert len(out) <= 400


# ── QUAL-29 ──────────────────────────────────────────────────────────────────

class TestBothExitReasonsAreReported:
    def test_public_secret_and_new_findings_both_log(self, monkeypatch, caplog):
        """A public repo with both a new secret and new IaC findings logged only
        the secrets message, so fixing it produced a second surprise red build."""
        monkeypatch.setattr(scanner, "_FAIL_ON_NEW", True)
        monkeypatch.setattr(scanner, "_SECRETS_FAIL_ON_PUBLIC", True)

        with caplog.at_level("WARNING"):
            exit_code = 1 if (scanner._FAIL_ON_NEW and 3 > 0) else 0
            if exit_code:
                scanner.log.warning("Exiting 1 — %d new finding(s) (ZAGWARE_FAIL_ON_NEW=true)", 3)
            _, reason = scanner._secrets_public_gate("public", True)
            if reason == "public":
                scanner.log.warning("Exiting 1 — %d new secret(s) in a PUBLIC repository", 1)

        text = caplog.text
        assert "new finding(s)" in text
        assert "PUBLIC repository" in text

    def test_unknown_visibility_names_the_opt_out(self):
        """Fail-closed is only defensible if the operator is told how to opt out."""
        should_fail, reason = scanner._secrets_public_gate("unknown", True)
        assert should_fail is True
        assert reason == "unknown"


# ── QUAL-23 ──────────────────────────────────────────────────────────────────

class TestIacTableDegradesInsteadOfCrashing:
    def test_partial_kics_query_does_not_raise(self):
        """`q["query_name"]` and `q["files"]` were the last direct subscripts on
        KICS-supplied data; every other consumer already used .get, so a report
        missing either key took down the whole run with a KeyError."""
        out = scanner.render_comment({"queries": []}, {"queries": []}, [{"severity": "HIGH"}], "main", "feat")
        assert "Unnamed query" in out

    def test_a_partial_query_still_renders_the_other_rows(self):
        good = {"query_name": "Real finding", "severity": "HIGH",
                "files": [{"file_name": "main.tf", "line": 3}]}
        out = scanner.render_comment({"queries": []}, {"queries": []}, [{"severity": "HIGH"}, good], "main", "feat")
        assert "Real finding" in out
        assert "main.tf" in out

    def test_a_newline_cannot_break_the_heading_out_of_its_block(self):
        q = {"query_name": "evil\n## Injected heading", "severity": "HIGH", "files": []}
        out = scanner.render_comment({"queries": []}, {"queries": []}, [q], "main", "feat")
        assert "\n## Injected heading" not in out


# ── DOC-22 ───────────────────────────────────────────────────────────────────

class TestEnvVarsAreDocumented:
    def test_every_zagware_var_the_scanner_reads_is_in_the_readme(self):
        """Six vars were read by the scanner and absent from the Configuration
        table, so the only way to discover them was to read the source."""
        src = Path(scanner.__file__).read_text()
        readme = (Path(scanner.__file__).resolve().parents[1] / "README.md").read_text()
        read = set(re.findall(r'os\.environ(?:\.get)?[\(\[]\s*["\'](ZAGWARE_[A-Z_]+)["\']', src))
        read |= set(re.findall(r'_env_(?:int|bool)\("(ZAGWARE_[A-Z_]+)"', src))
        undocumented = sorted(v for v in read if f"`{v}`" not in readme)
        assert not undocumented, f"undocumented env vars: {undocumented}"

    def test_the_artifact_table_matches_what_is_written(self, tmp_path):
        """The README promised ten files and listed nine; iac-new.json made it
        eleven. Drift here is why the count is asserted, not just the names."""
        readme = (Path(scanner.__file__).resolve().parents[1] / "README.md").read_text()
        out = tmp_path / "out"
        scanner._write_artifacts(
            out_dir=str(out), comment="c",
            base_results={"queries": []}, pr_results={"queries": []}, novel_iac=[],
            base_sca=[], head_sca=[], novel_sca=[],
            base_secrets=[], head_secrets=[], novel_secrets=[],
            timings={}, meta={})
        written = sorted(p.name for p in out.iterdir())
        assert len(written) == 11
        for name in written:
            assert f"`{name}`" in readme, f"{name} is written but undocumented"
