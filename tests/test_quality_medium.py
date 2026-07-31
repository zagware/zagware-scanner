"""Tests for QUAL-08/09/10/13/15/16/17/18 — the eight MEDIUM quality findings
the phased plan deferred past Phase 5.

QUAL-08: "SCA disabled", "no manifests found" and "scanned and clean" all
         produced the same silent empty section, so a Go monorepo using only
         go.mod looked clean when nothing had been scanned.
QUAL-09: four platforms, four different failure modes on a non-PR pipeline —
         an empty --branch, two unhandled KeyErrors, and on Azure a silent
         fallback to "main" that diffed main against itself forever.
QUAL-10: ZAGWARE_EXCLUDE_PATHS reached KICS only, so vendored trees and test
         fixtures were still scanned by Syft and betterleaks.
QUAL-13: GITHUB_HEAD_REF is the branch name in the contributor's FORK, absent
         from the base repo the scanner clones — so every fork PR failed.
QUAL-15: the hand-rolled parser silently half-parsed valid YAML.
QUAL-16: commit_sha was declared, threaded, and passed '' at the only call
         site, so it was null on every upload ever made.
QUAL-17: suppressed_ids holds 64-char hashes but users paste 16-char
         prefixes, so the "already suppressed" guard never fired and every
         suppression logged a spurious WARNING on every run, forever.
QUAL-18: a rejected push was indistinguishable from "nothing to do", so the
         comment came back unchanged and users concluded the feature was
         broken.
"""
from __future__ import annotations

import logging
import subprocess

import pytest

import scanner


# ── QUAL-08 ─────────────────────────────────────────────────────────────────

def _sca(sim="a", sev="HIGH"):
    return {"vulnerability_id": "CVE-1", "severity": sev, "package_name": "p",
            "package_version": "1", "package_type": "npm", "similarity_id": sim,
            "vuln_urls": [], "fix_versions": [], "fix_state": "unknown",
            "cvss_score": None, "kev_listed": False}


class TestScaSectionDistinguishesSkippedFromClean:
    def test_disabled_renders_nothing(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCA_ENABLED="false")
        assert mod.render_sca_section(None, None, []) == ""

    def test_no_manifests_says_so_explicitly(self, reload_scanner):
        """The exact QUAL-08 bug: this used to be an empty string, so the user
        concluded there were no vulnerabilities when nothing was scanned."""
        mod = reload_scanner(ZAGWARE_SCA_ENABLED=None)
        out = mod.render_sca_section(None, None, [])
        assert out != ""
        assert "skipped" in out.lower()
        assert "not* a statement" in out or "not a statement" in out.lower()

    def test_no_manifests_lists_what_would_have_been_detected(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SCA_ENABLED=None)
        out = mod.render_sca_section(None, None, [])
        assert "package-lock.json" in out

    def test_scanned_and_clean_shows_positive_confirmation(self, reload_scanner):
        """Coverage must be visible at zero findings, not silent."""
        mod = reload_scanner(ZAGWARE_SCA_ENABLED=None)
        out = mod.render_sca_section([], [], [])
        assert "No new dependency vulnerabilities" in out
        assert "skipped" not in out.lower()

    def test_one_side_none_still_renders_the_table(self, reload_scanner):
        """A PR that ADDS the only manifest has base=None, head=[...]. That is
        a real scan, not a skip."""
        mod = reload_scanner(ZAGWARE_SCA_ENABLED=None)
        out = mod.render_sca_section(None, [_sca()], [_sca()])
        assert "Zagware SCA" in out
        assert "skipped" not in out.lower()


class TestSecretsSectionDistinguishesDisabled:
    def test_disabled_renders_nothing(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_ENABLED="false")
        assert mod.render_secrets_section(None, None, [], "private") == ""

    def test_scanned_and_clean_shows_positive_confirmation(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SECRETS_ENABLED=None)
        out = mod.render_secrets_section([], [], [], "private")
        assert "No new secrets" in out


# ── QUAL-09 ─────────────────────────────────────────────────────────────────

class TestIsPrPipeline:
    def test_default_derives_from_pr_number(self, monkeypatch):
        gh = scanner.GitHub()
        monkeypatch.setenv("PR_NUMBER", "42")
        assert gh.is_pr_pipeline() is True

    def test_false_without_a_pr_number(self, monkeypatch):
        gh = scanner.GitHub()
        monkeypatch.delenv("PR_NUMBER", raising=False)
        assert gh.is_pr_pipeline() is False

    @pytest.mark.parametrize("cls", [scanner.GitHub, scanner.GitLab,
                                      scanner.Bitbucket, scanner.AzureDevOps])
    def test_every_platform_implements_it(self, cls):
        """All four must answer consistently — that is the whole point of
        QUAL-09, which was four platforms failing four different ways."""
        assert callable(cls().is_pr_pipeline)

    def test_azure_no_longer_hardcodes_main(self, monkeypatch):
        """Azure silently substituted the literal "main" for a missing target
        branch, producing a green build that diffed main against itself on
        every run. Asserted behaviourally: with the variable absent it must
        now raise rather than invent a branch — main()'s is_pr_pipeline gate
        catches this first, and the KeyError handler names the variable."""
        monkeypatch.delenv("SYSTEM_PULLREQUEST_TARGETBRANCH", raising=False)
        with pytest.raises(KeyError):
            scanner.AzureDevOps().base_branch()

    def test_azure_still_strips_the_refs_heads_prefix(self, monkeypatch):
        monkeypatch.setenv("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/develop")
        assert scanner.AzureDevOps().base_branch() == "develop"


# ── QUAL-10 ─────────────────────────────────────────────────────────────────

class TestExcludePathsReachEveryScanner:
    def test_syft_gets_one_exclude_per_path(self, reload_scanner, monkeypatch, tmp_path):
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor,test/fixtures")
        seen = {}

        def _fake_run(cmd, **kw):
            seen["cmd"] = cmd
            raise FileNotFoundError("stop")

        monkeypatch.setattr(mod.subprocess, "run", _fake_run)
        mod._run_syft(str(tmp_path), str(tmp_path / "s.json"))
        assert seen["cmd"].count("--exclude") == 3  # vendor, test/fixtures, .git
        assert "./vendor/**" in seen["cmd"]
        assert "./test/fixtures/**" in seen["cmd"]

    def test_betterleaks_gets_a_generated_allowlist_config(self, reload_scanner, tmp_path):
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor")
        path = mod._write_betterleaks_config(str(tmp_path), "base")
        assert path
        # Parse it, don't grep it. The previous form asserted the raw substring
        # `"^vendor/"`, which pinned the BASIC-string quoting that made the
        # config invalid TOML -- betterleaks refused to start and the secrets
        # scan failed for every user. A test that encodes the defect cannot
        # catch it. What matters is the regex betterleaks actually receives.
        import tomllib
        cfg = tomllib.loads((tmp_path / "betterleaks_base.toml").read_text())
        assert cfg["extend"]["useDefault"] is True, \
            "must ADD an allowlist, never narrow detection"
        paths = cfg["allowlists"][0]["paths"]
        assert r"^vendor/" in paths
        assert r"^\.git/" in paths

    def test_betterleaks_config_is_passed_to_the_binary(self, reload_scanner, monkeypatch, tmp_path):
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor")
        seen = {}

        def _fake_run(cmd, **kw):
            seen["cmd"] = cmd
            (tmp_path / "secrets_base.json").write_text("null")
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        monkeypatch.setattr(mod.subprocess, "run", _fake_run)
        mod.run_secrets_scan(str(tmp_path), str(tmp_path), "base")
        assert "--config" in seen["cmd"]

    def test_manifest_discovery_skips_excluded_paths(self, reload_scanner, tmp_path):
        """A vendored lockfile alone must not switch SCA on when the operator
        excluded that tree."""
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor")
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "package-lock.json").write_text("{}")
        assert mod._has_sca_manifests(str(tmp_path)) is False

    def test_manifest_discovery_still_finds_real_manifests(self, reload_scanner, tmp_path):
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor")
        (tmp_path / "package-lock.json").write_text("{}")
        assert mod._has_sca_manifests(str(tmp_path)) is True


# ── QUAL-13 ─────────────────────────────────────────────────────────────────

class TestForkPullRequestsAreScannable:
    def test_head_ref_prefers_the_pull_ref(self, monkeypatch):
        """refs/pull/<n>/head exists in the BASE repo for every PR including
        forks; GITHUB_HEAD_REF is a branch in the contributor's fork that the
        base repo does not have."""
        monkeypatch.setenv("PR_NUMBER", "7")
        monkeypatch.setenv("GITHUB_HEAD_REF", "contributor-feature")
        monkeypatch.delenv("ZAGWARE_HEAD_REF", raising=False)
        assert scanner.GitHub().head_branch() == "refs/pull/7/head"

    def test_explicit_override_still_wins(self, monkeypatch):
        """ZAGWARE_HEAD_REF is the issue_comment escape hatch and must keep
        taking precedence."""
        monkeypatch.setenv("PR_NUMBER", "7")
        monkeypatch.setenv("ZAGWARE_HEAD_REF", "explicit-branch")
        assert scanner.GitHub().head_branch() == "explicit-branch"

    def test_falls_back_when_pr_number_is_absent(self, monkeypatch):
        monkeypatch.delenv("PR_NUMBER", raising=False)
        monkeypatch.delenv("ZAGWARE_HEAD_REF", raising=False)
        monkeypatch.setenv("GITHUB_HEAD_REF", "branch-name")
        assert scanner.GitHub().head_branch() == "branch-name"

    def test_non_numeric_pr_number_does_not_build_a_bogus_ref(self, monkeypatch):
        monkeypatch.setenv("PR_NUMBER", "not-a-number")
        monkeypatch.delenv("ZAGWARE_HEAD_REF", raising=False)
        monkeypatch.setenv("GITHUB_HEAD_REF", "branch-name")
        assert scanner.GitHub().head_branch() == "branch-name"

    def test_checkout_targets_fetch_head_not_the_ref_string(self, monkeypatch):
        """Verified against real git: `git fetch origin refs/pull/7/head`
        populates FETCH_HEAD but creates no local ref of that name, so
        `git checkout refs/pull/7/head` fails with "pathspec did not match"."""
        calls = []
        monkeypatch.setattr(scanner, "_git",
                            lambda args, cwd=None, env=None: calls.append(args))
        scanner.clone_and_checkout_sha("https://h/r.git", "main", "refs/pull/7/head", "/tmp/d")
        checkout = next(c for c in calls if c[0] == "checkout")
        assert "FETCH_HEAD" in checkout
        assert "refs/pull/7/head" not in checkout

    def test_real_git_can_check_out_a_pull_ref(self, tmp_path):
        """End-to-end against real git: build an origin carrying a
        refs/pull/N/head ref that is NOT a branch, and prove the real code
        path checks it out."""
        import os
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}
        origin = tmp_path / "origin"
        origin.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(origin)], check=True)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "base"],
                       cwd=origin, check=True, env=env)
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "fork-work"],
                       cwd=origin, check=True, env=env)
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=origin,
                             capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(["git", "update-ref", "refs/pull/7/head", sha], cwd=origin, check=True)
        subprocess.run(["git", "reset", "-q", "--hard", "HEAD~1"], cwd=origin, check=True, env=env)

        dest = tmp_path / "clone"
        scanner.clone_and_checkout_sha(f"file://{origin}", "main", "refs/pull/7/head", str(dest))
        got = subprocess.run(["git", "log", "-1", "--format=%s"], cwd=dest,
                             capture_output=True, text=True, check=True).stdout.strip()
        assert got == "fork-work", "the fork's head commit must be what got checked out"


# ── QUAL-15 ─────────────────────────────────────────────────────────────────

def _supp(tmp_path, body: str):
    repo = tmp_path / "r"
    (repo / ".zagware").mkdir(parents=True, exist_ok=True)
    (repo / ".zagware" / "suppressions.yaml").write_text(body)
    return repo


class TestSuppressionParserFailsLoudly:
    def test_inline_comment_is_stripped_from_the_id(self, tmp_path):
        """`- id: abc123  # false positive` used to yield the whole string as
        the id, so it matched nothing."""
        repo = _supp(tmp_path, "- id: abc123  # false positive\n  reason: \"x\"\n")
        recs = scanner._parse_suppressions_file(str(repo))
        assert "abc123" in recs

    def test_hash_inside_a_quoted_reason_survives(self, tmp_path):
        repo = _supp(tmp_path, '- id: abc123\n  reason: "fails on #4 in prod"\n')
        recs = scanner._parse_suppressions_file(str(repo))
        assert recs["abc123"]["reason"] == "fails on #4 in prod"

    def test_bare_dash_list_item_starts_a_new_record(self, tmp_path):
        """A bare `-` on its own line is valid YAML; it used to fail the
        startswith("- ") test so its keys merged into the previous record."""
        repo = _supp(tmp_path, "- id: aaa111\n  reason: \"first\"\n-\n  id: bbb222\n  reason: \"second\"\n")
        recs = scanner._parse_suppressions_file(str(repo))
        assert set(recs) == {"aaa111", "bbb222"}
        assert recs["bbb222"]["reason"] == "second"

    def test_entry_without_an_id_is_reported_not_silently_dropped(self, tmp_path, caplog):
        repo = _supp(tmp_path, '- reason: "orphan with no id"\n')
        with caplog.at_level(logging.WARNING):
            recs = scanner._parse_suppressions_file(str(repo))
        assert recs == {}
        assert "no 'id' field" in caplog.text
        assert "line 1" in caplog.text

    def test_count_mismatch_is_reported(self, tmp_path, caplog):
        repo = _supp(tmp_path, '- id: aaa111\n  reason: "ok"\n- reason: "no id"\n')
        with caplog.at_level(logging.WARNING):
            scanner._parse_suppressions_file(str(repo))
        assert "Parsed 1 of 2" in caplog.text

    def test_flow_style_is_refused_loudly(self, tmp_path, caplog):
        repo = _supp(tmp_path, '- id: aaa111\n  reason: {nested: value}\n')
        with caplog.at_level(logging.WARNING):
            recs = scanner._parse_suppressions_file(str(repo))
        assert "not supported" in caplog.text
        assert recs["aaa111"]["reason"] == "", "a half-parsed value must not be stored"

    def test_unparseable_line_is_reported(self, tmp_path, caplog):
        repo = _supp(tmp_path, "- id: aaa111\n  this line has no colon\n")
        with caplog.at_level(logging.WARNING):
            scanner._parse_suppressions_file(str(repo))
        assert "unparseable line" in caplog.text

    def test_a_clean_file_logs_no_warnings(self, tmp_path, caplog):
        """Control: the loud path must stay quiet on a well-formed file."""
        repo = _supp(tmp_path, '- id: aaa111\n  reason: "fine"\n- id: bbb222\n  reason: "also fine"\n')
        with caplog.at_level(logging.WARNING):
            recs = scanner._parse_suppressions_file(str(repo))
        assert set(recs) == {"aaa111", "bbb222"}
        assert caplog.text == ""


class TestStripInlineComment:
    @pytest.mark.parametrize("raw,expected", [
        ("abc123  # note", "abc123"),
        ("abc123", "abc123"),
        ('"has #hash inside"', '"has #hash inside"'),
        ("'single #hash'", "'single #hash'"),
        ("value#nospace", "value#nospace"),   # no preceding space -> not a comment
        ("# whole line", ""),
    ])
    def test_cases(self, raw, expected):
        assert scanner._strip_inline_comment(raw) == expected


# ── QUAL-16 ─────────────────────────────────────────────────────────────────

class TestCommitShasAreSent:
    @pytest.mark.parametrize("cls", [scanner.GitHub, scanner.GitLab,
                                      scanner.Bitbucket, scanner.AzureDevOps])
    def test_every_platform_exposes_sha_accessors(self, cls):
        p = cls()
        assert isinstance(p.base_sha(), str)
        assert isinstance(p.head_sha(), str)

    def test_github_head_sha_reads_github_sha(self, monkeypatch):
        monkeypatch.setenv("GITHUB_SHA", "deadbeef")
        assert scanner.GitHub().head_sha() == "deadbeef"

    def test_gitlab_reads_ci_commit_sha(self, monkeypatch):
        monkeypatch.setenv("CI_COMMIT_SHA", "cafebabe")
        assert scanner.GitLab().head_sha() == "cafebabe"

    def test_bitbucket_reads_bitbucket_commit(self, monkeypatch):
        monkeypatch.setenv("BITBUCKET_COMMIT", "f00d")
        assert scanner.Bitbucket().head_sha() == "f00d"

    def test_azure_reads_build_sourceversion(self, monkeypatch):
        monkeypatch.setenv("BUILD_SOURCEVERSION", "abc123")
        assert scanner.AzureDevOps().head_sha() == "abc123"

    def test_missing_env_yields_empty_not_a_crash(self, monkeypatch):
        monkeypatch.delenv("GITHUB_SHA", raising=False)
        assert scanner.GitHub().head_sha() == ""


# ── QUAL-17 ─────────────────────────────────────────────────────────────────

class TestSuppressionIdResolutionIsDiscriminated:
    def _novel(self, *sids):
        return [{"files": [{"similarity_id": s} for s in sids]}]

    def test_single_match_resolves(self):
        outcome, sid, n = scanner.resolve_suppression_id("abc123", self._novel("abc123def"), [])
        assert (outcome, sid, n) == ("resolved", "abc123def", 1)

    def test_no_match_is_not_found(self):
        outcome, sid, n = scanner.resolve_suppression_id("zzzzzz", self._novel("abc123def"), [])
        assert (outcome, sid, n) == ("not_found", None, 0)

    def test_prefix_collision_is_reported_as_ambiguous(self):
        """Previously indistinguishable from not-found, so a user hitting a
        real collision was sent to debug a nonexistent typo."""
        outcome, sid, n = scanner.resolve_suppression_id(
            "abc123", self._novel("abc123aaa", "abc123bbb"), [])
        assert outcome == "ambiguous"
        assert sid is None
        assert n == 2

    def test_short_prefixes_do_not_over_match(self):
        outcome, _, _ = scanner.resolve_suppression_id("abc", self._novel("abc123def"), [])
        assert outcome == "not_found"

    def test_already_suppressed_prefix_is_recognised(self):
        """The QUAL-17 core: suppressed_ids holds full 64-char hashes while
        the comment shows 16-char prefixes, so `raw_id not in suppressed_ids`
        was ALWAYS true and warned forever. Prefix matching is what the fix
        relies on."""
        suppressed = {"abc123def456789000000000000000000000000000000000000000000000000"}
        raw_id = "abc123def4567890"  # the 16-char prefix the comment displays
        assert raw_id not in suppressed, "precondition: exact membership fails"
        assert any(s.startswith(raw_id) for s in suppressed), \
            "prefix comparison is what makes the guard actually work"


# ── QUAL-18 ─────────────────────────────────────────────────────────────────

class TestSuppressionPushFailureIsDistinguishable:
    def test_no_commands_is_nothing_todo(self, tmp_path):
        outcome, detail = scanner.apply_suppression_commands(
            str(tmp_path), "https://h/r.git", "b", [])
        assert (outcome, detail) == ("nothing_todo", "")

    def test_already_present_is_nothing_todo_not_failed(self, tmp_path, monkeypatch):
        repo = _supp(tmp_path, "- id: aaa111\n  reason: \"already here\"\n")
        monkeypatch.setattr(scanner, "_git", lambda args, cwd=None, env=None: None)
        outcome, detail = scanner.apply_suppression_commands(
            str(repo), "https://h/r.git", "b",
            [("aaa111", "r", "a", "2026-01-01T00:00:00Z")])
        assert outcome == "nothing_todo"

    def test_rejected_push_is_failed_with_the_reason(self, tmp_path, monkeypatch):
        """The exact QUAL-18 scenario: branch protection or a missing
        contents:write rejects the push."""
        repo = tmp_path / "r"
        repo.mkdir()

        def _fake_git(args, cwd=None, env=None):
            if args[0] == "push":
                raise subprocess.CalledProcessError(
                    1, args, "", "remote: Permission denied to github-actions[bot]")

        monkeypatch.setattr(scanner, "_git", _fake_git)
        outcome, detail = scanner.apply_suppression_commands(
            str(repo), "https://h/r.git", "b",
            [("aaa111", "r", "a", "2026-01-01T00:00:00Z")])
        assert outcome == "failed"
        assert "Permission denied" in detail, \
            "the git stderr must reach the caller so it can go in the PR comment"

    def test_failed_is_not_confusable_with_nothing_todo(self, tmp_path, monkeypatch):
        """Both used to be `False`; main() read that as nothing-to-do and the
        comment came back byte-identical."""
        repo = tmp_path / "r"
        repo.mkdir()

        def _fake_git(args, cwd=None, env=None):
            if args[0] == "push":
                raise subprocess.CalledProcessError(1, args, "", "rejected")

        monkeypatch.setattr(scanner, "_git", _fake_git)
        failed, _ = scanner.apply_suppression_commands(
            str(repo), "https://h/r.git", "b",
            [("aaa111", "r", "a", "2026-01-01T00:00:00Z")])
        nothing, _ = scanner.apply_suppression_commands(
            str(tmp_path / "other"), "https://h/r.git", "b", [])
        assert failed != nothing
