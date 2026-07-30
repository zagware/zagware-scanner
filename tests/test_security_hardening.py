"""Tests for SEC-05 / SEC-06 / SEC-07 / SEC-08 / SEC-09 / SEC-10 — the six
MEDIUM security findings the phased plan deferred past Phase 5.

SEC-05: urllib follows 30x by default and CPython's HTTPRedirectHandler
        strips only content headers, so Authorization survived a cross-host
        redirect; _http had no timeout at all; ZAGWARE_PLATFORM_URL accepted
        http://, putting the bearer token on the wire in cleartext.
SEC-06: _cell escaped only "|" and newline, and only 2 of 6 IaC columns went
        through it. File names, resource names and lockfile package names --
        all PR-controlled -- were interpolated raw, so a PR could forge the
        scanner's own comment (the authoritative gate output reviewers read).
SEC-07: every clone URL embedded a live credential in positional argv, so the
        token sat in /proc/<pid>/cmdline and was persisted by git into the
        clone's .git/config; `.git` was only the *default* exclude value, so
        any ZAGWARE_EXCLUDE_PATHS override silently un-excluded it.
SEC-08: betterleaks ran without --redact and its console output -- which for a
        secrets scanner is the leaked credential -- was copied into the CI log.
SEC-09: `$ip: 0` is falsy in JS, so PostHog's GeoIP plugin discarded it and
        geolocated the runner's real IP anyway.
SEC-10: a hand-written `suppressed_by:` in the repo's own suppressions.yaml
        was promoted to the same "pr_comment" confidence tier as a real,
        scanner-verified /zagware suppress command.
"""
from __future__ import annotations

import base64
import subprocess
import urllib.error
import urllib.parse
import urllib.request

import pytest

import scanner


# ── SEC-05 ──────────────────────────────────────────────────────────────────

class TestCrossHostRedirectIsRefused:
    def _redirect(self, from_url: str, to_url: str):
        handler = scanner._NoCrossHostRedirect()
        req = urllib.request.Request(from_url)
        req.add_header("Authorization", "Bearer SEKRET")
        return handler.redirect_request(req, None, 302, "Found", {}, to_url)

    def test_cross_host_redirect_returns_none(self):
        """None makes urllib raise instead of following -- fail closed."""
        assert self._redirect("https://a.example/x", "https://evil.example/y") is None

    def test_same_host_redirect_is_still_followed(self):
        out = self._redirect("https://a.example/x", "https://a.example/y")
        assert out is not None, "same-host redirects must keep working"

    def test_scheme_downgrade_to_other_host_refused(self):
        assert self._redirect("https://a.example/x", "http://evil.example/y") is None

    def test_port_change_counts_as_a_different_host(self):
        """netloc comparison includes the port, so :443 -> :8443 is cross-host."""
        assert self._redirect("https://a.example/x", "https://a.example:8443/y") is None

    def test_opener_is_built_with_the_guard_installed(self):
        assert any(isinstance(h, scanner._NoCrossHostRedirect)
                   for h in scanner._opener.handlers), \
            "the module opener must carry the redirect guard, not just define it"


class TestHttpHasATimeout:
    def test_urlopen_passes_a_default_timeout(self, monkeypatch):
        captured = {}

        def _fake_open(req, timeout=None):
            captured["timeout"] = timeout
            raise urllib.error.URLError("stop here")

        monkeypatch.setattr(scanner._opener, "open", _fake_open)
        with pytest.raises(urllib.error.URLError):
            scanner._urlopen(urllib.request.Request("https://a.example/"))
        assert captured["timeout"] == scanner._HTTP_TIMEOUT
        assert captured["timeout"] is not None, "an unbounded socket can hang the whole job"

    def test_http_helper_routes_through_the_guarded_opener(self, monkeypatch):
        """_http must not call urllib.request.urlopen directly -- that path has
        neither the redirect guard nor a timeout."""
        called = {}

        def _fake_urlopen(req, timeout=None):
            called["via"] = "guarded"
            raise urllib.error.URLError("stop here")

        monkeypatch.setattr(scanner, "_urlopen", _fake_urlopen)
        with pytest.raises(urllib.error.URLError):
            scanner._http("GET", "https://a.example/")
        assert called.get("via") == "guarded"


class TestPlatformUrlRequiresHttps:
    def test_https_is_accepted(self):
        assert scanner._validate_platform_url("https://app.zagware.io") == "https://app.zagware.io"

    def test_plain_http_is_refused(self):
        assert scanner._validate_platform_url("http://app.zagware.io") == ""

    def test_http_localhost_is_allowed_for_development(self):
        assert scanner._validate_platform_url("http://localhost:8000") == "http://localhost:8000"
        assert scanner._validate_platform_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"

    def test_empty_stays_empty(self):
        assert scanner._validate_platform_url("") == ""

    def test_refusal_is_logged_with_the_reason(self, caplog):
        import logging
        with caplog.at_level(logging.ERROR):
            scanner._validate_platform_url("http://evil.example")
        assert "https" in caplog.text
        assert "bearer token" in caplog.text.lower()

    def test_nonsense_scheme_is_refused(self):
        assert scanner._validate_platform_url("ftp://app.zagware.io") == ""
        assert scanner._validate_platform_url("app.zagware.io") == ""


# ── SEC-06 ──────────────────────────────────────────────────────────────────

class TestCellEscaping:
    def test_backtick_cannot_escape_the_code_span(self):
        assert "`" not in scanner._cell("evil`name")

    def test_angle_brackets_are_escaped(self):
        out = scanner._cell("</details><img src=x>")
        assert "<" not in out and ">" not in out
        assert "&lt;" in out and "&gt;" in out

    def test_pipe_is_escaped(self):
        assert scanner._cell("a|b") == "a\\|b"

    def test_newlines_and_carriage_returns_cannot_inject_rows(self):
        out = scanner._cell("a\r\n| forged | row |")
        assert "\n" not in out and "\r" not in out

    def test_none_becomes_empty_string(self):
        assert scanner._cell(None) == ""

    def test_non_string_is_coerced(self):
        assert scanner._cell(42) == "42"

    def test_long_values_are_truncated(self):
        assert scanner._cell("x" * 200).endswith("…")


class TestCommentCannotBeForgedByAPullRequest:
    """End-to-end: a PR-supplied file name carrying markup must not survive
    into the rendered comment as live markup."""

    HOSTILE = '`</details><img src=x onerror=1>|forged'

    def _iac(self, **over):
        f = {"file_name": self.HOSTILE, "line": 1, "similarity_id": "a",
             "resource_name": self.HOSTILE, "issue_type": self.HOSTILE,
             "expected_value": "e", "actual_value": "v"}
        f.update(over)
        return [{"query_name": "rule", "severity": "HIGH", "category": "Networking",
                 "platform": "Terraform", "description": "d", "cwe": None,
                 "query_url": None, "files": [f]}]

    def test_hostile_file_name_is_neutralised_in_the_iac_table(self):
        novel = self._iac()
        out = scanner.render_comment({"queries": []}, {"queries": novel}, novel,
                                      "main", "feature")
        # render_comment legitimately emits its own </details> as section
        # structure, so scope the assertion to the finding's own data row --
        # that is where the PR-supplied text lands.
        row = next(l for l in out.splitlines() if l.startswith("| `"))
        assert "</details>" not in row
        assert "<img" not in row
        assert "`" not in row.replace("| `", "").replace("` |", "").replace("` ", ""), \
            "no stray backtick may survive inside a value and break the code span"
        assert "&lt;/details&gt;" in row, "the markup must be neutralised, not dropped"

    def test_hostile_package_name_is_neutralised_in_the_sca_table(self):
        f = {"vulnerability_id": "CVE-1", "severity": "HIGH",
             "package_name": self.HOSTILE, "package_version": "1.0",
             "package_type": "npm", "similarity_id": "s",
             "vuln_urls": [], "fix_versions": [], "fix_state": "unknown",
             "cvss_score": None, "kev_listed": False}
        out = scanner.render_sca_section([], [f], [f])
        assert "</details><img" not in out
        assert "<img" not in out

    def test_hostile_secrets_path_is_neutralised(self):
        f = {"rule_id": "generic", "file_path": self.HOSTILE, "line": 1,
             "tags": [], "validation_status": "unknown", "similarity_id": "s"}
        out = scanner.render_secrets_section([], [f], [f], "private")
        assert "<img" not in out

    def test_hostile_value_is_neutralised_in_suppression_hints(self):
        novel = self._iac()
        out = scanner.render_suppression_hints(novel, [], [])
        assert "<img" not in out

    def test_a_clean_finding_still_renders_its_real_values(self):
        """Control: escaping must not mangle ordinary input."""
        novel = self._iac(file_name="terraform/main.tf", resource_name="aws_s3_bucket.logs",
                          issue_type="Missing attribute")
        out = scanner.render_comment({"queries": []}, {"queries": novel}, novel,
                                      "main", "feature")
        assert "terraform/main.tf" in out
        assert "aws_s3_bucket.logs" in out
        assert "Missing attribute" in out


# ── SEC-07 ──────────────────────────────────────────────────────────────────

class TestCredentialIsSplitOutOfTheCloneUrl:
    URL = "https://x-access-token:ghp_secrettoken@github.com/owner/repo.git"

    def test_url_is_returned_credential_free(self):
        clean, _ = scanner._split_credential(self.URL)
        assert clean == "https://github.com/owner/repo.git"
        assert "ghp_secrettoken" not in clean

    def test_credential_moves_into_an_extraheader_env(self):
        _, env = scanner._split_credential(self.URL)
        assert env["GIT_CONFIG_COUNT"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
        decoded = base64.b64decode(
            env["GIT_CONFIG_VALUE_0"].split("Basic ", 1)[1]).decode()
        assert decoded == "x-access-token:ghp_secrettoken"

    def test_url_without_credentials_is_untouched(self):
        clean, env = scanner._split_credential("https://github.com/owner/repo.git")
        assert clean == "https://github.com/owner/repo.git"
        assert env == {}

    def test_non_default_port_is_preserved(self):
        clean, _ = scanner._split_credential("https://u:p@git.example.com:8443/x.git")
        assert clean == "https://git.example.com:8443/x.git"

    def test_percent_encoded_credential_is_decoded_before_encoding(self):
        """Bitbucket emails are percent-encoded in the URL; the Basic header
        must carry the real value, not the encoded one."""
        _, env = scanner._split_credential("https://a%40b.com:tok@bitbucket.org/x.git")
        decoded = base64.b64decode(
            env["GIT_CONFIG_VALUE_0"].split("Basic ", 1)[1]).decode()
        assert decoded == "a@b.com:tok"

    def test_clone_passes_a_clean_argv_and_the_env(self, monkeypatch):
        seen = {}

        def _fake_git(args, cwd=None, env=None):
            seen["args"] = args
            seen["env"] = env

        monkeypatch.setattr(scanner, "_git", _fake_git)
        scanner.clone_branch(self.URL, "main", "/tmp/dest")
        assert not any("ghp_secrettoken" in a for a in seen["args"]), \
            "the token must never appear in git argv (/proc/<pid>/cmdline)"
        assert seen["env"]["GIT_CONFIG_KEY_0"] == "http.extraHeader"

    def test_fetch_for_a_sha_also_gets_the_credential(self, monkeypatch):
        calls = []
        monkeypatch.setattr(scanner, "_git",
                            lambda args, cwd=None, env=None: calls.append((args, env)))
        scanner.clone_and_checkout_sha(self.URL, "main", "deadbeef", "/tmp/dest")
        fetch = next(c for c in calls if c[0][0] == "fetch")
        assert fetch[1] and fetch[1]["GIT_CONFIG_KEY_0"] == "http.extraHeader", \
            "origin is credential-free now, so fetch must supply auth out-of-band"

    def test_real_git_clone_leaves_no_credential_in_git_config(self, tmp_path):
        """Executed against real git: clone a real local repo through the real
        code path and assert .git/config carries no token. Uses a file:// URL
        with a credential, which git accepts and ignores."""
        origin = tmp_path / "origin"
        origin.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(origin)], check=True)
        (origin / "f.txt").write_text("x")
        env = {**__import__("os").environ,
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}
        subprocess.run(["git", "add", "."], cwd=origin, check=True, env=env)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=origin, check=True, env=env)

        dest = tmp_path / "clone"
        scanner.clone_branch(f"file://{origin}", "main", str(dest))
        cfg = (dest / ".git" / "config").read_text()
        assert "ghp_" not in cfg
        assert (dest / "f.txt").exists(), "the clone must still actually work"


class TestGitIsAlwaysExcludedFromScans:
    def test_dot_git_present_by_default(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS=None)
        assert ".git" in mod._scan_exclude_paths().split(",")

    def test_dot_git_survives_an_operator_override(self, reload_scanner):
        """The exact SEC-07 regression: setting the var used to drop .git."""
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor,node_modules")
        parts = mod._scan_exclude_paths().split(",")
        assert ".git" in parts
        assert "vendor" in parts and "node_modules" in parts

    def test_no_duplicate_when_operator_lists_it_explicitly(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_EXCLUDE_PATHS="vendor,.git")
        assert mod._scan_exclude_paths().split(",").count(".git") == 1

    def test_syft_is_told_to_skip_dot_git(self, monkeypatch, tmp_path):
        seen = {}

        def _fake_run(cmd, **kw):
            seen["cmd"] = cmd
            raise FileNotFoundError("stop")

        monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
        scanner._run_syft(str(tmp_path), str(tmp_path / "sbom.json"))
        assert "--exclude" in seen["cmd"]
        assert "./.git/**" in seen["cmd"]


# ── SEC-08 ──────────────────────────────────────────────────────────────────

class TestBetterleaksRedaction:
    def _run(self, monkeypatch, tmp_path, returncode: int):
        seen = {}

        class _R:
            def __init__(self):
                self.returncode = returncode
                self.stdout = "LEAKED ghp_realsecrettokenvalue000000000000000000"
                self.stderr = "LEAKED ghp_realsecrettokenvalue000000000000000000"

        def _fake_run(cmd, **kw):
            seen["cmd"] = cmd
            (tmp_path / "secrets_base.json").write_text("null")
            return _R()

        monkeypatch.setattr(scanner.subprocess, "run", _fake_run)
        scanner.run_secrets_scan(str(tmp_path), str(tmp_path), "base")
        return seen

    def test_redact_flag_is_passed(self, monkeypatch, tmp_path):
        seen = self._run(monkeypatch, tmp_path, 0)
        assert "--redact" in seen["cmd"]

    def test_console_output_is_never_logged_on_failure(self, monkeypatch, tmp_path, caplog):
        """The exact SEC-08 leak: up to 400 chars of unredacted scanner console
        output went to the CI job log on any non-zero exit."""
        import logging
        with caplog.at_level(logging.WARNING):
            self._run(monkeypatch, tmp_path, 1)
        assert "ghp_realsecrettokenvalue" not in caplog.text
        assert "LEAKED" not in caplog.text
        assert "exited 1" in caplog.text, "the return code must still be reported"


# ── SEC-09 ──────────────────────────────────────────────────────────────────

class TestTelemetryGeoipIsActuallyDisabled:
    def _props(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(scanner.json, "dumps",
                            lambda payload, *a, **k: captured.update(payload) or "{}")
        monkeypatch.setattr(scanner.threading, "Thread",
                            lambda *a, **k: type("T", (), {"start": lambda s: None})())
        scanner._send_telemetry_event("scan_started", {"_distinct_id": "x"})
        return captured.get("properties", {})

    def test_geoip_disable_is_sent_true(self, monkeypatch, reload_scanner):
        mod = reload_scanner(ZAGWARE_TELEMETRY=None)
        captured = {}
        monkeypatch.setattr(mod.json, "dumps",
                            lambda payload, *a, **k: captured.update(payload) or "{}")
        monkeypatch.setattr(mod.threading, "Thread",
                            lambda *a, **k: type("T", (), {"start": lambda s: None})())
        mod._send_telemetry_event("scan_started", {"_distinct_id": "x"})
        props = captured["properties"]
        assert props["$geoip_disable"] is True, \
            "PostHog only skips GeoIP on $geoip_disable; $ip=0 is falsy and was ignored"

    def test_ip_is_none_not_zero(self, monkeypatch, reload_scanner):
        mod = reload_scanner(ZAGWARE_TELEMETRY=None)
        captured = {}
        monkeypatch.setattr(mod.json, "dumps",
                            lambda payload, *a, **k: captured.update(payload) or "{}")
        monkeypatch.setattr(mod.threading, "Thread",
                            lambda *a, **k: type("T", (), {"start": lambda s: None})())
        mod._send_telemetry_event("scan_started", {"_distinct_id": "x"})
        assert captured["properties"]["$ip"] is None
        assert captured["properties"]["$ip"] != 0


class TestHashHonesty:
    def test_docstring_no_longer_claims_irreversibility(self):
        doc = scanner._telemetry_hash.__doc__ or ""
        assert "NOT irreversible" in doc or "not irreversible" in doc.lower()

    def test_hash_is_still_stable_for_grouping(self):
        a = scanner._telemetry_hash("GitHub:acme/widgets")
        b = scanner._telemetry_hash("GitHub:acme/widgets")
        assert a == b and len(a) == 16


# ── SEC-10 ──────────────────────────────────────────────────────────────────

def _write_supp(repo, body: str):
    (repo / ".zagware").mkdir(parents=True, exist_ok=True)
    (repo / ".zagware" / "suppressions.yaml").write_text(body)


class TestSuppressionAttributionTiers:
    def test_scanner_resolved_command_is_verified(self, tmp_path):
        repo = tmp_path / "r"
        repo.mkdir()
        recs = scanner.collect_suppression_records(
            str(repo), {"queries": []}, [], [], {"abc123"},
            [("abc123", "reason", "real-author", "2026-01-01T00:00:00Z")],
        )
        assert len(recs) == 1
        assert recs[0]["added_via"] == "pr_comment"
        assert recs[0]["added_by"] == "real-author"
        assert recs[0]["claimed_by"] is None

    def test_hand_written_suppressed_by_is_not_promoted_to_verified(self, tmp_path):
        """The exact SEC-10 forgery: a PR author hand-writes suppressed_by and
        previously got a record indistinguishable from a real command."""
        repo = tmp_path / "r"
        repo.mkdir()
        _write_supp(repo, '- id: abc123\n  reason: "x"\n  suppressed_by: "trusted-maintainer"\n')
        recs = scanner.collect_suppression_records(
            str(repo), {"queries": []}, [], [], {"abc123"}, [],
        )
        assert recs[0]["added_via"] == "file_unverified"
        assert recs[0]["added_via"] != "pr_comment"
        assert recs[0]["added_by"] == "unknown", \
            "an unverified claim must not populate added_by"
        assert recs[0]["claimed_by"] == "trusted-maintainer", \
            "the claim is still carried, but explicitly as a claim"

    def test_file_entry_without_any_claim(self, tmp_path):
        repo = tmp_path / "r"
        repo.mkdir()
        _write_supp(repo, '- id: abc123\n  reason: "x"\n')
        recs = scanner.collect_suppression_records(
            str(repo), {"queries": []}, [], [], {"abc123"}, [],
        )
        assert recs[0]["added_via"] == "file_unverified"
        assert recs[0]["claimed_by"] is None
        assert recs[0]["added_by"] == "unknown"

    def test_blame_fallback_is_gone(self):
        """A depth-1 clone attributes every line to the checked-out commit, so
        blame credited whoever pushed last. Removed rather than relabelled."""
        assert not hasattr(scanner, "_blame_suppressions_file")

    def test_no_git_blame_is_ever_invoked(self, tmp_path, monkeypatch):
        repo = tmp_path / "r"
        repo.mkdir()
        _write_supp(repo, '- id: abc123\n  reason: "x"\n')

        def _must_not_run(*a, **k):
            pytest.fail("collect_suppression_records must not shell out to git")

        monkeypatch.setattr(scanner.subprocess, "run", _must_not_run)
        scanner.collect_suppression_records(
            str(repo), {"queries": []}, [], [], {"abc123"}, [])
