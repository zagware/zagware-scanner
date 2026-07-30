"""QUAL-20: a minimal fixture test set for the scanner's core diff/render
logic, which had no direct unit tests before this review despite carrying
the most security-relevant behaviour in the file.

This file targets exactly the four gaps QUAL-20 named:
  1. new_findings / new_sca_findings / new_secrets_findings — the base/head/
     suppression diff that decides what a PR sees as "new".
  2. The severity filter table (covered by test_severity_table_docs.py and
     test_severity_thresholds.py — not duplicated here).
  3. Truncation must never destroy the platform comment-identity marker, on
     any of the two marker shapes the scanner emits (collapsible marker for
     GitHub/GitLab/Azure, plain-link marker for Bitbucket) — extends
     test_platform_comment_pagination.py's existing Bitbucket-only coverage.
  4. The suppression round-trip: apply_suppression_commands()'s YAML output,
     re-read by _parse_suppressions_file(), must return the exact same
     reason string, including one containing both a quote and a backslash.
     This also pins the QUAL-24 fix (backslash-then-quote escaping on write,
     single-pass unescape with exact-one-quote-pair stripping on read).
"""
from __future__ import annotations

import scanner


# ── (1) new_findings / new_sca_findings / new_secrets_findings ─────────────

def _iac_query(sim_ids: list[str], severity: str = "HIGH") -> dict:
    return {
        "query_name": "rule", "severity": severity, "category": "Networking",
        "platform": "Terraform",
        "files": [{"file_name": "main.tf", "line": i, "similarity_id": sid}
                  for i, sid in enumerate(sim_ids)],
    }


class TestNewFindingsIac:
    def test_identical_base_and_head_yields_no_novel_findings(self):
        base = {"queries": [_iac_query(["a", "b"])]}
        pr = {"queries": [_iac_query(["a", "b"])]}
        assert scanner.new_findings(base, pr) == []

    def test_head_only_finding_is_novel(self):
        base = {"queries": [_iac_query(["a"])]}
        pr = {"queries": [_iac_query(["a", "b"])]}
        out = scanner.new_findings(base, pr)
        assert len(out) == 1
        assert [f["similarity_id"] for f in out[0]["files"]] == ["b"]

    def test_suppressed_id_is_excluded_even_though_it_is_novel(self):
        base = {"queries": [_iac_query(["a"])]}
        pr = {"queries": [_iac_query(["a", "b"])]}
        assert scanner.new_findings(base, pr, suppressed={"b"}) == []

    def test_empty_base_treats_every_head_finding_as_novel(self):
        base = {"queries": []}
        pr = {"queries": [_iac_query(["a", "b"])]}
        out = scanner.new_findings(base, pr)
        assert count_ids(out) == {"a", "b"}


def count_ids(queries: list[dict]) -> set[str]:
    return {f["similarity_id"] for q in queries for f in q["files"]}


def _sca_finding(sim_id: str, severity: str = "HIGH") -> dict:
    return {"vulnerability_id": "CVE-2026-1", "severity": severity,
            "package_name": "pkg", "package_version": "1.0", "similarity_id": sim_id}


class TestNewScaFindings:
    def test_identical_base_and_head_yields_no_novel_findings(self):
        base = [_sca_finding("a")]
        head = [_sca_finding("a")]
        assert scanner.new_sca_findings(base, head) == []

    def test_head_only_finding_is_novel(self):
        base = [_sca_finding("a")]
        head = [_sca_finding("a"), _sca_finding("b")]
        out = scanner.new_sca_findings(base, head)
        assert [f["similarity_id"] for f in out] == ["b"]

    def test_suppressed_id_is_excluded(self):
        base = [_sca_finding("a")]
        head = [_sca_finding("a"), _sca_finding("b")]
        assert scanner.new_sca_findings(base, head, suppressed={"b"}) == []

    def test_none_base_treats_every_head_finding_as_novel(self):
        """base=None means "not scanned" (e.g. no manifest on the base branch),
        not "scanned and empty" -- both must behave identically here since a
        finding absent from an unscanned base is unambiguously new."""
        head = [_sca_finding("a"), _sca_finding("b")]
        out = scanner.new_sca_findings(None, head)
        assert {f["similarity_id"] for f in out} == {"a", "b"}

    def test_none_head_yields_no_findings(self):
        assert scanner.new_sca_findings([_sca_finding("a")], None) == []


def _secrets_finding(sim_id: str) -> dict:
    return {"rule_id": "generic-api-key", "file_path": "config.py",
            "line": 3, "similarity_id": sim_id}


class TestNewSecretsFindings:
    def test_identical_base_and_head_yields_no_novel_findings(self):
        base = [_secrets_finding("a")]
        head = [_secrets_finding("a")]
        assert scanner.new_secrets_findings(base, head) == []

    def test_head_only_finding_is_novel(self):
        base = [_secrets_finding("a")]
        head = [_secrets_finding("a"), _secrets_finding("b")]
        out = scanner.new_secrets_findings(base, head)
        assert [f["similarity_id"] for f in out] == ["b"]

    def test_suppressed_id_is_excluded(self):
        base = [_secrets_finding("a")]
        head = [_secrets_finding("a"), _secrets_finding("b")]
        assert scanner.new_secrets_findings(base, head, suppressed={"b"}) == []

    def test_none_base_treats_every_head_finding_as_novel(self):
        head = [_secrets_finding("a")]
        assert scanner.new_secrets_findings(None, head) == head


# ── (3) truncation must never destroy either marker shape ──────────────────

def _big_novel_query() -> list[dict]:
    return [{
        "query_name": "rule", "severity": "HIGH", "category": "Networking",
        "platform": "Terraform", "description": "d" * 200, "cwe": None, "query_url": None,
        "files": [{"file_name": f"file{i}.tf", "line": i,
                   "resource_name": "x", "similarity_id": str(i),
                   "issue_type": "Missing", "expected_value": "a", "actual_value": "b"}
                  for i in range(2000)],
    }]


def _truncate(comment: str) -> str:
    """Mirrors main()'s truncation step exactly."""
    if len(comment) > scanner._MAX_COMMENT:
        note = "\n\n> ⚠️ _Comment truncated — run locally for full output._"
        return comment[: scanner._MAX_COMMENT - len(note)] + note
    return comment


class TestMarkerSurvivesTruncationOnEveryPlatformShape:
    """QUAL-05's fix (marker emitted as line 1 of render_comment) covers both
    marker constants identically -- collapsible=True is shared by GitHub,
    GitLab and Azure DevOps (all render _COMMENT_MARKER); collapsible=False
    is Bitbucket (_BB_COMMENT_MARKER). Bitbucket alone was pinned by
    test_platform_comment_pagination.py; this locks in the shared path too."""

    def test_collapsible_marker_survives_for_github_gitlab_azure(self):
        novel = _big_novel_query()
        comment = scanner.render_comment({"queries": []}, {"queries": novel}, novel,
                                          "main", "feature", collapsible=True)
        assert len(comment) > scanner._MAX_COMMENT  # sanity: actually oversized
        truncated = _truncate(comment)
        assert truncated.startswith(scanner._COMMENT_MARKER)

    def test_bitbucket_marker_survives(self):
        novel = _big_novel_query()
        comment = scanner.render_comment({"queries": []}, {"queries": novel}, novel,
                                          "main", "feature", collapsible=False)
        assert len(comment) > scanner._MAX_COMMENT
        truncated = _truncate(comment)
        assert truncated.startswith(scanner._BB_COMMENT_MARKER)


# ── (4) suppression round-trip, including quote + backslash ────────────────

class TestSuppressionReasonRoundTrip:
    def test_plain_reason_round_trips(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setattr(scanner, "_git", lambda args, cwd=None: None)

        scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature",
            [("deadbeef01", "accepted risk", "maintainer", "2026-01-01T00:00:00Z")],
        )
        records = scanner._parse_suppressions_file(str(repo))
        assert records["deadbeef01"]["reason"] == "accepted risk"

    def test_reason_with_quote_and_backslash_round_trips_exactly(self, tmp_path, monkeypatch):
        """The exact QUAL-24 scenario: a human-written reason containing both
        a double quote and a bare backslash (e.g. quoting someone, or a
        Windows-style path) must come back byte-for-byte identical, not
        mangled with a dangling backslash or a silently dropped character."""
        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setattr(scanner, "_git", lambda args, cwd=None: None)

        reason = r'reviewer said "fine, ship it" — see C:\configs\policy.yaml'
        scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature",
            [("cafebabe02", reason, "maintainer", "2026-01-01T00:00:00Z")],
        )
        records = scanner._parse_suppressions_file(str(repo))
        assert records["cafebabe02"]["reason"] == reason

    def test_reason_that_is_only_backslashes_round_trips(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setattr(scanner, "_git", lambda args, cwd=None: None)

        reason = "\\\\server\\share\\path"
        scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature",
            [("f00dcafe03", reason, "maintainer", "2026-01-01T00:00:00Z")],
        )
        records = scanner._parse_suppressions_file(str(repo))
        assert records["f00dcafe03"]["reason"] == reason

    def test_written_yaml_is_valid_yaml(self, tmp_path, monkeypatch):
        """Belt-and-braces: the escaped output must also be syntactically
        valid YAML, not merely something our own hand-rolled parser accepts."""
        import yaml

        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setattr(scanner, "_git", lambda args, cwd=None: None)

        reason = r'a "quoted" reason with a \backslash and \\double\\ backslashes'
        scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature",
            [("0123456789", reason, "maintainer", "2026-01-01T00:00:00Z")],
        )
        text = (repo / ".zagware" / "suppressions.yaml").read_text()
        parsed = yaml.safe_load(text)
        assert parsed[0]["reason"] == reason
