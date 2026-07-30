"""Tests for QUAL-11/DOC-06: the documented `expires:` suppression field must
actually expire suppressions, not silently do nothing forever.

Before the fix, `.zagware/suppressions.yaml` documented `expires: "<ISO date>"`
as "optional -- suppression auto-expires", `_parse_suppressions_file` read the
key into `current` but `_flush()` never propagated it into the returned
record, and `load_suppressions()` returned every record's id unconditionally.
A user who time-boxed an accepted-risk finding got a permanent suppression
with no error, no warning, and no reminder anywhere in the PR comment.
"""
from __future__ import annotations

import logging

import scanner


def _make_repo(tmp_path, name="repo"):
    d = tmp_path / name
    d.mkdir()
    (d / ".zagware").mkdir()
    return d


def _write_suppressions(repo, text: str) -> None:
    (repo / ".zagware" / "suppressions.yaml").write_text(text)


class TestExpiresIsEnforced:
    def test_future_expiry_stays_active(self, tmp_path):
        repo = _make_repo(tmp_path)
        _write_suppressions(repo, (
            "- id: abc123def456\n"
            "  reason: \"time-boxed accepted risk\"\n"
            "  expires: \"2099-12-31\"\n"
        ))
        assert scanner.load_suppressions(str(repo)) == {"abc123def456"}

    def test_past_expiry_is_dropped(self, tmp_path, caplog):
        repo = _make_repo(tmp_path)
        _write_suppressions(repo, (
            "- id: abc123def456\n"
            "  reason: \"time-boxed accepted risk\"\n"
            "  expires: \"2020-01-01\"\n"
        ))
        with caplog.at_level(logging.INFO, logger="zagware"):
            result = scanner.load_suppressions(str(repo))
        assert result == set()
        assert any("expired" in r.message for r in caplog.records)

    def test_no_expires_field_stays_active_forever(self, tmp_path):
        """The common case (no expires) must be unaffected -- most
        suppressions have no expiry at all."""
        repo = _make_repo(tmp_path)
        _write_suppressions(repo, (
            "- id: abc123def456\n"
            "  reason: \"false positive\"\n"
        ))
        assert scanner.load_suppressions(str(repo)) == {"abc123def456"}

    def test_expiry_exactly_today_stays_active(self, tmp_path):
        """expires is a date-of-expiry, not a date-of-still-valid -- the
        suppression should remain active through its expiry date itself and
        lapse only once that date has fully passed."""
        import datetime as dt
        repo = _make_repo(tmp_path)
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        _write_suppressions(repo, (
            f"- id: abc123def456\n"
            f"  reason: \"expires today\"\n"
            f"  expires: \"{today}\"\n"
        ))
        assert scanner.load_suppressions(str(repo)) == {"abc123def456"}

    def test_unparseable_expiry_stays_active_but_warns(self, tmp_path, caplog):
        """A malformed date must not silently do nothing (the exact bug
        class this whole feature was), and must not force-expire on a typo
        either -- it stays active with a loud warning until fixed."""
        repo = _make_repo(tmp_path)
        _write_suppressions(repo, (
            "- id: abc123def456\n"
            "  reason: \"typo'd date\"\n"
            "  expires: \"31 December 2026\"\n"
        ))
        with caplog.at_level(logging.WARNING, logger="zagware"):
            result = scanner.load_suppressions(str(repo))
        assert result == {"abc123def456"}
        assert any("unparseable" in r.message for r in caplog.records)

    def test_mixed_expired_and_active_entries(self, tmp_path):
        repo = _make_repo(tmp_path)
        _write_suppressions(repo, (
            "- id: expiredfinding01\n"
            "  reason: \"should be gone\"\n"
            "  expires: \"2020-01-01\"\n"
            "- id: activefinding02\n"
            "  reason: \"still suppressed\"\n"
            "  expires: \"2099-01-01\"\n"
            "- id: permanentfinding03\n"
            "  reason: \"no expiry at all\"\n"
        ))
        result = scanner.load_suppressions(str(repo))
        assert result == {"activefinding02", "permanentfinding03"}

    def test_old_broken_behaviour_proves_the_bug_was_real(self, tmp_path):
        """Anchor: the raw parse (not the public load_suppressions API) must
        capture expires at all -- proving the previous silent-drop in _flush
        genuinely existed, this isn't a hypothetical."""
        repo = _make_repo(tmp_path)
        _write_suppressions(repo, (
            "- id: abc123def456\n"
            "  reason: \"x\"\n"
            "  expires: \"2020-01-01\"\n"
        ))
        records = scanner._parse_suppressions_file(str(repo))
        assert records["abc123def456"]["expires"] == "2020-01-01"
