"""Tests for SEC-01 (author authorization on /zagware suppress), SEC-15
(the scanner's own comment is never a trusted command source), and QUAL-21
(optional reason, backtick tolerance) — all three touch the same
_filter_authorized_comments / parse_suppression_commands pipeline in
src/scanner.py, so they're covered together.

Threat model exercised here: a hostile PR contributor with no repo privilege
posting `/zagware suppress <id> <reason>` on a public repo (SEC-01's exact
scenario from REVIEW-2026-07-30.md).
"""
from __future__ import annotations

import scanner


def _comment(body, author="someone", author_association="", created_at="2026-01-01T00:00:00Z"):
    return {"body": body, "author": author, "author_association": author_association, "created_at": created_at}


# ── SEC-01: authorization gate ──────────────────────────────────────────────

class TestFilterAuthorizedComments:
    def test_default_allowlist_permits_owner_member_collaborator(self):
        comments = [
            _comment("/zagware suppress abc123 fine", author_association="OWNER"),
            _comment("/zagware suppress abc124 fine", author_association="MEMBER"),
            _comment("/zagware suppress abc125 fine", author_association="COLLABORATOR"),
        ]
        assert scanner._filter_authorized_comments(comments) == comments

    def test_default_allowlist_rejects_unprivileged_outside_contributor(self):
        """The exact SEC-01 scenario: any GitHub user on a public repo."""
        comments = [_comment("/zagware suppress abc123 nice try", author="rando",
                              author_association="NONE")]
        assert scanner._filter_authorized_comments(comments) == []

    def test_rejects_first_time_contributor(self):
        comments = [_comment("/zagware suppress abc123 x",
                              author_association="FIRST_TIME_CONTRIBUTOR")]
        assert scanner._filter_authorized_comments(comments) == []

    def test_default_deny_when_author_association_missing(self):
        """A platform/response shape that omits the field must be rejected,
        not silently trusted — this is the specific 'default-deny' requirement
        from the fix, distinct from an explicit disallowed value."""
        c = {"body": "/zagware suppress abc123 x", "author": "someone", "created_at": ""}
        assert scanner._filter_authorized_comments([c]) == []

    def test_case_insensitive_association_matching(self):
        comments = [_comment("/zagware suppress abc123 fine", author_association="owner")]
        assert scanner._filter_authorized_comments(comments) == comments

    def test_unrelated_comments_from_unauthorized_users_are_dropped(self):
        """Every comment not from an allowed association is excluded, not just
        ones that happen to contain a suppress attempt — parse_suppression_commands
        is the only consumer of this list, so a strict allowlist (rather than
        content-sniffing which comments to keep) is both simpler and safer."""
        comments = [_comment("nice PR, one nit on line 40", author_association="NONE")]
        assert scanner._filter_authorized_comments(comments) == []

    def test_custom_allowlist_via_env(self, reload_scanner):
        mod = reload_scanner(ZAGWARE_SUPPRESS_ALLOWED_ASSOCIATIONS="CONTRIBUTOR")
        comments = [{"body": "/zagware suppress abc123 x", "author": "a",
                     "author_association": "CONTRIBUTOR", "created_at": ""}]
        assert mod._filter_authorized_comments(comments) == comments
        # and the default set is no longer implicitly allowed
        owner_comment = [{"body": "/zagware suppress abc123 x", "author": "a",
                           "author_association": "OWNER", "created_at": ""}]
        assert mod._filter_authorized_comments(owner_comment) == []


class TestEndToEndAuthorizationBypass:
    """Reproduces the full attack path SEC-01 describes end-to-end through the
    real two-function pipeline (filter -> parse), not just the filter alone."""

    def test_unauthorized_suppress_command_never_reaches_parse_suppression_commands(self):
        comments = [_comment("/zagware suppress deadbeef01 accepted risk",
                              author="attacker", author_association="NONE")]
        filtered = scanner._filter_authorized_comments(comments)
        commands = scanner.parse_suppression_commands(filtered)
        assert commands == []

    def test_authorized_suppress_command_reaches_parse_suppression_commands(self):
        comments = [_comment("/zagware suppress deadbeef01 accepted risk",
                              author="maintainer", author_association="OWNER")]
        filtered = scanner._filter_authorized_comments(comments)
        commands = scanner.parse_suppression_commands(filtered)
        assert commands == [("deadbeef01", "accepted risk", "maintainer", "2026-01-01T00:00:00Z")]


# ── SEC-15: the scanner's own comment is never a trusted command source ────

class TestOwnCommentIsNeverParsed:
    def test_comment_containing_github_marker_is_skipped(self):
        body = f"{scanner._COMMENT_MARKER}\n## some heading\n/zagware suppress abc123 <reason>"
        comments = [_comment(body, author_association="OWNER")]
        assert scanner.parse_suppression_commands(comments) == []

    def test_comment_containing_bitbucket_marker_is_skipped(self):
        body = f"/zagware suppress abc123 <reason>\n{scanner._BB_COMMENT_MARKER}"
        comments = [_comment(body, author_association="OWNER")]
        assert scanner.parse_suppression_commands(comments) == []

    def test_reply_quoting_the_template_without_the_marker_still_parses(self):
        """The marker check, not content-sniffing, is what makes this safe —
        a genuine human reply quoting the template with a real id (no hidden
        marker) is legitimately actionable, so it must still parse."""
        comments = [_comment("/zagware suppress <abc123> <reason>", author_association="OWNER")]
        commands = scanner.parse_suppression_commands(comments)
        assert len(commands) == 1
        assert commands[0][0] == "abc123"  # angle brackets stripped as non-hex


# ── QUAL-21: optional reason + backtick tolerance ───────────────────────────

class TestOptionalReasonAndBackticks:
    def test_no_reason_no_longer_a_silent_no_op(self):
        comments = [_comment("/zagware suppress deadbeef01", author_association="OWNER")]
        commands = scanner.parse_suppression_commands(comments)
        assert commands == [("deadbeef01", "Suppressed via PR comment", "someone", "2026-01-01T00:00:00Z")]

    def test_leading_and_trailing_backticks_stripped(self):
        comments = [_comment("/zagware suppress `deadbeef01` accepted", author_association="OWNER")]
        commands = scanner.parse_suppression_commands(comments)
        assert commands[0][0] == "deadbeef01"

    def test_command_must_start_the_line_not_be_embedded_mid_sentence(self):
        """SEC-15's anchoring requirement: quoting the command inside prose
        (not authoring it as a command) must not trigger."""
        comments = [_comment('I saw someone write "/zagware suppress abc123 x" in another PR',
                              author_association="OWNER")]
        assert scanner.parse_suppression_commands(comments) == []
