"""Tests for QUAL-05/QUAL-12: the Bitbucket comment marker must survive
truncation, its dead fallback matcher must be gone, and the GitLab/Bitbucket
existing-comment lookups must paginate instead of only ever checking page 1.

QUAL-05: The Bitbucket marker used to be appended AFTER the whole comment was
assembled, then the truncation step sliced the tail off any comment over
_MAX_COMMENT chars -- destroying the marker on every large Bitbucket PR
comment, so post_or_update_comment could never find its own previous comment
and duplicated it on every push. The fix emits the marker as the first line
of render_comment's own output instead (matching how GitHub/GitLab/Azure's
_COMMENT_MARKER is already prepended), so it can never be truncated away.

QUAL-12: GitHub already paginates its existing-comment lookup; GitLab and
Bitbucket fetched exactly one page and stopped, so the scanner's own comment
fell off page 1 on any PR/MR with enough activity and got duplicated.
"""
from __future__ import annotations

import pytest

import scanner


@pytest.fixture
def gitlab_env(monkeypatch):
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test-token")
    monkeypatch.setenv("CI_PROJECT_PATH", "acme/widgets")
    monkeypatch.setenv("CI_PROJECT_ID", "1234")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "42")
    return scanner.GitLab()


@pytest.fixture
def bitbucket_env(monkeypatch):
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "7")
    monkeypatch.setenv("BITBUCKET_API_TOKEN", "atlassian-test-token")
    monkeypatch.setenv("ATLASSIAN_EMAIL", "bot@acme.test")
    monkeypatch.setenv("BITBUCKET_WORKSPACE", "acme")
    monkeypatch.setenv("BITBUCKET_REPO_SLUG", "widgets")
    monkeypatch.setenv("BITBUCKET_PR_ID", "42")
    return scanner.Bitbucket()


class TestGitLabCommentPagination:
    def test_finds_marker_on_a_later_page_and_updates(self, gitlab_env, fake_http):
        page_1 = [{"id": 1, "body": "unrelated system note"}] * 100
        page_2 = [{"id": 999, "body": f"{scanner._COMMENT_MARKER}\nold content"}]
        pages = {1: page_1, 2: page_2}

        def responder(method, url, data, headers):
            if method == "GET":
                page = int(url.rsplit("page=", 1)[1])
                return pages[page]
            assert method == "PUT"
            assert url.endswith("/999")
            return {}

        calls = fake_http(responder)
        gitlab_env.post_or_update_comment("new content")

        get_calls = [c for c in calls if c["method"] == "GET"]
        assert len(get_calls) == 2  # paginated past page 1
        put_calls = [c for c in calls if c["method"] == "PUT"]
        assert len(put_calls) == 1  # updated, not a fresh POST

    def test_no_marker_anywhere_posts_a_new_note(self, gitlab_env, fake_http):
        page_1 = [{"id": 1, "body": "unrelated"}] * 100
        page_2 = [{"id": 2, "body": "also unrelated"}] * 3
        pages = {1: page_1, 2: page_2}

        def responder(method, url, data, headers):
            if method == "GET":
                page = int(url.rsplit("page=", 1)[1])
                return pages[page]
            assert method == "POST"
            return {}

        calls = fake_http(responder)
        gitlab_env.post_or_update_comment("new content")

        assert len([c for c in calls if c["method"] == "GET"]) == 2
        assert len([c for c in calls if c["method"] == "POST"]) == 1

    def test_short_circuits_on_first_marker_hit(self, gitlab_env, fake_http):
        """A marker on page 1 must not trigger a page-2 fetch."""
        def responder(method, url, data, headers):
            if method == "GET":
                assert "page=1" in url
                return [{"id": 5, "body": scanner._COMMENT_MARKER}] * 100
            assert method == "PUT"
            return {}

        calls = fake_http(responder)
        gitlab_env.post_or_update_comment("new content")
        assert len([c for c in calls if c["method"] == "GET"]) == 1


class TestBitbucketCommentPagination:
    def test_follows_next_url_to_find_marker_on_page_two(self, bitbucket_env, fake_http):
        page_1_url = "https://api.bitbucket.org/2.0/repositories/acme/widgets/pullrequests/42/comments?pagelen=100"
        page_2_url = page_1_url + "&page=2"

        pages = {
            page_1_url: {
                "values": [{"id": 1, "content": {"raw": "unrelated"}}] * 100,
                "next": page_2_url,
            },
            page_2_url: {
                "values": [{"id": 999, "content": {"raw": f"{scanner._BB_COMMENT_MARKER}\nold"}}],
            },
        }

        def responder(method, url, data, headers):
            if method == "GET":
                return pages[url]
            assert method == "PUT"
            assert url.endswith("/999")
            return {}

        calls = fake_http(responder)
        bitbucket_env.post_or_update_comment("new content")

        assert len([c for c in calls if c["method"] == "GET"]) == 2
        assert len([c for c in calls if c["method"] == "PUT"]) == 1

    def test_no_next_url_and_no_marker_posts_a_new_comment(self, bitbucket_env, fake_http):
        def responder(method, url, data, headers):
            if method == "GET":
                return {"values": [{"id": 1, "content": {"raw": "unrelated"}}]}
            assert method == "POST"
            return {}

        calls = fake_http(responder)
        bitbucket_env.post_or_update_comment("new content")

        assert len([c for c in calls if c["method"] == "GET"]) == 1
        assert len([c for c in calls if c["method"] == "POST"]) == 1

    def test_dead_fallback_heading_text_no_longer_matches(self, bitbucket_env, fake_http):
        """Anchor for the QUAL-05 dead-matcher half: a comment containing the
        stale '## Zagware IaC Scanner' string (the pre-rebrand heading, never
        emitted by any current render path) but NOT the real marker must be
        treated as a stranger's comment, not the scanner's own -- proving the
        removed fallback clause is genuinely gone."""
        def responder(method, url, data, headers):
            if method == "GET":
                return {"values": [
                    {"id": 1, "content": {"raw": "## Zagware IaC Scanner\nsome old content"}},
                ]}
            assert method == "POST"  # must NOT match id 1 via the old fallback
            return {}

        calls = fake_http(responder)
        bitbucket_env.post_or_update_comment("new content")
        assert len([c for c in calls if c["method"] == "POST"]) == 1
        assert not any(c["method"] == "PUT" for c in calls)


class TestBitbucketMarkerSurvivesTruncation:
    def test_marker_is_the_first_line_for_non_collapsible_render(self):
        novel = [{
            "query_name": "rule", "severity": "HIGH", "category": "Networking",
            "platform": "Terraform", "description": "d", "cwe": None, "query_url": None,
            "files": [{"file_name": "main.tf", "line": 1, "similarity_id": "a"}],
        }]
        out = scanner.render_comment({"queries": []}, {"queries": novel}, novel,
                                      "main", "feature", collapsible=False)
        assert out.startswith(scanner._BB_COMMENT_MARKER)

    def test_marker_survives_truncation_of_an_oversized_comment(self):
        """The exact QUAL-05 bug: build a comment far larger than _MAX_COMMENT
        with the marker at the front (as render_comment now emits it), apply
        the same tail-truncation main() applies, and confirm the marker is
        still present. Before the fix the marker was appended AFTER this
        content and would have been the first thing sliced off."""
        novel = [{
            "query_name": "rule", "severity": "HIGH", "category": "Networking",
            "platform": "Terraform", "description": "d" * 200, "cwe": None, "query_url": None,
            "files": [{"file_name": f"file{i}.tf", "line": i,
                       "resource_name": "x", "similarity_id": str(i),
                       "issue_type": "Missing", "expected_value": "a", "actual_value": "b"}
                      for i in range(2000)],
        }]
        comment = scanner.render_comment({"queries": []}, {"queries": novel}, novel,
                                          "main", "feature", collapsible=False)
        assert len(comment) > scanner._MAX_COMMENT  # sanity: actually oversized

        note = "\n\n> ⚠️ _Comment truncated — run locally for full output._"
        truncated = comment[: scanner._MAX_COMMENT - len(note)] + note

        assert scanner._BB_COMMENT_MARKER in truncated
        assert truncated.startswith(scanner._BB_COMMENT_MARKER)
