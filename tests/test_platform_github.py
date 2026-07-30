"""Integration tests for the GitHub platform adapter: URL construction,
pagination, and response parsing through the real _http() seam (mocked, not
network) rather than testing parse_suppression_commands in isolation.

Covers the read_pr_comments() half of SEC-01: this is the function whose
docstring now promises an author_association field is captured — a unit
test on parse_suppression_commands alone wouldn't catch a regression here
if the field stopped being read from the real API response shape.
"""
from __future__ import annotations

import pytest

import scanner


@pytest.fixture
def github_env(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test_token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
    monkeypatch.setenv("PR_NUMBER", "42")
    return scanner.GitHub()


class TestReadPrComments:
    def test_captures_author_association_per_comment(self, github_env, fake_http):
        def responder(method, url, data, headers):
            assert method == "GET"
            return [
                {"body": "/zagware suppress abc123 fine", "user": {"login": "octocat"},
                 "created_at": "2026-01-01T00:00:00Z", "author_association": "OWNER"},
                {"body": "lgtm", "user": {"login": "rando"},
                 "created_at": "2026-01-02T00:00:00Z", "author_association": "NONE"},
            ]

        calls = fake_http(responder)
        comments = github_env.read_pr_comments()

        assert len(comments) == 2
        assert comments[0]["author_association"] == "OWNER"
        assert comments[1]["author_association"] == "NONE"
        assert calls[0]["url"] == (
            "https://api.github.com/repos/acme/widgets/issues/42/comments?per_page=100&page=1"
        )
        assert calls[0]["headers"]["Authorization"] == "Bearer ghs_test_token"

    def test_missing_author_association_defaults_to_empty_string(self, github_env, fake_http):
        """A GitHub Enterprise response shape (or API change) that omits the
        field must not crash the adapter — and must feed
        _filter_authorized_comments' default-deny path, not bypass it."""
        fake_http(lambda m, u, d, h: [
            {"body": "/zagware suppress abc123 x", "user": {"login": "a"}, "created_at": ""},
        ])
        comments = github_env.read_pr_comments()
        assert comments[0]["author_association"] == ""
        assert scanner._filter_authorized_comments(comments) == []

    def test_paginates_across_multiple_pages(self, github_env, fake_http):
        page_1 = [{"body": "c1", "user": {"login": "a"}, "created_at": "", "author_association": "OWNER"}] * 100
        page_2 = [{"body": "c2", "user": {"login": "b"}, "created_at": "", "author_association": "OWNER"}] * 3

        pages = {1: page_1, 2: page_2}

        def responder(method, url, data, headers):
            page = int(url.rsplit("page=", 1)[1])
            return pages[page]

        fake_http(responder)
        comments = github_env.read_pr_comments()
        assert len(comments) == 103  # full page 1 (100) + partial page 2 (3) -> stop

    def test_no_pr_number_returns_empty_without_calling_api(self, monkeypatch, fake_http):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_TOKEN", "t")
        monkeypatch.setenv("GITHUB_REPOSITORY", "acme/widgets")
        monkeypatch.delenv("PR_NUMBER", raising=False)
        gh = scanner.GitHub()

        calls = fake_http(lambda *a: pytest.fail("must not call _http when there is no PR"))
        assert gh.read_pr_comments() == []
        assert calls == []
