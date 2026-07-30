"""Tests for DOC-02: every copy-pasteable snippet pinned `:latest` with zero
mention of the security tradeoff, and the tag/channel table recommending
`:stable`/`:secure` sat 600+ lines below the quick-start snippets a user
would have already copied.

Ground truth verified directly against the live registry (docker buildx
imagetools inspect, anonymous): `ghcr.io/zagware/zagware-scanner:latest`
exists; `:stable` returns "not found" -- promotion has never completed, so
recommending it as the default would break the documented quick start. The
fix surfaces the tag/channel table before Quick start, adds a callout under
every snippet, and is honest that `:stable`/`:secure` don't exist yet rather
than recommending a tag that doesn't resolve.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _slug(heading_text: str) -> str:
    cleaned = re.sub(r"[`*\[\]()]", "", heading_text)
    return re.sub(r"[^\w\- ]", "", cleaned).strip().lower().replace(" ", "-")


class TestImageTagsSectionPrecedesQuickStart:
    def test_section_exists_and_comes_before_quick_start(self):
        text = (REPO_ROOT / "README.md").read_text()
        tags_idx = text.index("## Image tags and release channels")
        quick_start_idx = text.index("## Quick start")
        assert tags_idx < quick_start_idx, (
            "the tag/channel table must be visible before a reader reaches "
            "any copy-pasteable snippet, not after"
        )

    def test_table_is_honest_that_stable_does_not_yet_exist(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[
            text.index("## Image tags and release channels"):
            text.index("## Quick start")
        ]
        assert "Not yet published" in section or "not yet published" in section.lower()


class TestQuickStartSnippetsHaveSecurityCallout:
    def test_every_platform_snippet_has_a_stable_pin_callout(self):
        text = (REPO_ROOT / "README.md").read_text()
        callout_count = text.count("Security-conscious consumers")
        # GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps
        assert callout_count == 4, (
            f"expected a security callout under each of the 4 quick-start "
            f"snippets, found {callout_count}"
        )


class TestReadmeAnchorsResolve:
    def test_every_internal_link_target_has_a_matching_heading(self):
        text = (REPO_ROOT / "README.md").read_text()
        headings = {
            _slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.+)$", text, re.MULTILINE)
        }
        links = set(re.findall(r"\]\(#([\w-]+)\)", text))
        missing = links - headings
        assert not missing, f"broken internal anchor(s): {missing}"


class TestExampleFilesDocumentTheChannelChoice:
    def test_each_example_file_notes_the_stable_recommendation(self):
        for f in [
            "examples/github-actions.yml",
            "examples/gitlab-ci.yml",
            "examples/bitbucket-pipelines.yml",
            "examples/azure-pipelines.yml",
        ]:
            text = (REPO_ROOT / f).read_text()
            assert "release channels" in text and ":stable" in text, (
                f"{f} does not document the :stable recommendation"
            )
