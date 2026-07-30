"""Tests for DOC-07/DOC-08/DOC-09/DOC-12/DOC-23: documentation accuracy and
README/examples parity.

DOC-07: README/.zagware/suppressions.yaml pointed users at summary.json for
similarity_id; that file holds only metadata + timings, no per-finding data.

DOC-08: the README Azure DevOps snippet hardcoded ZAGWARE_PLATFORM_URL and
omitted the volume mount + PublishBuildArtifacts task the real example uses
-- copy-pasting it produced no scan artifacts at all.

DOC-09: README linked examples/gitlab-ci.yml as the "full policy setup
guide" for GitLab's Pipeline Execution Policy feature; that file is the
single-project job scanner, containing zero policy content.

DOC-12: all four example files' artifact lists predated the secrets feature
and omitted secrets-base/head/new.json.

DOC-23: README quick-start snippets and their examples/*.yml counterparts
disagreed (missing artifact-upload machinery in three of four platforms),
so following both in sequence produced different behaviour.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSuppressionIdInstructionsPointAtRealFiles:
    def test_summary_json_no_longer_cited_as_an_id_source(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### The manual way"):text.index("### How suppressions work")]
        assert "summary.json" not in section

    def test_real_artifact_files_are_cited_with_jq_paths(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### The manual way"):text.index("### How suppressions work")]
        assert "iac-head.json" in section and "queries[].files[].similarity_id" in section
        assert "sca-new.json" in section
        assert "secrets-new.json" in section

    def test_suppress_findings_pr_comment_section_is_the_recommended_first_step(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### The manual way"):text.index("### How suppressions work")]
        assert "📋 Suppress findings" in section


class TestScanArtifactsSectionExists:
    def test_section_lists_all_ten_real_files(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "## Scan artifacts" in text
        section = text[text.index("## Scan artifacts"):text.index("## How findings are fingerprinted")]
        for f in (
            "iac-base.json", "iac-head.json",
            "sca-base.json", "sca-head.json", "sca-new.json",
            "secrets-base.json", "secrets-head.json", "secrets-new.json",
            "pr-comment.md", "summary.json",
        ):
            assert f"`{f}`" in section, f"Scan artifacts section missing {f}"


class TestExampleArtifactListsIncludeSecrets:
    def test_every_example_file_mentions_secrets_artifacts(self):
        for f in [
            "examples/github-actions.yml",
            "examples/gitlab-ci.yml",
            "examples/bitbucket-pipelines.yml",
            "examples/azure-pipelines.yml",
        ]:
            text = (REPO_ROOT / f).read_text()
            assert "secrets-" in text, f"{f} artifact comment omits secrets-*.json"


class TestReadmeExampleParityForArtifactUpload:
    """DOC-08/DOC-23: every README quick-start snippet must actually produce
    a downloadable artifact -- the same guarantee the example files give."""

    def test_github_actions_snippet_uploads_artifacts(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### GitHub Actions"):text.index("### GitLab CI")]
        assert "actions/upload-artifact" in section

    def test_gitlab_snippet_has_artifacts_block(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### GitLab CI"):text.index("### Bitbucket Pipelines")]
        assert "artifacts:" in section
        assert "zagware-scan-results/" in section

    def test_bitbucket_snippet_has_artifacts_block(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### Bitbucket Pipelines"):text.index("### Azure DevOps")]
        assert "artifacts:" in section

    def test_azure_snippet_has_volume_mount_and_publish_task(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### Azure DevOps"):text.index("## PR comment")]
        assert "-v " in section and "zagware-scan-results" in section
        assert "PublishBuildArtifacts" in section

    def test_azure_snippet_does_not_hardcode_platform_url(self):
        """DOC-08's exact defect: README hardcoded the URL while the example
        used the pipeline variable, and the base snippet always sent it even
        when unconfigured."""
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### Azure DevOps"):text.index("## PR comment")]
        base_snippet = section[:section.index("```", section.index("```yaml") + 6)]
        assert "ZAGWARE_PLATFORM_URL=https://app.zagware.io" not in base_snippet

    def test_azure_snippet_documents_unexpanded_macro_behaviour(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[text.index("### Azure DevOps"):text.index("## PR comment")]
        assert "unexpanded" in section.lower() or "literal string" in section.lower()


class TestAzureExampleGuardsOptionalVars:
    def test_example_base_step_omits_platform_vars(self):
        text = (REPO_ROOT / "examples/azure-pipelines.yml").read_text()
        # The docker run script body (not the header comments) must not send
        # the platform vars unconditionally.
        script_start = text.index("docker run --rm")
        script_end = text.index("displayName")
        script_body = text[script_start:script_end]
        assert "ZAGWARE_PLATFORM_URL" not in script_body
        assert "ZAGWARE_PLATFORM_TOKEN" not in script_body

    def test_example_documents_how_to_add_platform_vars(self):
        text = (REPO_ROOT / "examples/azure-pipelines.yml").read_text()
        assert "ZAGWARE_PLATFORM_URL=$(ZAGWARE_PLATFORM_URL)" in text
        assert "unexpanded" in text.lower()


class TestGitlabPolicyLinkPointsAtRealPolicyContent:
    def test_readme_no_longer_links_gitlab_ci_yml_as_policy_guide(self):
        text = (REPO_ROOT / "README.md").read_text()
        section = text[
            text.index("Group-wide enforcement via Pipeline Execution Policy"):
            text.index("### Bitbucket Pipelines")
        ]
        assert "](examples/gitlab-ci.yml)" not in section

    def test_readme_links_the_real_policy_file(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "examples/gitlab-pipeline-execution-policy.yml" in text

    def test_policy_file_exists_and_has_real_pipeline_execution_policy_content(self):
        path = REPO_ROOT / "examples/gitlab-pipeline-execution-policy.yml"
        assert path.exists()
        doc = yaml.safe_load(path.read_text())
        assert "pipeline_execution_policy" in doc
        policy = doc["pipeline_execution_policy"][0]
        for key in ("name", "description", "enabled", "content"):
            assert key in policy, f"policy missing required field {key}"
        assert "include" in policy["content"]
        include = policy["content"]["include"][0]
        assert "project" in include and "file" in include


class TestNoBrokenRelativeLinks:
    def test_every_relative_link_target_exists(self):
        text = (REPO_ROOT / "README.md").read_text()
        links = re.findall(r"\]\(((?!http|#)[^)]+)\)", text)
        missing = [l for l in set(links) if not (REPO_ROOT / l).exists()]
        assert not missing, f"README links to non-existent file(s): {missing}"
