"""Tests for DOC-13/DOC-14/DOC-15/DOC-16/DOC-17/DOC-18/DOC-19/DOC-20/DOC-26:
the remaining README and examples/ documentation defects from the 2026-07-30 audit.

DOC-13: BITBUCKET_GIT_USER is read by the scanner and defaults to
`{workspace}-admin` -- a convention, not a guarantee. When it does not hold the
very first clone fails with a git auth error, and the escape hatch was
documented nowhere.

DOC-14: the README told org owners to pipe an unpinned fetch of a mutable
`main` ref straight into a shell, in a project whose supply-chain section
argues for SHA pinning.

DOC-15: ZAGWARE_FAIL_ON_NEW also gates on new secrets (they are counted in the
same new-findings total and are never filtered by ZAGWARE_MIN_SEVERITY), and
ZAGWARE_SECRETS_FAIL_ON_PUBLIC defaults to enabled -- so a public-repo user got
a merge-blocking failure on their first new secret with zero configuration,
while none of the four examples mentioned either secrets variable.

DOC-16: the pinning example pinned 2.0.5 and the tag table showed 2.2.0; the
current release is far ahead of both.

DOC-17: the Docker badge linked to /pkgs/container/..., which 404s.

DOC-18: `cosign download attestation` cannot retrieve this image's SBOM -- it is
a BuildKit OCI referrer attestation in the image index, not a cosign `.att`
sidecar tag.

DOC-19: the FAQ permissions table gave GitHub's requirement as only
`pull-requests: write`, contradicting the quick start and the suppressions
section (which need `contents: write`, the issue_comment trigger, and
PR_NUMBER).

DOC-20: the supported-ecosystems table advertised apk/dpkg/rpm coverage that a
`syft scan dir:` over a source working tree can never produce.

DOC-26: an ~800-line README with no table of contents.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = (REPO_ROOT / "README.md").read_text()

EXAMPLES = ("github-actions", "gitlab-ci", "bitbucket-pipelines", "azure-pipelines")


def _section(name: str, text: str = README) -> str:
    """Body of the `## <name>` section, up to the next heading of the same or
    higher level. Fence-aware: `#` lines inside ```code blocks``` are content,
    not headings."""
    lines = text.splitlines()
    start = level = None
    in_fence = False
    body: list[str] = []
    for line in lines:
        if line.startswith("```"):
            in_fence = not in_fence
            if start is not None:
                body.append(line)
            continue
        heading = None if in_fence else re.match(r"^(#{2,6}) (.*)$", line)
        if start is None:
            if heading and heading.group(2).strip() == name:
                start, level = line, len(heading.group(1))
            continue
        if heading and len(heading.group(1)) <= level:
            break
        body.append(line)
    assert start is not None, f"heading {name!r} not found in README"
    return "\n".join(body)


def _outside_fences(text: str = README):
    """Yield (lineno, line) for every line not inside a ``` fenced block."""
    in_fence = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield i, line


def _slug(heading: str) -> str:
    """GitHub's heading -> anchor slug."""
    t = re.sub(r"^#+\s+", "", heading).strip()
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)  # inline links -> their text
    t = re.sub(r"[`*_]", "", t)
    t = re.sub(r"[^\w\s-]", "", t.lower())
    return t.strip().replace(" ", "-")


class TestBitbucketGitUserIsDocumented:
    """DOC-13"""

    def test_readme_bitbucket_setup_documents_the_override(self):
        section = _section("Bitbucket Pipelines")
        assert "BITBUCKET_GIT_USER" in section
        assert "<workspace>-admin" in section
        assert "authentication error" in section

    def test_configuration_platform_inputs_carries_a_bitbucket_git_user_row(self):
        section = _section("Platform inputs")
        row = [l for l in section.splitlines() if l.startswith("| `BITBUCKET_GIT_USER`")]
        assert row, "no BITBUCKET_GIT_USER row in the Configuration platform-inputs tables"
        assert "<workspace>-admin" in row[0]

    def test_faq_permissions_table_mentions_it_for_bitbucket(self):
        section = _section("Frequently asked questions")
        bitbucket = [l for l in section.splitlines() if l.startswith("| Bitbucket |")]
        assert bitbucket and "BITBUCKET_GIT_USER" in bitbucket[0]

    def test_bitbucket_example_header_documents_it(self):
        text = (REPO_ROOT / "examples/bitbucket-pipelines.yml").read_text()
        header = text[: text.index("pipelines:")]
        assert "BITBUCKET_GIT_USER" in header
        assert "<workspace>-admin" in header


class TestOrgRulesetSetupIsNotCurlPipeBash:
    """DOC-14"""

    def test_no_curl_piped_into_a_shell_anywhere_in_the_readme(self):
        offenders = [
            line for line in README.splitlines()
            if "curl" in line and re.search(r"\|\s*(ba)?sh\b", line)
        ]
        assert not offenders, f"curl | bash still present: {offenders}"

    def test_the_mutable_main_ref_is_no_longer_fetched(self):
        assert "security-workflows/main/rulesets/setup-org-level.sh" not in README

    def test_download_step_uses_a_pinned_ref_placeholder(self):
        assert (
            "https://raw.githubusercontent.com/zagware/security-workflows/"
            "<commit-sha>/rulesets/setup-org-level.sh" in README
        )

    def test_reader_is_told_where_to_get_the_current_sha(self):
        assert "gh api repos/zagware/security-workflows/commits/main --jq .sha" in README

    def test_download_and_run_are_separate_steps_with_a_review_in_between(self):
        section = _section("Organization-wide enforcement via GitHub rulesets (GitHub Team+)")
        download = section.index("curl -fsSLO")
        review = section.index("less setup-org-level.sh")
        run = section.index("bash setup-org-level.sh <your-org>")
        assert download < review < run
        assert "Review it before running" in section

    def test_script_is_flagged_as_living_in_a_separate_repository(self):
        section = _section("Organization-wide enforcement via GitHub rulesets (GitHub Team+)")
        assert "not part of this repository" in section
        assert "zagware/security-workflows" in section
        # The known SRC_REPO defect is in that other repo; say so rather than
        # silently shipping a broken one-liner.
        assert "SRC_REPO" in section


class TestFailOnNewCoversSecrets:
    """DOC-15"""

    def test_severity_section_no_longer_claims_iac_and_sca_only(self):
        section = _section("Severity filtering")
        assert "This applies to both IaC and SCA findings" not in section
        assert "Secrets" in section
        assert "regardless" in section and "ZAGWARE_MIN_SEVERITY" in section

    def test_configuration_row_says_secrets_bypass_min_severity(self):
        row = [
            l for l in _section("Scan behaviour").splitlines()
            if l.startswith("| `ZAGWARE_FAIL_ON_NEW`")
        ]
        assert row, "ZAGWARE_FAIL_ON_NEW row missing"
        (row,) = row
        assert "Secrets" in row
        assert re.search(r"secrets? always count|always count", row, re.I)
        # the old text scoped the whole flag to ZAGWARE_MIN_SEVERITY
        assert row.count("Exit 1 when new findings are found at or above") == 0

    def test_github_quick_start_warns_about_the_public_repo_default(self):
        section = _section("GitHub Actions")
        assert "ZAGWARE_SECRETS_FAIL_ON_PUBLIC" in section
        assert "public" in section
        assert "defaults to `true`" in section

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_example_lists_both_secrets_variables(self, name):
        text = (REPO_ROOT / f"examples/{name}.yml").read_text()
        assert "ZAGWARE_SECRETS_ENABLED" in text
        assert "ZAGWARE_SECRETS_FAIL_ON_PUBLIC" in text

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_example_calls_out_the_true_default(self, name):
        text = (REPO_ROOT / f"examples/{name}.yml").read_text()
        block = text[text.index("ZAGWARE_SECRETS_FAIL_ON_PUBLIC"):]
        block = block[: block.index("\n#\n")]
        assert 'DEFAULT "true"' in block
        assert "PUBLIC" in block

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_secrets_variables_are_inside_the_leading_comment_block(self, name):
        """They must be in the header users actually read, not buried in YAML."""
        text = (REPO_ROOT / f"examples/{name}.yml").read_text()
        header_lines = []
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                header_lines.append(line)
            else:
                break
        header = "\n".join(header_lines)
        assert "ZAGWARE_SECRETS_ENABLED" in header
        assert "ZAGWARE_SECRETS_FAIL_ON_PUBLIC" in header


class TestVersionLiteralsAreNotStale:
    """DOC-16"""

    @pytest.mark.parametrize("stale", ["2.0.5", "2.2.0"])
    def test_stale_version_literals_are_gone(self, stale):
        assert f"zagware-scanner:{stale}" not in README
        assert f"`:{stale}`" not in README

    def test_pinning_example_uses_a_placeholder_and_points_at_releases(self):
        section = _section("Pinning to a specific version")
        assert "uses: docker://ghcr.io/zagware/zagware-scanner:<version>" in section
        assert "image: ghcr.io/zagware/zagware-scanner:<version>" in section
        assert "https://github.com/zagware/zagware-scanner/releases" in section
        assert not re.search(r"zagware-scanner:\d+\.\d+\.\d+", section)

    def test_tag_table_row_carries_no_hardcoded_example_version(self):
        section = _section("Image tags and release channels")
        (row,) = [l for l in section.splitlines() if l.startswith("| `:<version>`")]
        assert not re.search(r"\d+\.\d+\.\d+", row)
        assert "releases" in row


class TestDockerBadgeTarget:
    """DOC-17"""

    def test_badge_points_at_the_org_packages_url(self):
        badge = [l for l in README.splitlines() if l.startswith("[![Docker]")]
        assert len(badge) == 1
        (badge,) = badge
        assert "https://github.com/zagware/zagware-scanner/pkgs/container/" not in badge
        assert (
            "https://github.com/orgs/zagware/packages/container/package/zagware-scanner"
            in badge
        )


class TestSbomRetrievalCommand:
    """DOC-18"""

    def test_the_cosign_sidecar_retrieval_is_no_longer_offered(self):
        commands = [l.strip() for l in _section("Verify the image you're running").splitlines()]
        assert not [c for c in commands if c.startswith("cosign download attestation")]
        assert ".predicate.packages[].name" not in README

    def test_buildkit_native_retrieval_is_used(self):
        section = _section("Verify the image you're running")
        assert "docker buildx imagetools inspect ghcr.io/zagware/zagware-scanner:latest" in section
        assert "--format '{{ json .SBOM.SPDX }}' | jq -r '.packages[].name'" in section

    def test_the_two_correct_commands_are_left_intact(self):
        section = _section("Verify the image you're running")
        assert "cosign verify ghcr.io/zagware/zagware-scanner:latest" in section
        assert "gh attestation verify oci://ghcr.io/zagware/zagware-scanner:latest" in section


class TestFaqPermissionsTableAgreesWithTheRestOfTheDocument:
    """DOC-19"""

    def test_github_row_lists_everything_the_quick_start_grants(self):
        section = _section("Frequently asked questions")
        (row,) = [l for l in section.splitlines() if l.startswith("| GitHub Actions |")]
        assert row != "| GitHub Actions | `permissions: pull-requests: write` (GITHUB_TOKEN is automatic) |"
        assert "pull-requests: write" in row
        assert "contents: write" in row
        assert "issue_comment" in row
        assert "PR_NUMBER" in row
        assert "GITHUB_TOKEN" in row

    def test_quick_start_and_faq_no_longer_disagree(self):
        quick_start = _section("GitHub Actions")
        assert "contents: write" in quick_start
        assert "issue_comment" in quick_start
        faq_row = [
            l for l in _section("Frequently asked questions").splitlines()
            if l.startswith("| GitHub Actions |")
        ][0]
        for required in ("contents: write", "issue_comment"):
            assert required in faq_row, f"{required!r} in quick start but not the FAQ table"


class TestOsPackageCoverageIsNotAdvertised:
    """DOC-20"""

    ECOSYSTEMS = "Supported dependency ecosystems ([Syft][] + [Grype][])"

    def test_os_packages_row_is_gone_from_the_ecosystems_table(self):
        rows = [l for l in _section(self.ECOSYSTEMS).splitlines() if l.startswith("|")]
        assert not [r for r in rows if r.startswith("| OS packages")]
        assert not [r for r in rows if "dpkg" in r or "rpm" in r]

    def test_the_limitation_is_stated_explicitly(self):
        section = _section(self.ECOSYSTEMS)
        assert "OS packages inside container images are not scanned" in section
        assert "dir:" in section
        assert "grype <image>" in section


class TestTableOfContents:
    """DOC-26"""

    def test_a_toc_exists_between_the_intro_and_the_first_section(self):
        toc = README.index("**Contents**")
        assert toc < README.index("\n## How it works")
        assert toc > README.index("**Catch security issues before they reach your main branch.**")

    def test_toc_covers_every_top_level_section(self):
        headings = [line for _, line in _outside_fences() if line.startswith("## ")]
        expected = {_slug(h) for h in headings}
        toc_block = README[README.index("**Contents**"):README.index("\n## How it works")]
        listed = set(re.findall(r"^- \[[^\]]+\]\(#([^)]+)\)$", toc_block, re.M))
        assert listed == expected, f"missing: {expected - listed}; extra: {listed - expected}"

    def test_every_internal_link_in_the_readme_resolves_to_a_real_heading(self):
        anchors = {
            _slug(line)
            for _, line in _outside_fences()
            if re.match(r"^#{1,6} ", line)
        }
        links = set(re.findall(r"\]\(#([^)]+)\)", README))
        assert not (links - anchors), f"dangling anchors: {sorted(links - anchors)}"

    def test_code_fences_stay_balanced(self):
        assert sum(1 for l in README.splitlines() if l.startswith("```")) % 2 == 0
