"""Tests for DOC-01/DOC-11/DOC-21: the shipped LICENSE must be the verbatim,
unmodified Apache-2.0 text (not a splice with MIT permission-grant language
and an "all rights reserved" clause), the OCI image-license labels must
reflect the bundled MIT betterleaks binary, and the copyright years across
LICENSE/README must agree.

Before the fix, LICENSE section 4's final paragraph replaced the canonical
"may provide additional or different license terms... provided Your use...
otherwise complies with the conditions stated in this License" text with MIT
grant language plus "all rights reserved", several definitions were
shortened, and the Appendix boilerplate was missing entirely -- Syft/Grype
(bundled in this very image) and any consumer's licence-compliance tooling
would read the SPDX label Apache-2.0 and then find an unrecognised custom
licence.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# The load-bearing canonical clause LICENSE previously replaced with MIT-style
# grant + "all rights reserved" language. If this substring is missing, the
# file has drifted from Apache-2.0 again.
CANONICAL_SECTION_4_TAIL = (
    "You may add Your own copyright statement to Your modifications and\n"
    "      may provide additional or different license terms and conditions\n"
    "      for use, reproduction, or distribution of Your modifications, or\n"
    "      for any such Derivative Works as a whole, provided Your use,\n"
    "      reproduction, and distribution of the Work otherwise complies with\n"
    "      the conditions stated in this License."
)


class TestLicenseIsVerbatimApache2:
    def test_contains_the_canonical_section_4_clause(self):
        text = (REPO_ROOT / "LICENSE").read_text()
        assert CANONICAL_SECTION_4_TAIL in text, (
            "LICENSE section 4 does not match canonical Apache-2.0 -- "
            "the MIT-style splice may have regressed"
        )

    def test_does_not_contain_all_rights_reserved(self):
        text = (REPO_ROOT / "LICENSE").read_text()
        assert "all rights reserved" not in text.lower()

    def test_does_not_contain_mit_permission_grant_language(self):
        """The exact phrase the splice introduced -- distinct from any
        legitimate Apache-2.0 text, which never mentions "sell copies"."""
        text = (REPO_ROOT / "LICENSE").read_text()
        assert "sell copies of the Work" not in text

    def test_contains_the_appendix(self):
        text = (REPO_ROOT / "LICENSE").read_text()
        assert "APPENDIX: How to apply the Apache License to your work." in text

    def test_definitions_are_not_truncated(self):
        """The "Work" and "Contribution" definitions were shortened in the
        splice (dropped "whether in Source or Object form" and "the original
        version of the Work..." respectively)."""
        text = (REPO_ROOT / "LICENSE").read_text()
        assert "whether in Source or\n      Object form, made available under" in text
        assert "the original version of the Work and any modifications or additions" in text

    def test_full_text_length_matches_canonical(self):
        """A cheap end-to-end sanity check: the canonical Apache-2.0 text is
        a known, fixed length. A truncated or spliced document will differ
        significantly; this doesn't require network access."""
        text = (REPO_ROOT / "LICENSE").read_text()
        # Canonical apache.org/licenses/LICENSE-2.0.txt body (excluding the
        # appendix's bracketed placeholders, now filled in) is ~10.8-11.4KB.
        assert 10_000 < len(text) < 12_000, (
            f"LICENSE is {len(text)} bytes -- outside the expected range for "
            f"the full verbatim Apache-2.0 text with appendix"
        )


class TestCopyrightYearConsistency:
    def test_license_and_readme_copyright_years_match(self):
        license_text = (REPO_ROOT / "LICENSE").read_text()
        readme_text = (REPO_ROOT / "README.md").read_text()

        license_years = set(re.findall(r"Copyright (\d{4}) Zagware Ltd\.", license_text))
        readme_years = set(re.findall(r"Copyright (\d{4}) Zagware Ltd\.", readme_text))

        assert license_years, "no copyright year found in LICENSE"
        assert readme_years, "no copyright year found in README.md"
        assert license_years == readme_years, (
            f"LICENSE copyright year(s) {license_years} != README.md {readme_years}"
        )


class TestImageLicenseLabelReflectsBundledMIT:
    """DOC-11: the image bundles betterleaks (MIT) alongside Apache-2.0
    components -- a bare "Apache-2.0" SPDX label is false for the artifact."""

    def test_dockerfile_label(self):
        text = (REPO_ROOT / "Dockerfile").read_text()
        match = re.search(r'LABEL org\.opencontainers\.image\.licenses="([^"]+)"', text)
        assert match, "no org.opencontainers.image.licenses LABEL found in Dockerfile"
        assert match.group(1) == "Apache-2.0 AND MIT"

    def test_publish_yml_label(self):
        doc = yaml.safe_load((REPO_ROOT / ".github/workflows/publish.yml").read_text())
        steps = doc["jobs"]["build-sign-push"]["steps"]
        meta_step = next(s for s in steps if s.get("name") == "Docker metadata")
        labels = meta_step["with"]["labels"]
        license_lines = [l.strip() for l in labels.splitlines()
                          if l.strip().startswith("org.opencontainers.image.licenses=")]
        assert license_lines, "no org.opencontainers.image.licenses label in Docker metadata step"
        assert license_lines[0] == "org.opencontainers.image.licenses=Apache-2.0 AND MIT"
