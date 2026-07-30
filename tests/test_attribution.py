"""Tests for DOC-10: Syft is a first-class bundled engine (it generates the
SBOM Grype scans -- src/scanner.py's run_sca_scan calls syft before grype)
but was never credited or linked anywhere in the README; betterleaks was
linked with no vendor or license, the only non-Apache-2.0 component in the
image and therefore the one most in need of it.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestEngineTableCreditsSyft:
    def test_syft_is_linked_and_attributed(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "[Syft](https://github.com/anchore/syft)" in text
        assert "Anchore, Apache 2.0" in text or "(Anchore, Apache" in text

    def test_betterleaks_row_has_vendor_and_license(self):
        text = (REPO_ROOT / "README.md").read_text()
        row = next(
            l for l in text.splitlines()
            if "betterleaks/betterleaks" in l and l.strip().startswith("|")
        )
        assert "MIT" in row, f"betterleaks table row missing licence: {row!r}"

    def test_dependency_ecosystems_heading_credits_both_tools(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert re.search(
            r"## Supported dependency ecosystems.*Syft.*Grype",
            text,
        ), "the dependency-ecosystems heading must credit Syft alongside Grype"


class TestNoticeFile:
    def test_notice_file_exists(self):
        assert (REPO_ROOT / "NOTICE").exists()

    def test_notice_lists_all_four_bundled_components(self):
        text = (REPO_ROOT / "NOTICE").read_text()
        for name in ("KICS", "Syft", "Grype", "betterleaks"):
            assert name in text, f"NOTICE is missing {name}"

    def test_notice_gives_vendor_license_and_version_per_component(self):
        text = (REPO_ROOT / "NOTICE").read_text()
        assert "Checkmarx" in text and "Apache-2.0" in text
        assert "Anchore" in text
        assert "MIT" in text  # betterleaks -- the one non-Apache-2.0 component
        assert "2.1.20" in text  # KICS version
        assert "v1.50.0" in text  # Syft version
        assert "v0.112.0" in text  # Grype version
        assert "1.7.2" in text  # betterleaks version

    def test_notice_credits_the_kics_rules_commit(self):
        text = (REPO_ROOT / "NOTICE").read_text()
        assert "e1f23cad9640f55b963f22a116b04906b8c16ac6" in text

    def test_readme_links_to_notice(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "[NOTICE](NOTICE)" in text

    def test_notice_versions_match_dockerfile_pins(self):
        """The NOTICE file must not drift from the Dockerfile's own ARG
        defaults, which are the single source of truth (see SUP-08)."""
        dockerfile = (REPO_ROOT / "Dockerfile").read_text()
        notice = (REPO_ROOT / "NOTICE").read_text()

        def arg(name: str) -> str:
            m = re.search(rf"^ARG {name}=(.+)$", dockerfile, re.MULTILINE)
            assert m, f"ARG {name} not found in Dockerfile"
            return m.group(1).strip()

        assert arg("KICS_VERSION") in notice
        assert arg("SYFT_VERSION") in notice
        assert arg("GRYPE_VERSION") in notice
        assert arg("BETTERLEAKS_VERSION") in notice
        assert arg("KICS_RULES_COMMIT") in notice
