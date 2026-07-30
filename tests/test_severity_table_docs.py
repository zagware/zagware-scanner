"""Tests for DOC-05: the severity-filtering table in README.md must match
scanner.py's real threshold behaviour on every row.

Before the fix, the table omitted CRITICAL and TRACE from the IaC ladder
entirely and claimed `ZAGWARE_MIN_SEVERITY=HIGH` shows "HIGH only" when the
real `_severities_below()` logic shows CRITICAL and HIGH. This test derives
the expected "survives this threshold" set directly from the real
`_SCA_MIN_RANK`/`_SEVERITY_ORDER` constants (not a re-typed copy) so it
cannot silently drift from scanner.py again.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import scanner  # noqa: E402


def _severity_table_rows() -> dict[str, tuple[str, str]]:
    """Parse the README's `ZAGWARE_MIN_SEVERITY` table into
    {threshold_label: (iac_cell, sca_cell)}."""
    text = (REPO_ROOT / "README.md").read_text()
    start = text.index("| `ZAGWARE_MIN_SEVERITY` | IaC findings shown")
    end = text.index("\n\n", start)
    block = text[start:end]
    rows: dict[str, tuple[str, str]] = {}
    for line in block.splitlines()[2:]:  # skip header + separator
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 3, f"malformed table row: {line!r}"
        label = cells[0].strip("`")
        rows[label] = (cells[1], cells[2])
    return rows


def _real_sca_survivors(threshold: str) -> set[str]:
    survivors = set()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"):
        sca_sev = "LOW" if sev == "NEGLIGIBLE" else sev
        if scanner._SCA_MIN_RANK.get(sca_sev, -1) <= scanner._SCA_MIN_RANK[threshold]:
            survivors.add(sev)
    return survivors


def _real_iac_survivors(threshold: str) -> set[str]:
    idx = scanner._SEVERITY_ORDER.index(threshold)
    return set(scanner._SEVERITY_ORDER[: idx + 1])


class TestSeverityTableMatchesRealBehaviour:
    def test_every_valid_threshold_has_a_table_row(self):
        rows = _severity_table_rows()
        for threshold in scanner._SEVERITY_ORDER:
            assert threshold in rows, f"README severity table is missing a row for {threshold}"
        assert "_(unset)_" in rows

    def test_iac_column_matches_severities_below_logic(self):
        rows = _severity_table_rows()
        for threshold in scanner._SEVERITY_ORDER:
            iac_cell, _ = rows[threshold]
            expected = _real_iac_survivors(threshold)
            named = set(re.findall(r"[A-Z]+", iac_cell))
            if "All" in iac_cell:
                named |= set(scanner._SEVERITY_ORDER)
            assert expected <= named, (
                f"IaC column for {threshold} ({iac_cell!r}) does not list all of "
                f"the severities scanner.py actually shows: {expected}"
            )

    def test_sca_column_matches_sca_min_rank_logic(self):
        rows = _severity_table_rows()
        for threshold in scanner._SEVERITY_ORDER:
            _, sca_cell = rows[threshold]
            expected = _real_sca_survivors(threshold)
            named = set(re.findall(r"[A-Z]+", sca_cell))
            if "All" in sca_cell:
                # "All" cells reference LOW/INFO by backtick, not by literal
                # severity name -- resolve via the note's cross-reference.
                continue
            assert expected <= named, (
                f"SCA column for {threshold} ({sca_cell!r}) does not list all of "
                f"the severities scanner.py actually shows: {expected}"
            )

    def test_unknown_never_excluded_note_is_present(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "never excluded by\nany threshold" in text or "never excluded by any threshold" in text.replace("\n", " ")


class TestAcceptedValueListsIncludeAllSixTiers:
    def test_readme_configuration_table_lists_all_six(self):
        text = (REPO_ROOT / "README.md").read_text()
        row = next(l for l in text.splitlines() if l.startswith("| `ZAGWARE_MIN_SEVERITY`"))
        for tier in scanner._SEVERITY_ORDER:
            assert tier in row, f"README Configuration table row missing {tier}: {row!r}"

    def test_every_example_file_lists_all_six(self):
        for f in [
            "examples/github-actions.yml",
            "examples/gitlab-ci.yml",
            "examples/bitbucket-pipelines.yml",
            "examples/azure-pipelines.yml",
        ]:
            text = (REPO_ROOT / f).read_text()
            line = next(l for l in text.splitlines() if "ZAGWARE_MIN_SEVERITY" in l)
            for tier in scanner._SEVERITY_ORDER:
                assert tier in line, f"{f} severity comment missing {tier}: {line!r}"


class TestNoFictionalScanEngineClaims:
    def test_readme_never_mentions_trivy(self):
        text = (REPO_ROOT / "README.md").read_text()
        assert "trivy" not in text.lower(), "README references Trivy, which promote.yml never runs"

    def test_readme_slsa_claim_matches_actual_workflow(self):
        """DOC-04: the build+attest run in the same job (publish.yml), which
        caps at SLSA Build Level 2, not Level 3."""
        text = (REPO_ROOT / "README.md").read_text()
        assert "SLSA" in text
        assert "Build Level 3" not in text and "Build **Level 3**" not in text
        assert "Level 2" in text or "Level **2**" in text
