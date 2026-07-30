"""Tests for QUAL-03/QUAL-07/QUAL-14: SCA severity-threshold defaulting and
unmapped-severity rendering.

QUAL-03: ZAGWARE_MIN_SEVERITY=INFO/TRACE (a natural "report everything"
reading, and a value README.md documents as supported) collapsed the SCA
threshold to CRITICAL-only, because the rank lookup defaulted through
_SCA_SEVERITY_ORDER (5 tiers, no INFO/TRACE) instead of a map covering all six
IaC-validated tiers.

QUAL-07: Grype's own severity taxonomy includes "Unknown" (not just our
missing-key default) -- with a threshold set, every Unknown-severity CVE was
silently dropped (rank defaulted to 99, always above any threshold); with no
threshold set it was counted in the header total but never appeared in the
summary line or detail table, because both iterated the fixed
_SCA_SEVERITY_ORDER list rather than the finding's actual severity keys.

QUAL-14: The IaC renderer has the identical bug shape -- sev_counts is keyed
on whatever KICS emits (defaulting to "UNKNOWN" when a query has no severity
key), but both the summary line and the detail loop iterated the fixed
_SEVERITY_ORDER, so an out-of-taxonomy severity was counted in total_new but
never rendered.
"""
from __future__ import annotations

import json

import scanner


def _grype_output(severity: str) -> dict:
    return {
        "matches": [{
            "vulnerability": {
                "id": "CVE-2024-1000", "severity": severity,
                "risk": 1.0, "knownExploited": [], "epss": [], "cvss": [],
                "fix": {"versions": [], "state": "not-fixed"},
            },
            "artifact": {"name": "acme-lib", "version": "1.0.0", "type": "npm", "locations": []},
            "matchDetails": [],
        }],
    }


def _run_sca(mod, tmp_path, monkeypatch, grype_json):
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setattr(mod, "_run_syft", lambda path, out: True)

    def _fake_grype(sbom, out):
        mod.Path(out).write_text(json.dumps(grype_json))
        return True

    monkeypatch.setattr(mod, "_run_grype", _fake_grype)
    return mod.run_sca_scan(str(tmp_path), str(tmp_path), "base")


class TestScaSeverityThresholdDefaulting:
    """QUAL-03: INFO/TRACE thresholds must not collapse SCA to CRITICAL-only."""

    def test_info_threshold_keeps_all_real_severities(self, tmp_path, monkeypatch, reload_scanner):
        mod = reload_scanner(ZAGWARE_MIN_SEVERITY="INFO")
        for sev in ("Critical", "High", "Medium", "Low", "Negligible"):
            result = _run_sca(mod, tmp_path, monkeypatch, _grype_output(sev))
            assert len(result) == 1, f"{sev} was dropped under ZAGWARE_MIN_SEVERITY=INFO"

    def test_trace_threshold_keeps_all_real_severities(self, tmp_path, monkeypatch, reload_scanner):
        mod = reload_scanner(ZAGWARE_MIN_SEVERITY="TRACE")
        for sev in ("Critical", "High", "Medium", "Low", "Negligible"):
            result = _run_sca(mod, tmp_path, monkeypatch, _grype_output(sev))
            assert len(result) == 1, f"{sev} was dropped under ZAGWARE_MIN_SEVERITY=TRACE"

    def test_high_threshold_still_excludes_lower_severities(self, tmp_path, monkeypatch, reload_scanner):
        """Anchor: a real (non-defaulted) threshold must keep excluding as
        before -- the fix must not turn every threshold into a no-op."""
        mod = reload_scanner(ZAGWARE_MIN_SEVERITY="HIGH")
        assert len(_run_sca(mod, tmp_path, monkeypatch, _grype_output("Critical"))) == 1
        assert len(_run_sca(mod, tmp_path, monkeypatch, _grype_output("High"))) == 1
        assert len(_run_sca(mod, tmp_path, monkeypatch, _grype_output("Medium"))) == 0
        assert len(_run_sca(mod, tmp_path, monkeypatch, _grype_output("Low"))) == 0


class TestScaUnknownSeverityRendered:
    """QUAL-07: Grype's real "Unknown" severity must never be silently dropped."""

    def test_unknown_severity_never_excluded_by_any_threshold(self, tmp_path, monkeypatch, reload_scanner):
        for threshold in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TRACE"):
            mod = reload_scanner(ZAGWARE_MIN_SEVERITY=threshold)
            result = _run_sca(mod, tmp_path, monkeypatch, _grype_output("Unknown"))
            assert len(result) == 1, f"Unknown severity was dropped at threshold={threshold}"

    def test_unknown_severity_appears_in_rendered_comment(self, tmp_path, monkeypatch, reload_scanner):
        mod = reload_scanner(ZAGWARE_MIN_SEVERITY=None)
        result = _run_sca(mod, tmp_path, monkeypatch, _grype_output("Unknown"))
        assert result[0]["severity"] == "UNKNOWN"
        out = mod.render_sca_section(None, result, result)
        assert "1 new vulnerability" in out
        assert "UNKNOWN" in out
        assert "CVE-2024-1000" in out  # must be in the detail table, not just the header count


class TestIacUnmappedSeverityRendered:
    """QUAL-14: an IaC query with an out-of-taxonomy severity must render, not
    just be counted in the header total."""

    def _novel_query(self, severity: str) -> dict:
        return {
            "query_name": "custom-rule", "severity": severity, "category": "Custom",
            "platform": "Terraform", "description": "custom finding", "cwe": None,
            "query_url": None,
            "files": [{
                "file_name": "main.tf", "line": 3, "resource_name": "aws_s3_bucket.x",
                "similarity_id": "abc123", "issue_type": "MissingAttribute",
                "expected_value": "true", "actual_value": "false",
            }],
        }

    def test_out_of_taxonomy_severity_appears_in_summary_and_table(self):
        novel = [self._novel_query("SUPER_CRITICAL")]
        base = {"queries": []}
        pr = {"queries": novel}
        out = scanner.render_comment(base, pr, novel, "main", "feature")
        assert "**1 new finding(s)" in out
        assert "SUPER_CRITICAL" in out
        assert "custom-rule" in out
        assert "aws_s3_bucket.x" in out  # detail table row, not just the count

    def test_missing_severity_key_defaults_to_unknown_and_still_renders(self):
        q = self._novel_query("UNKNOWN")
        del q["severity"]
        novel = [q]
        base = {"queries": []}
        pr = {"queries": novel}
        out = scanner.render_comment(base, pr, novel, "main", "feature")
        assert "**1 new finding(s)" in out
        assert "custom-rule" in out
