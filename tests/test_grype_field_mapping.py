"""Tests for QUAL-06: kev_listed and risk_score must read the field names
Grype actually emits.

Ground truth verified directly against the exact bundled Grype version
(v0.112.0) source: grype/presenter/models/vulnerability_metadata.go declares
KnownExploited []KnownExploited with json tag "knownExploited,omitempty" on
VulnerabilityMetadata (embedded in Vulnerability), and vulnerability.go
declares Risk float64 with json tag "risk" directly on Vulnerability. There is
no "kev" key and no "riskScore" key anywhere in the schema — those always
read as None/False, which is the exact bug this test locks in the fix for.
"""
from __future__ import annotations

import json

import scanner


def _grype_output(vuln_overrides: dict) -> dict:
    """A match shaped like a real (bundled-version) grype -o json entry,
    with the fields under test overridable."""
    match = {
        "vulnerability": {
            "id": "CVE-2024-9999",
            "severity": "Critical",
            "risk": 8.5,
            "knownExploited": [{"cve": "CVE-2024-9999", "vendorProject": "acme"}],
            "epss": [{"cve": "CVE-2024-9999", "epss": 0.42}],
            "cvss": [],
            "fix": {"versions": [], "state": "not-fixed"},
        },
        "artifact": {"name": "acme-lib", "version": "1.0.0", "type": "npm", "locations": []},
        "matchDetails": [],
    }
    match["vulnerability"].update(vuln_overrides)
    return {"matches": [match]}


class TestKevAndRiskFieldMapping:
    def _run(self, tmp_path, grype_json, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}")
        monkeypatch.setattr(scanner, "_run_syft", lambda path, out: True)

        def _fake_grype(sbom, out):
            scanner.Path(out).write_text(json.dumps(grype_json))
            return True
        monkeypatch.setattr(scanner, "_run_grype", _fake_grype)
        return scanner.run_sca_scan(str(tmp_path), str(tmp_path), "base")

    def test_kev_listed_true_when_known_exploited_present(self, tmp_path, monkeypatch):
        result = self._run(tmp_path, _grype_output({}), monkeypatch)
        assert len(result) == 1
        assert result[0]["kev_listed"] is True

    def test_kev_listed_false_when_known_exploited_absent(self, tmp_path, monkeypatch):
        result = self._run(tmp_path, _grype_output({"knownExploited": []}), monkeypatch)
        assert result[0]["kev_listed"] is False

    def test_kev_listed_false_when_known_exploited_key_missing_entirely(self, tmp_path, monkeypatch):
        grype_json = _grype_output({})
        del grype_json["matches"][0]["vulnerability"]["knownExploited"]
        result = self._run(tmp_path, grype_json, monkeypatch)
        assert result[0]["kev_listed"] is False

    def test_risk_score_reads_the_real_risk_field(self, tmp_path, monkeypatch):
        result = self._run(tmp_path, _grype_output({"risk": 9.9}), monkeypatch)
        assert result[0]["risk_score"] == 9.9

    def test_risk_score_none_when_absent(self, tmp_path, monkeypatch):
        grype_json = _grype_output({})
        del grype_json["matches"][0]["vulnerability"]["risk"]
        result = self._run(tmp_path, grype_json, monkeypatch)
        assert result[0]["risk_score"] is None

    def test_old_broken_keys_prove_the_bug_was_real(self, tmp_path, monkeypatch):
        """Anchor: a match carrying the OLD (wrong) 'kev'/'riskScore' keys
        instead of the real ones must NOT be detected as KEV-listed or
        risk-scored — proving the old code's keys genuinely never existed in
        real Grype output, this isn't a hypothetical."""
        grype_json = _grype_output({})
        del grype_json["matches"][0]["vulnerability"]["knownExploited"]
        del grype_json["matches"][0]["vulnerability"]["risk"]
        grype_json["matches"][0]["vulnerability"]["kev"] = "yes-i-am-kev-listed"
        grype_json["matches"][0]["vulnerability"]["riskScore"] = 10.0
        result = self._run(tmp_path, grype_json, monkeypatch)
        assert result[0]["kev_listed"] is False
        assert result[0]["risk_score"] is None

    def test_kev_column_renders_yes_in_pr_comment(self, tmp_path, monkeypatch):
        """End-to-end through the render path: a KEV-listed finding must
        actually show 'Yes' in the rendered SCA table, not silently 'No'."""
        result = self._run(tmp_path, _grype_output({}), monkeypatch)
        out = scanner.render_sca_section(None, result, result)
        assert "🔴 Yes" in out
