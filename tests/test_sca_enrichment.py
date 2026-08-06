"""Tests for advisory SCA reachability enrichment (scanner.enrich_sca_findings).

Covers the contract uploaded to the git-tracking-platform:
  - govulncheck  → Go call-graph reachability (reachable / not_reachable) + traces
  - npm audit    → dependency scope (runtime vs dev), reachability left unknown
  - osv-scanner  → only contributes when call analysis is present
  - alias matching (GO-id/GHSA ↔ the CVE Grype happened to pick)
  - precedence (a strong verdict is never clobbered by a weaker later one)
  - plain-Grype findings keep the non-blocking defaults
  - the upload payload carries the per-scan `enrichment` map

Every native tool is stubbed via subprocess.run + the _tool_available gate, so
the suite needs none of go / npm / osv-scanner installed.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import scanner  # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────────────

def _cp(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _route(mapping: dict[str, str]):
    """Return a subprocess.run stub that picks stdout by a substring of argv.

    `mapping` maps a match token (e.g. "govulncheck", "npm", "osv-scanner",
    "--omit=dev") to the stdout string to return. Longest token wins so
    "--omit=dev" beats a bare "npm"."""
    def _run(cmd, *a, **k):
        argv = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        best = ""
        for tok in sorted(mapping, key=len, reverse=True):
            if tok in argv:
                best = mapping[tok]
                break
        return _cp(best)
    return _run


def _find(findings, vid):
    return next(f for f in findings if f["vulnerability_id"] == vid)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    scanner._SCA_ENRICHMENT.clear()
    monkeypatch.setattr(scanner, "_SCA_ENRICH_ENABLED", True)
    # Nothing available unless a test opts a tool in.
    monkeypatch.setattr(scanner, "_tool_available", lambda b: False)
    yield


# ── framework-level ─────────────────────────────────────────────────────────

def test_parse_json_stream_handles_concatenated_objects():
    text = '{"a":1}\n {"b":2}\t{"c":[3]}'
    assert scanner._parse_json_stream(text) == [{"a": 1}, {"b": 2}, {"c": [3]}]
    assert scanner._parse_json_stream("") == []
    # Truncated trailing object is tolerated, not fatal.
    assert scanner._parse_json_stream('{"a":1} {"b":') == [{"a": 1}]


def test_defaults_applied_and_no_enrichment_when_no_tools(tmp_path):
    findings = [{"vulnerability_id": "CVE-1", "package_name": "left-pad",
                 "package_version": "1.0.0"}]
    enrichment = scanner.enrich_sca_findings(str(tmp_path), findings)
    assert enrichment == {}
    f = findings[0]
    assert f["reachability"] == "unknown"
    assert f["reachability_source"] == ""
    assert f["dependency_scope"] == "unknown"
    assert f["call_paths"] == []


def test_disabled_flag_skips_enrichment(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_SCA_ENRICH_ENABLED", False)
    monkeypatch.setattr(scanner, "_tool_available", lambda b: True)
    called = {"n": 0}
    monkeypatch.setattr(scanner, "_run_govulncheck", lambda p: (called.__setitem__("n", called["n"] + 1), ([], None))[1])
    findings = [{"vulnerability_id": "CVE-1", "package_name": "x", "package_version": "1"}]
    assert scanner.enrich_sca_findings(str(tmp_path), findings) == {}
    assert called["n"] == 0  # runners never invoked
    assert findings[0]["reachability"] == "unknown"


# ── govulncheck (Go call-graph reachability) ─────────────────────────────────

GOVULN_STREAM = (
    '{"osv":{"id":"GO-2023-0001","aliases":["CVE-2023-1111","GHSA-aaaa"],'
    '"affected":[{"package":{"name":"golang.org/x/net"}}]}}\n'
    '{"finding":{"osv":"GO-2023-0001","trace":['
    '{"module":"golang.org/x/net","package":"golang.org/x/net/http2","function":"readFrame"},'
    '{"module":"example.com/app","function":"main"}]}}\n'
    '{"osv":{"id":"GO-2023-0002","aliases":["CVE-2023-2222"],'
    '"affected":[{"package":{"name":"golang.org/x/text"}}]}}\n'
    '{"finding":{"osv":"GO-2023-0002","trace":[{"module":"golang.org/x/text"}]}}\n'
)


def test_govulncheck_reachable_vs_not_reachable_and_alias_match(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    monkeypatch.setattr(scanner, "_tool_available", lambda b: b in ("go", "govulncheck"))
    monkeypatch.setattr(scanner.subprocess, "run", _route({
        "govulncheck": GOVULN_STREAM,  # both -json and -version routed here; version parse is best-effort
    }))
    findings = [
        # Grype picked the CVE alias, not the GO- id — must still match.
        {"vulnerability_id": "CVE-2023-1111", "package_name": "golang.org/x/net", "package_version": "v0.41.0"},
        {"vulnerability_id": "CVE-2023-2222", "package_name": "golang.org/x/text", "package_version": "v0.26.0"},
    ]
    enrichment = scanner.enrich_sca_findings(str(tmp_path), findings)

    assert "go" in enrichment and enrichment["go"]["tool"] == "govulncheck"
    assert enrichment["go"]["mode"] == "reachability"

    net = _find(findings, "CVE-2023-1111")
    assert net["reachability"] == "reachable"
    assert net["dependency_scope"] == "runtime"
    assert "govulncheck" in net["reachability_source"]
    assert net["call_paths"] and "readFrame" in net["call_paths"][0]["trace"]

    txt = _find(findings, "CVE-2023-2222")
    assert txt["reachability"] == "not_reachable"
    assert "govulncheck" in txt["reachability_source"]
    assert txt["call_paths"] == []


def test_govulncheck_skipped_without_go_mod(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_tool_available", lambda b: True)
    monkeypatch.setattr(scanner.subprocess, "run", _route({"govulncheck": GOVULN_STREAM}))
    findings = [{"vulnerability_id": "CVE-2023-1111", "package_name": "golang.org/x/net", "package_version": "v0.41.0"}]
    enrichment = scanner.enrich_sca_findings(str(tmp_path), findings)  # no go.mod
    assert "go" not in enrichment
    assert findings[0]["reachability"] == "unknown"


# ── npm audit (dependency scope) ─────────────────────────────────────────────

NPM_FULL = json.dumps({"vulnerabilities": {
    "lodash": {"name": "lodash", "severity": "high",
               "via": [{"url": "https://github.com/advisories/GHSA-xxxx"}]},
    "mocha": {"name": "mocha", "severity": "low",
              "via": [{"url": "https://github.com/advisories/GHSA-yyyy"}]},
}})
NPM_PROD = json.dumps({"vulnerabilities": {
    "lodash": {"name": "lodash", "severity": "high", "via": []},
}})


def test_npm_audit_sets_scope_leaves_reachability_unknown(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}")
    monkeypatch.setattr(scanner, "_tool_available", lambda b: b == "npm")
    monkeypatch.setattr(scanner.subprocess, "run", _route({
        "--omit=dev": NPM_PROD,
        "npm": NPM_FULL,
    }))
    findings = [
        {"vulnerability_id": "GHSA-xxxx", "package_name": "lodash", "package_version": "4.17.20"},
        {"vulnerability_id": "GHSA-yyyy", "package_name": "mocha", "package_version": "9.0.0"},
    ]
    enrichment = scanner.enrich_sca_findings(str(tmp_path), findings)

    assert enrichment["npm"]["tool"] == "npm-audit" and enrichment["npm"]["mode"] == "advisory"
    lodash = _find(findings, "GHSA-xxxx")
    mocha = _find(findings, "GHSA-yyyy")
    assert lodash["dependency_scope"] == "runtime"
    assert mocha["dependency_scope"] == "dev"
    # npm audit is not call analysis — reachability must stay unknown.
    assert lodash["reachability"] == "unknown" and mocha["reachability"] == "unknown"
    assert "npm-audit" in lodash["reachability_source"]


# ── osv-scanner (only enriches with call analysis) ───────────────────────────

def _osv(called_value):
    return json.dumps({"results": [{"packages": [{
        "package": {"name": "golang.org/x/crypto", "version": "v0.1.0", "ecosystem": "Go"},
        "vulnerabilities": [{"id": "GO-2024-1", "aliases": ["CVE-2024-9"]}],
        "groups": [{"ids": ["GO-2024-1"], "experimentalAnalysis": {"GO-2024-1": {"called": called_value}}}],
    }]}]})


def test_osv_call_analysis_marks_not_reachable(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_tool_available", lambda b: b == "osv-scanner")
    monkeypatch.setattr(scanner.subprocess, "run", _route({"osv-scanner": _osv(False)}))
    findings = [{"vulnerability_id": "CVE-2024-9", "package_name": "golang.org/x/crypto", "package_version": "v0.1.0"}]
    enrichment = scanner.enrich_sca_findings(str(tmp_path), findings)
    assert enrichment["osv"]["mode"] == "reachability"
    assert findings[0]["reachability"] == "not_reachable"
    assert "osv-scanner" in findings[0]["reachability_source"]


def test_osv_advisory_records_mode_but_sets_no_reachability(tmp_path, monkeypatch):
    # Core image (osv-scanner, no Go): advisory version-match only. osv-scanner
    # is recorded as having assessed the tree (mode=advisory), but with no call
    # analysis it must NOT set a per-finding reachability verdict or source.
    payload = json.dumps({"results": [{"packages": [{
        "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
        "vulnerabilities": [{"id": "GHSA-z", "aliases": []}],
        "groups": [{"ids": ["GHSA-z"]}],  # no experimentalAnalysis
    }]}]})
    monkeypatch.setattr(scanner, "_tool_available", lambda b: b == "osv-scanner")
    monkeypatch.setattr(scanner.subprocess, "run", _route({"osv-scanner": payload}))
    findings = [{"vulnerability_id": "GHSA-z", "package_name": "left-pad", "package_version": "1.0.0"}]
    enrichment = scanner.enrich_sca_findings(str(tmp_path), findings)
    assert enrichment["osv"]["mode"] == "advisory"      # recorded as assessed
    assert findings[0]["reachability"] == "unknown"     # but no verdict claimed
    assert findings[0]["reachability_source"] == ""


# ── precedence & payload ─────────────────────────────────────────────────────

def test_apply_verdict_only_fills_defaults():
    f = {"vulnerability_id": "CVE-1", "package_name": "p", "package_version": "1",
         "reachability": "reachable", "reachability_source": "govulncheck",
         "dependency_scope": "unknown", "call_paths": []}
    by_name = {"p": [f]}
    # A weaker later verdict must NOT downgrade reachability, but MAY fill scope.
    scanner._apply_verdict(by_name, {"name": "p", "ids": {"CVE-1"},
                                     "reachability": "not_reachable", "scope": "runtime",
                                     "source": "osv-scanner"})
    assert f["reachability"] == "reachable"             # not clobbered
    assert f["dependency_scope"] == "runtime"           # default filled
    assert f["reachability_source"] == "govulncheck,osv-scanner"


def test_upload_payload_carries_enrichment(monkeypatch):
    scanner._SCA_ENRICHMENT["base"] = {"go": {"tool": "govulncheck", "version": "v1.1.4", "mode": "reachability"}}
    scanner._SCA_ENRICHMENT["pr"] = {"npm": {"tool": "npm-audit", "version": "11", "mode": "advisory"}}
    sent = []

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"scan_id": "s-1"}).encode()

    def _fake_urlopen(req, *a, **k):
        sent.append(json.loads(req.data.decode()))
        return _Resp()

    monkeypatch.setattr(scanner, "_urlopen", _fake_urlopen)
    monkeypatch.setattr(scanner, "_repo_base_url", lambda: "https://github.com/o/r")

    scanner.upload_sca_to_platform(
        "https://platform", "tok", "o/r", "main", "feature", 42,
        base_findings=[{"vulnerability_id": "CVE-1", "package_name": "p", "package_version": "1"}],
        head_findings=[{"vulnerability_id": "CVE-1", "package_name": "p", "package_version": "1"}],
    )
    assert len(sent) == 2
    assert sent[0]["enrichment"] == {"go": {"tool": "govulncheck", "version": "v1.1.4", "mode": "reachability"}}
    assert sent[0]["scan_type"] == "pr_base"
    assert sent[1]["enrichment"] == {"npm": {"tool": "npm-audit", "version": "11", "mode": "advisory"}}
    assert sent[1]["scan_type"] == "pr_head"
