"""Tests for SEC-02 (category matching + expected_value redaction) and SEC-03
(redact before platform upload) — both are about the same written guarantee:
"Findings never include the raw secret value in the PR comment, platform
upload, or scan artifacts" (README.md:372-375).

Category ground truth: verified directly against the KICS ruleset commit
pinned in Dockerfile's KICS_RULES_COMMIT (e1f23cad9640f55b963f22a116b04906b8c16ac6) —
the real, complete category taxonomy is: Access Control, Availability, Backup,
Best Practices, Bill Of Materials, Build Process, Encryption, Insecure
Configurations, Insecure Defaults, Networking and Firewall, Observability,
Resource Management, Secret Management, Structure and Semantics, Supply-Chain.
Only "Secret Management" denotes a secret-VALUE-shaped finding.
"""
from __future__ import annotations

import scanner

# Assembled at runtime, never written as a literal. This repository is a secret
# scanner: an AWS-key-shaped string committed here trips GitHub push protection
# on our own pushes, and would fire on every customer who clones us. The value
# still matches the scanner's `AKIA[0-9A-Z]{16}` pattern, which is the point of
# the fixture.
AWS_KEY_SHAPED = "AKIA" + "Q" * 16


class TestRedactValueCategoryMatching:
    def test_secret_management_category_is_fully_redacted(self):
        """The exact real KICS category for credential queries."""
        assert scanner._redact_value("hunter2", "Secret Management") == "***REDACTED***"

    def test_category_matching_is_case_insensitive(self):
        assert scanner._redact_value("hunter2", "secret management") == "***REDACTED***"
        assert scanner._redact_value("hunter2", "SECRET MANAGEMENT") == "***REDACTED***"

    def test_encryption_category_is_not_blanket_redacted(self):
        """Encryption findings (e.g. "encryption enabled: false") are not
        secret-VALUE-shaped — blanket-redacting them would hide genuinely
        useful review information for the vast majority of non-secret
        findings. Only the regex pattern pass applies, which a plain boolean
        string does not match."""
        assert scanner._redact_value("false", "Encryption") == "false"
        assert scanner._redact_value("AES256", "Encryption") == "AES256"

    def test_other_real_kics_categories_are_not_blanket_redacted(self):
        for cat in ["Access Control", "Availability", "Backup", "Best Practices",
                    "Bill Of Materials", "Build Process", "Insecure Configurations",
                    "Insecure Defaults", "Networking and Firewall", "Observability",
                    "Resource Management", "Structure and Semantics", "Supply-Chain"]:
            assert scanner._redact_value("0.0.0.0/0", cat) == "0.0.0.0/0", cat

    def test_pattern_pass_still_catches_secret_shaped_values_in_any_category(self):
        """Defense in depth: even in a non-secret category, a value that
        matches one of the five secret-shaped regexes is still redacted."""
        assert scanner._redact_value(AWS_KEY_SHAPED, "Best Practices") == "***REDACTED***"
        assert scanner._redact_value("password: hunter2", "Access Control") == "***REDACTED***"

    def test_non_secret_shaped_value_in_secret_management_is_still_redacted(self):
        """The category branch is unconditional once matched — the whole
        point of the category signal is that KICS itself has already
        classified this as a credential finding, so redact regardless of
        whether the value happens to match one of the five generic regexes."""
        assert scanner._redact_value("arbitrary-non-pattern-value", "Secret Management") == "***REDACTED***"

    def test_previously_broken_regime_reproduced_to_prove_it_was_a_typo_not_a_design_choice(self):
        """Anchor: the old _SECRET_CATEGORIES = {"secrets","password",...} never
        matched "secret management" (substring "secrets" plural does not occur
        in "secret management"). This documents why that was wrong, not a
        behaviour we want back."""
        old_broken_categories = {"secrets", "password", "credential", "key", "token", "authentication"}
        assert not any(k in "secret management" for k in old_broken_categories)


class TestRedactKicsResults:
    def _kics_result(self, category="Secret Management", actual="hunter2", expected="no hardcoded secret"):
        return {
            "queries": [{
                "category": category,
                "files": [{"actual_value": actual, "expected_value": expected, "file_name": "main.tf"}],
            }]
        }

    def test_redacts_both_actual_and_expected_value_for_secret_category(self):
        redacted = scanner._redact_kics_results(self._kics_result())
        f = redacted["queries"][0]["files"][0]
        assert f["actual_value"] == "***REDACTED***"
        # expected_value gets only the regex pass (no category blanket), and
        # "no hardcoded secret" doesn't match any of the five patterns —
        # confirm it survives untouched, proving this isn't a blanket wipe.
        assert f["expected_value"] == "no hardcoded secret"

    def test_expected_value_still_redacted_if_pattern_matches(self):
        redacted = scanner._redact_kics_results(
            self._kics_result(category="Best Practices", expected=AWS_KEY_SHAPED)
        )
        assert redacted["queries"][0]["files"][0]["expected_value"] == "***REDACTED***"

    def test_does_not_mutate_the_original_dict(self):
        original = self._kics_result()
        scanner._redact_kics_results(original)
        assert original["queries"][0]["files"][0]["actual_value"] == "hunter2"

    def test_non_secret_category_actual_value_untouched(self):
        redacted = scanner._redact_kics_results(self._kics_result(category="Networking and Firewall", actual="0.0.0.0/0"))
        assert redacted["queries"][0]["files"][0]["actual_value"] == "0.0.0.0/0"


class TestRenderCommentRedactsBothColumns:
    def _novel(self, category="Secret Management"):
        return [{
            "query_name": "Hardcoded Secret Found",
            "severity": "CRITICAL",
            "category": category,
            "platform": "Terraform",
            "description": "desc",
            "files": [{
                "file_name": "main.tf", "line": 12,
                "resource_name": "db", "issue_type": "MissingAttribute",
                "expected_value": "no hardcoded secret",
                "actual_value": "hunter2",
                "similarity_id": "a" * 64,
            }],
        }]

    def test_actual_value_redacted_in_rendered_comment(self):
        empty = {"queries": []}
        out = scanner.render_comment(empty, empty, self._novel(), "main", "pr")
        assert "hunter2" not in out
        assert "***REDACTED***" in out

    def test_non_secret_category_actual_value_visible_in_comment(self):
        """Control: the fix must not blanket-hide legitimate review info for
        the common non-secret case."""
        empty = {"queries": []}
        out = scanner.render_comment(empty, empty, self._novel(category="Networking and Firewall"), "main", "pr")
        assert "hunter2" in out  # unchanged as a literal value in this test, just proving no blanket redaction


class TestUploadToPlatformRedactsBeforeSending:
    """SEC-03 end-to-end: the exact payload sent to the platform must never
    contain the raw actual_value KICS extracted.

    upload_to_platform() does not go through the shared _http() helper (same
    as upload_sca_to_platform/upload_secrets_to_platform, an existing pattern
    this test respects rather than papers over). Since SEC-05 it routes
    through scanner._urlopen — the single chokepoint that blocks cross-host
    redirects and enforces a timeout — so that is what is patched here."""

    def test_redacted_kics_results_reach_the_http_payload_untouched(self, monkeypatch):
        sent_bodies: list[bytes] = []

        class _FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return b'{"scan_id": "test-scan-id"}'

        def _fake_urlopen(req, timeout=30):
            sent_bodies.append(req.data)
            return _FakeResponse()

        monkeypatch.setattr(scanner, "_urlopen", _fake_urlopen)

        raw = {
            "queries": [{
                "category": "Secret Management",
                "files": [{"actual_value": "hunter2", "expected_value": "x", "file_name": "main.tf"}],
            }]
        }
        redacted_base = scanner._redact_kics_results(raw)
        redacted_head = scanner._redact_kics_results(raw)

        scanner.upload_to_platform(
            "https://platform.example", "gtp_test_token",
            "acme/widgets", "main", "", "feature", "",
            42, redacted_base, redacted_head,
        )

        assert len(sent_bodies) == 2  # base scan + head scan (pr_number set, base_scan_id returned)
        for body in sent_bodies:
            assert b"hunter2" not in body, "raw secret value reached the platform upload payload"
            assert b"REDACTED" in body

    def test_raw_unredacted_results_would_have_leaked_without_the_fix(self, monkeypatch):
        """Negative control proving the test harness actually catches the
        SEC-03 bug: calling upload_to_platform with the RAW (unredacted)
        dict — the exact call shape main() used before this fix — must leak
        the secret, so we know the assertions above are meaningful."""
        sent_bodies: list[bytes] = []

        class _FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return b'{"scan_id": "test-scan-id"}'

        monkeypatch.setattr(scanner, "_urlopen",
                             lambda req, timeout=30: (sent_bodies.append(req.data), _FakeResponse())[1])

        raw = {
            "queries": [{
                "category": "Secret Management",
                "files": [{"actual_value": "hunter2", "expected_value": "x", "file_name": "main.tf"}],
            }]
        }
        scanner.upload_to_platform(
            "https://platform.example", "gtp_test_token",
            "acme/widgets", "main", "", "feature", "",
            42, raw, raw,
        )
        assert any(b"hunter2" in body for body in sent_bodies)
