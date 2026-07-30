"""Tests for SUP-15/SUP-17/SUP-18/SUP-19: the remaining supply-chain defects
in .github/workflows/{audit,promote,publish}.yml.

SUP-18: promote.yml's cooling-period step declared `jq --arg digest` and then
never referenced it -- the filter selected purely on the `latest` *tag*. The
14-day cooling period, the load-bearing guarantee of the whole rollout design,
was therefore measured against whichever version the packages API reported as
tagged :latest rather than against the LATEST_DIGEST just resolved from the
registry. When those disagree the age of one image is applied to another; when
two versions transiently carry the tag jq emits two lines, `date -d` fails, and
the BSD `date -jf` fallback (a flag that does not exist on the Linux runner)
fails too, leaving `AGE_DAYS=$(( (NOW_TS - ) / 86400 ))` as an arithmetic
syntax error.

SUP-19: publish.yml wrote the workflow_dispatch tag input into $GITHUB_OUTPUT
as a single `value=...` line, so a newline injected arbitrary extra step
outputs into docker/metadata-action tags, the release title and the summary.

SUP-17: audit.yml's header claimed it "Optionally rolls :stable back to the
prior digest". Nothing in the file re-tags anything and its permissions are
deliberately insufficient to. Worse, no prior :stable digest was recorded
anywhere -- promote.yml overwrote the pointer without archiving it.

SUP-15: the KICS query-rules commit pin is real content-addressing, but no
automated check ever re-established which KICS release that tree belongs to.

Where practical these extract the *actual* `run:` block text from the YAML and
execute it with `bash -eo pipefail` -- GitHub Actions' own default shell
invocation -- against fake `docker`/`curl`/`date` binaries planted first on
PATH, the same technique as tests/test_workflow_grype_gating.py.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

LATEST_DIGEST = "sha256:" + "a1" * 32
OTHER_DIGEST = "sha256:" + "b2" * 32
STABLE_DIGEST = "sha256:" + "c3" * 32

KICS_COMMIT = "e1f23cad9640f55b963f22a116b04906b8c16ac6"
KICS_TAG_OBJECT = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"


# ── helpers ───────────────────────────────────────────────────────────────────

def _workflow(path: str) -> dict:
    return yaml.safe_load((REPO_ROOT / path).read_text())


def _step(workflow_path: str, step_name: str) -> dict:
    """Return the named step dict from a workflow -- the actual shipped step,
    not a paraphrase of it."""
    for job in _workflow(workflow_path)["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == step_name:
                return step
    raise AssertionError(f"step {step_name!r} not found in {workflow_path}")


def _run_block(workflow_path: str, step_name: str) -> str:
    step = _step(workflow_path, step_name)
    assert "run" in step, f"step {step_name!r} has no run: block"
    return step["run"]


def _resolve(script: str, expressions: dict[str, str]) -> str:
    """Substitute `${{ ... }}` GitHub Actions expressions the way the runner
    would before handing the script to bash."""
    resolved = script
    for expr, value in expressions.items():
        resolved = re.sub(r"\$\{\{\s*" + re.escape(expr) + r"\s*\}\}", value, resolved)
    assert "${{" not in resolved, f"unresolved GH expression left in script:\n{resolved}"
    return resolved


def _plant(bin_dir: Path, name: str, body: str) -> None:
    exe = bin_dir / name
    exe.write_text(body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# GNU `date` is what the ubuntu-latest runner ships and what the shipped bash
# now relies on exclusively (the BSD `date -jf` fallback was unreachable there
# and has been dropped). This shim supplies GNU `-d` semantics -- including
# failing on an unparseable date -- so the step can be exercised off-Linux.
GNU_DATE_SHIM = textwrap.dedent("""\
    #!/usr/bin/env python3
    import sys, time
    from datetime import datetime, timezone

    args, when, fmt = sys.argv[1:], None, None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-d":
            i += 1
            when = args[i]
        elif a.startswith("-d"):
            when = a[2:]
        elif a.startswith("+"):
            fmt = a[1:]
        i += 1

    if when is None:
        ts = int(time.time())
    else:
        try:
            parsed = datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            print("date: invalid date '%s'" % when, file=sys.stderr)
            sys.exit(1)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        ts = int(parsed.timestamp())

    if fmt != "%s":
        print("date: unsupported format %r in test shim" % fmt, file=sys.stderr)
        sys.exit(2)
    print(ts)
""")

FAKE_DOCKER = textwrap.dedent("""\
    #!/bin/sh
    for a in "$@"; do
      case "$a" in
        *:latest)
          [ -n "$FAKE_LATEST_DIGEST" ] || exit 1
          printf '%s\\n' "$FAKE_LATEST_DIGEST"
          exit 0
          ;;
        *:stable)
          [ -n "$FAKE_STABLE_DIGEST" ] || exit 1
          printf '%s\\n' "$FAKE_STABLE_DIGEST"
          exit 0
          ;;
      esac
    done
    exit 1
""")

FAKE_CURL_VERSIONS = textwrap.dedent("""\
    #!/bin/sh
    if [ -n "$FAKE_CURL_FAIL" ]; then
      echo "curl: (22) HTTP error" >&2
      exit 22
    fi
    cat "$FAKE_VERSIONS_JSON"
""")

FAKE_CURL_KICS = textwrap.dedent("""\
    #!/bin/sh
    if [ -n "$FAKE_CURL_FAIL" ]; then
      echo "curl: (22) HTTP error" >&2
      exit 22
    fi
    for a in "$@"; do
      case "$a" in
        */git/ref/tags/*) cat "$FAKE_REF_JSON"; exit 0 ;;
        */git/tags/*)     cat "$FAKE_TAG_OBJECT_JSON"; exit 0 ;;
      esac
    done
    exit 1
""")


def _bash(script: str, tmp_path: Path, env_overrides: dict[str, str],
          fakes: dict[str, str]) -> subprocess.CompletedProcess:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in fakes.items():
        _plant(bin_dir, name, body)

    gh_output = tmp_path / "GITHUB_OUTPUT"
    gh_output.touch()
    gh_summary = tmp_path / "GITHUB_STEP_SUMMARY"
    gh_summary.touch()

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["GITHUB_OUTPUT"] = str(gh_output)
    env["GITHUB_STEP_SUMMARY"] = str(gh_summary)
    env.update(env_overrides)

    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    proc.gh_output = gh_output.read_text()
    proc.gh_summary = gh_summary.read_text()
    return proc


def _parse_output(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


def _iso_days_ago(days: float) -> str:
    when = datetime.now(timezone.utc) - timedelta(days=days)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _versions_fixture(entries: list[dict]) -> str:
    """Shape a GHCR `.../versions` API payload. `.name` is the version's own
    digest; `.metadata.container.tags` is what the pre-fix filter selected on."""
    return json.dumps([
        {
            "id": i,
            "name": e["digest"],
            "created_at": e["created_at"],
            "metadata": {"container": {"tags": e.get("tags", [])}},
        }
        for i, e in enumerate(entries, start=1)
    ])


# ── SUP-18: cooling period must be measured against the resolved digest ──────

RESOLVE_STEP = "Resolve latest tag digest and age"


def _run_resolve(tmp_path: Path, versions: str, *,
                 latest_digest: str = LATEST_DIGEST,
                 stable_digest: str = STABLE_DIGEST,
                 curl_fails: bool = False) -> subprocess.CompletedProcess:
    script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
    assert "${{" not in script, "this step must not interpolate GH expressions into bash"

    fixture = tmp_path / "versions.json"
    fixture.write_text(versions)

    return _bash(
        script, tmp_path,
        env_overrides={
            "GH_TOKEN": "test-token",
            "FAKE_LATEST_DIGEST": latest_digest,
            "FAKE_STABLE_DIGEST": stable_digest,
            "FAKE_VERSIONS_JSON": str(fixture),
            "FAKE_CURL_FAIL": "1" if curl_fails else "",
        },
        fakes={"docker": FAKE_DOCKER, "curl": FAKE_CURL_VERSIONS, "date": GNU_DATE_SHIM},
    )


@pytest.mark.integration
class TestCoolingPeriodUsesTheResolvedDigest:
    """Anchor regression: the age must come from the version whose digest is
    the one resolved from the registry, never from whichever version the API
    reports as tagged :latest."""

    def test_promotes_when_the_resolved_digest_is_old_even_if_the_tagged_one_is_new(self, tmp_path):
        # Registry says :latest -> LATEST_DIGEST (40 days old). The API's
        # `latest`-tagged entry is a *different*, 1-day-old version. Pre-fix
        # the filter picked the tagged entry and refused to promote.
        versions = _versions_fixture([
            {"digest": OTHER_DIGEST, "created_at": _iso_days_ago(1), "tags": ["latest"]},
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["2.9.0"]},
        ])
        proc = _run_resolve(tmp_path, versions)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["skip"] == "false"
        assert out["age_days"] == "40"
        assert out["digest"] == LATEST_DIGEST

    def test_refuses_when_the_resolved_digest_is_new_even_if_the_tagged_one_is_old(self, tmp_path):
        # The dangerous direction: pre-fix this promoted a 1-day-old image
        # because some *other* version had carried :latest for 40 days.
        versions = _versions_fixture([
            {"digest": OTHER_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["latest"]},
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(1), "tags": ["2.9.0"]},
        ])
        proc = _run_resolve(tmp_path, versions)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["skip"] == "true"
        assert "age_days" not in out


@pytest.mark.integration
class TestCoolingPeriodFailsClosed:
    """Every state in which the age cannot be established must abort the run,
    not skip quietly and not compute an age for the wrong image."""

    def test_two_versions_with_the_same_digest_fail_closed(self, tmp_path):
        versions = _versions_fixture([
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["latest"]},
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(1), "tags": ["latest"]},
        ])
        proc = _run_resolve(tmp_path, versions)
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output
        assert "age_days" not in proc.gh_output
        assert "found 2" in (proc.stdout + proc.stderr)

    def test_no_version_matching_the_resolved_digest_fails_closed(self, tmp_path):
        versions = _versions_fixture([
            {"digest": OTHER_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["latest"]},
        ])
        proc = _run_resolve(tmp_path, versions)
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output
        assert "found 0" in (proc.stdout + proc.stderr)

    def test_api_failure_fails_closed(self, tmp_path):
        versions = _versions_fixture([
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["latest"]},
        ])
        proc = _run_resolve(tmp_path, versions, curl_fails=True)
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output

    def test_non_array_api_response_fails_closed(self, tmp_path):
        proc = _run_resolve(tmp_path, '{"message": "Bad credentials"}')
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output

    def test_unparseable_created_at_fails_closed(self, tmp_path):
        versions = _versions_fixture([
            {"digest": LATEST_DIGEST, "created_at": "not-a-date", "tags": ["latest"]},
        ])
        proc = _run_resolve(tmp_path, versions)
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output
        assert "age_days" not in proc.gh_output


class TestCoolingPeriodFilterShape:
    def test_jq_filter_actually_references_the_digest_argument(self):
        script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
        assert "--arg digest" in script
        # The defect was a declared-but-unused --arg; the filter must consume it.
        filter_lines = [ln for ln in script.splitlines() if "select(" in ln]
        assert filter_lines, "no jq select() filter found in the step"
        assert any("$digest" in ln for ln in filter_lines), (
            "the jq filter must select on the resolved digest, not on a tag"
        )
        assert not any('index("latest")' in ln for ln in filter_lines), (
            "selecting on the :latest tag is exactly the SUP-18 defect"
        )

    def test_unreachable_bsd_date_fallback_is_gone(self):
        script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
        code = [ln for ln in script.splitlines() if not ln.lstrip().startswith("#")]
        assert not any("date -jf" in ln for ln in code), (
            "-jf is a BSD flag; ubuntu-latest's GNU date rejects it, so this "
            "'fallback' could only ever turn one failure into a worse one"
        )


# ── SUP-17: the prior :stable digest must be on record ───────────────────────

@pytest.mark.integration
class TestPromoteRecordsTheDigestItReplaces:
    def test_resolve_step_exports_the_outgoing_stable_digest(self, tmp_path):
        versions = _versions_fixture([
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["latest"]},
        ])
        proc = _run_resolve(tmp_path, versions)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["previous_stable_digest"] == STABLE_DIGEST

    def test_first_ever_promotion_records_an_empty_previous_digest(self, tmp_path):
        """No :stable tag yet -- the output must still exist (downstream steps
        reference it) and must be empty rather than absent."""
        versions = _versions_fixture([
            {"digest": LATEST_DIGEST, "created_at": _iso_days_ago(40.04), "tags": ["latest"]},
        ])
        proc = _run_resolve(tmp_path, versions, stable_digest="")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["previous_stable_digest"] == ""
        assert out["skip"] == "false"


PREDICATE_EXPRESSIONS = {
    "steps.latest.outputs.digest": LATEST_DIGEST,
    "steps.latest.outputs.previous_stable_digest": STABLE_DIGEST,
    "steps.latest.outputs.age_days": "40",
    "steps.scan.outputs.high_count": "0",
    "github.server_url": "https://github.com",
    "github.repository": "zagware/zagware-scanner",
    "github.run_id": "123456789",
}


def _run_predicate(tmp_path: Path, previous: str) -> dict:
    script = _run_block(".github/workflows/promote.yml", "Build promotion predicate")
    exprs = dict(PREDICATE_EXPRESSIONS,
                 **{"steps.latest.outputs.previous_stable_digest": previous})
    proc = _bash(_resolve(script, exprs), tmp_path, env_overrides={}, fakes={})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(Path("/tmp/promotion-predicate.json").read_text())


@pytest.mark.integration
class TestPromotionPredicateCarriesTheReplacedDigest:
    """The attestation is the durable record: job logs age out, the signed
    predicate does not."""

    def test_replaced_digest_is_recorded(self, tmp_path):
        predicate = _run_predicate(tmp_path, STABLE_DIGEST)
        assert predicate["replacedDigest"] == STABLE_DIGEST
        assert predicate["digest"] == LATEST_DIGEST

    def test_first_promotion_records_null_not_an_empty_string(self, tmp_path):
        predicate = _run_predicate(tmp_path, "")
        assert predicate["replacedDigest"] is None


@pytest.mark.integration
class TestPromotionSummaryShowsTheRollbackTarget:
    STEP = "Promotion summary"

    def _summary(self, tmp_path: Path, previous: str) -> str:
        script = _run_block(".github/workflows/promote.yml", self.STEP)
        resolved = _resolve(script, PREDICATE_EXPRESSIONS)
        proc = _bash(resolved, tmp_path,
                     env_overrides={"PREVIOUS_STABLE_DIGEST": previous}, fakes={})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return proc.gh_summary

    def test_summary_names_the_replaced_digest_and_how_to_restore_it(self, tmp_path):
        summary = self._summary(tmp_path, STABLE_DIGEST)
        assert STABLE_DIGEST in summary
        assert "imagetools create" in summary
        assert "zagware-scanner:secure" in summary

    def test_summary_says_so_when_there_is_nothing_to_roll_back_to(self, tmp_path):
        summary = self._summary(tmp_path, "")
        assert "none" in summary.lower()
        assert "imagetools create" not in summary

    def test_previous_digest_reaches_the_summary_via_env_not_interpolation(self):
        step = _step(".github/workflows/promote.yml", self.STEP)
        assert step["env"]["PREVIOUS_STABLE_DIGEST"].strip() == (
            "${{ steps.latest.outputs.previous_stable_digest }}"
        )


class TestAuditYmlClaimsOnlyWhatItDoes:
    WORKFLOW = ".github/workflows/audit.yml"

    def _header(self) -> str:
        text = (REPO_ROOT / self.WORKFLOW).read_text()
        return "\n".join(
            ln for ln in text.splitlines()[: text.splitlines().index("")]
        )

    def test_header_no_longer_claims_it_rolls_stable_back(self):
        """Anchor regression: '# to alert maintainers. Optionally rolls
        :stable back to the prior digest.' described a safety net that has
        never existed anywhere in the repo."""
        assert re.search(r"\brolls?\b", self._header(), re.I) is None, (
            "audit.yml's header must not claim a rollback capability it does "
            "not have"
        )

    def test_audit_never_retags_anything(self):
        """The claim was false because nothing here moves a tag -- keep it
        that way, so the corrected comment stays true."""
        for job in _workflow(self.WORKFLOW)["jobs"].values():
            for step in job["steps"]:
                run = step.get("run", "")
                assert "imagetools create" not in run
                assert "cosign sign" not in run

    def test_audit_permissions_cannot_move_a_tag(self):
        perms = _workflow(self.WORKFLOW)["jobs"]["audit"]["permissions"]
        assert perms.get("packages") != "write"
        assert perms.get("contents") == "read"


# ── SUP-19: the dispatch tag input must not be able to inject outputs ────────

TAG_STEP = "Set image tag"


def _run_set_image_tag(tmp_path: Path, input_tag: str,
                       event_name: str = "workflow_dispatch") -> subprocess.CompletedProcess:
    script = _run_block(".github/workflows/publish.yml", TAG_STEP)
    resolved = _resolve(script, {"github.event_name": f'"{event_name}"'})
    # The runner substitutes the expression *inside* the existing quotes.
    resolved = resolved.replace(f'""{event_name}""', f'"{event_name}"')
    return _bash(resolved, tmp_path,
                 env_overrides={"INPUT_TAG": input_tag, "GITHUB_REF_NAME": "v2.9.0"},
                 fakes={})


class TestDispatchTagOutputIsHeredocDelimited:
    def test_step_never_writes_a_bare_single_line_value_assignment(self):
        """Anchor regression: `echo "value=${INPUT_TAG}" >> "$GITHUB_OUTPUT"`
        is the exact construct a newline in INPUT_TAG weaponises."""
        script = _run_block(".github/workflows/publish.yml", TAG_STEP)
        assert not re.search(r'echo\s+"value=', script), (
            "the tag value must be written with the heredoc delimiter form"
        )
        assert re.search(r'echo\s+"value<<\S+"', script), (
            "expected the documented `value<<DELIM` heredoc output form"
        )

    def test_reserved_tag_guard_from_sup_02_is_still_present(self):
        """SUP-02 and SUP-19 share this step; neither fix may drop the other."""
        script = _run_block(".github/workflows/publish.yml", TAG_STEP)
        assert "stable|secure)" in script
        assert "Refusing to dispatch" in script

    def test_input_reaches_bash_through_env_not_expression_interpolation(self):
        step = _step(".github/workflows/publish.yml", TAG_STEP)
        assert step["env"]["INPUT_TAG"].strip() == "${{ github.event.inputs.tag }}"
        assert "github.event.inputs.tag" not in step["run"]


@pytest.mark.integration
class TestDispatchTagInputValidation:
    @pytest.mark.parametrize("good_input", ["latest", "2.1.0", "10.20.30"])
    def test_valid_input_round_trips_through_the_heredoc(self, tmp_path, good_input):
        proc = _run_set_image_tag(tmp_path, good_input)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        lines = proc.gh_output.splitlines()
        assert lines[0].startswith("value<<")
        delim = lines[0].split("<<", 1)[1]
        assert lines[1] == good_input
        assert lines[2] == delim
        assert len(lines) == 3

    @pytest.mark.parametrize("bad_input", [
        "latest\nvalue=stable",           # the injection the finding describes
        "2.1.0\nvalue=secure",
        "latest\nZAGWARE_TAG_EOF\nvalue=stable",  # try to close the heredoc early
        "stable",
        "secure",
        "v2.1.0",
        "2.1",
        "",
    ])
    def test_rejected_input_writes_nothing_at_all(self, tmp_path, bad_input):
        proc = _run_set_image_tag(tmp_path, bad_input)
        assert proc.returncode != 0
        assert proc.gh_output == "", (
            "a rejected input must leave $GITHUB_OUTPUT untouched -- anything "
            "written here flows into metadata-action tags and the release title"
        )
        assert "::error::" in (proc.stdout + proc.stderr)

    def test_push_path_is_unaffected(self, tmp_path):
        proc = _run_set_image_tag(tmp_path, "", event_name="push")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert proc.gh_output.splitlines()[1] == "2.9.0"


# ── SUP-15: the KICS rules pin must be re-verified against the release tag ───

KICS_STEP = "Verify pinned KICS rules commit matches the KICS release tag"


def _run_kics_verify(tmp_path: Path, ref_json: dict, *,
                     tag_object_json: dict | None = None,
                     kics_commit: str = KICS_COMMIT,
                     kics_version: str = "2.1.20",
                     curl_fails: bool = False) -> subprocess.CompletedProcess:
    script = _run_block(".github/workflows/publish.yml", KICS_STEP)
    assert "${{" not in script, "secrets must reach this step via env:, never inline"

    ref_path = tmp_path / "ref.json"
    ref_path.write_text(json.dumps(ref_json))
    tag_path = tmp_path / "tagobj.json"
    tag_path.write_text(json.dumps(tag_object_json or {}))

    return _bash(
        script, tmp_path,
        env_overrides={
            "GH_TOKEN": "test-token",
            "KICS_RULES_COMMIT": kics_commit,
            "KICS_VERSION": kics_version,
            "FAKE_REF_JSON": str(ref_path),
            "FAKE_TAG_OBJECT_JSON": str(tag_path),
            "FAKE_CURL_FAIL": "1" if curl_fails else "",
        },
        fakes={"curl": FAKE_CURL_KICS},
    )


class TestKicsRulesVerificationIsWiredIn:
    def test_step_runs_before_the_docker_build(self):
        steps = _workflow(".github/workflows/publish.yml")["jobs"]["build-sign-push"]["steps"]
        names = [s.get("name") for s in steps]
        assert KICS_STEP in names, "no KICS rules provenance step in publish.yml"
        build = next(i for i, s in enumerate(steps)
                     if str(s.get("uses", "")).startswith("docker/build-push-action@"))
        assert names.index(KICS_STEP) < build, (
            "verifying the rules pin after the build has already fetched them "
            "is not a gate"
        )

    def test_token_is_passed_via_env_not_interpolated_into_the_command(self):
        step = _step(".github/workflows/publish.yml", KICS_STEP)
        assert step["env"]["GH_TOKEN"].strip() == "${{ secrets.GITHUB_TOKEN }}"
        assert "secrets." not in step["run"]

    def test_values_it_checks_really_are_exported_by_the_dockerfile_read_step(self):
        """The step reads $KICS_RULES_COMMIT/$KICS_VERSION out of the
        environment; those only exist because an earlier step dumps the
        Dockerfile's ARG defaults into $GITHUB_ENV."""
        read_step = _run_block(".github/workflows/publish.yml",
                               "Read pinned versions from Dockerfile")
        assert "GITHUB_ENV" in read_step and "ARG" in read_step
        dockerfile = (REPO_ROOT / "Dockerfile").read_text()
        for arg in ("KICS_RULES_COMMIT", "KICS_VERSION"):
            assert re.search(rf"^ARG {arg}=\S+", dockerfile, re.M), (
                f"{arg} must be a Dockerfile ARG for the workflow check to see it"
            )

    def test_claim_is_provenance_not_signature_verification(self):
        """The old Dockerfile wording said 'verified independently'. Upstream
        KICS release commits are bot-authored and unsigned, so this step must
        not restate that claim."""
        script = _run_block(".github/workflows/publish.yml", KICS_STEP)
        assert "unsigned" in script.lower()


@pytest.mark.integration
class TestKicsRulesVerificationBehaviour:
    def test_matching_lightweight_tag_passes(self, tmp_path):
        proc = _run_kics_verify(tmp_path, {"object": {"type": "commit", "sha": KICS_COMMIT}})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert KICS_COMMIT in proc.stdout

    def test_annotated_tag_is_dereferenced_to_its_commit(self, tmp_path):
        proc = _run_kics_verify(
            tmp_path,
            {"object": {"type": "tag", "sha": KICS_TAG_OBJECT}},
            tag_object_json={"object": {"type": "commit", "sha": KICS_COMMIT}},
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_tag_pointing_elsewhere_fails_closed(self, tmp_path):
        moved = "0" * 40
        proc = _run_kics_verify(tmp_path, {"object": {"type": "commit", "sha": moved}})
        assert proc.returncode != 0
        combined = proc.stdout + proc.stderr
        assert "::error::" in combined
        assert KICS_COMMIT in combined and moved in combined

    def test_annotated_tag_pointing_elsewhere_fails_closed(self, tmp_path):
        proc = _run_kics_verify(
            tmp_path,
            {"object": {"type": "tag", "sha": KICS_TAG_OBJECT}},
            tag_object_json={"object": {"type": "commit", "sha": "1" * 40}},
        )
        assert proc.returncode != 0

    def test_api_failure_fails_closed(self, tmp_path):
        proc = _run_kics_verify(tmp_path, {"object": {"type": "commit", "sha": KICS_COMMIT}},
                                curl_fails=True)
        assert proc.returncode != 0
        assert "::error::" in (proc.stdout + proc.stderr)

    def test_unresolvable_ref_fails_closed(self, tmp_path):
        proc = _run_kics_verify(tmp_path, {"message": "Not Found"})
        assert proc.returncode != 0

    @pytest.mark.parametrize("missing", ["KICS_RULES_COMMIT", "KICS_VERSION"])
    def test_missing_dockerfile_arg_fails_closed(self, tmp_path, missing):
        kwargs = {"kics_commit": "", "kics_version": "2.1.20"}
        if missing == "KICS_VERSION":
            kwargs = {"kics_commit": KICS_COMMIT, "kics_version": ""}
        proc = _run_kics_verify(tmp_path, {"object": {"type": "commit", "sha": KICS_COMMIT}},
                                **kwargs)
        assert proc.returncode != 0
        assert "::error::" in (proc.stdout + proc.stderr)
