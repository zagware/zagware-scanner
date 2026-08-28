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
    # Stands in for `docker buildx imagetools inspect <ref> --format <fmt>`,
    # which promote.yml calls twice: once to resolve a tag to a digest, and
    # once to read the version label back off that digest.
    REF=""
    FMT=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --format) FMT="$2"; shift 2 ;;
        ghcr.io/*) REF="$1"; shift ;;
        *) shift ;;
      esac
    done

    case "$FMT" in
      *Labels*)
        [ -n "$FAKE_VERSION_LABEL" ] || exit 1
        printf '%s\\n' "$FAKE_VERSION_LABEL"
        exit 0
        ;;
    esac

    # The real call asks for `{{json .Manifest}}` and pipes it through jq, so
    # the stub has to answer in that shape -- a stub that returned a bare
    # digest would pass while the shipped command no longer does.
    case "$REF" in
      *:latest)
        [ -n "$FAKE_LATEST_DIGEST" ] || exit 1
        printf '{"digest":"%s"}\\n' "$FAKE_LATEST_DIGEST"
        exit 0
        ;;
      *:stable)
        [ -n "$FAKE_STABLE_DIGEST" ] || exit 1
        printf '{"digest":"%s"}\\n' "$FAKE_STABLE_DIGEST"
        exit 0
        ;;
    esac
    exit 1
""")

FAKE_GH_RELEASE = textwrap.dedent("""\
    #!/bin/sh
    if [ -n "$FAKE_GH_FAIL" ]; then
      echo "gh: release not found (HTTP 404)" >&2
      exit 1
    fi
    printf '%s\\n' "$FAKE_RELEASE_DATE"
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


# ── The cooling clock runs on the RELEASE, bound to the candidate digest ─────
#
# SUP-18's defect was measuring the age of a different image than the one being
# promoted: the filter selected on whatever the API reported as tagged `latest`.
# The fix then measured the candidate digest's own creation date -- correct, but
# it made the gate unsatisfiable, because the remedy for a blocking CVE is a
# rebuild and a rebuild mints a new digest, resetting the soak to zero.
#
# The clock now runs on the release the candidate was built FROM, read out of
# the digest's own org.opencontainers.image.version label. That keeps SUP-18's
# invariant -- the binding runs from the candidate outward, never from a tag
# inward -- while letting a weekly rebuild of an already-soaked release be
# promotable the moment it lands.

RESOLVE_STEP = "Resolve promotion candidate and release age"


def _run_resolve(tmp_path: Path, *,
                 latest_digest: str = LATEST_DIGEST,
                 stable_digest: str = STABLE_DIGEST,
                 version_label: str = "2.9.0",
                 release_date: str | None = None,
                 gh_fails: bool = False) -> subprocess.CompletedProcess:
    script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
    assert "${{" not in script, "this step must not interpolate GH expressions into bash"

    # The cooling gate reads COOLING_DAYS from the workflow-level `env:` block,
    # which the extracted run-block alone does not carry. Inject it FROM the
    # workflow rather than restating 7 here -- a hardcoded copy would keep
    # passing after someone changed the real threshold, which is precisely the
    # bug this suite exists to catch.
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/promote.yml").read_text()
    )
    workflow_env = {k: str(v) for k, v in (workflow.get("env") or {}).items()}
    assert "COOLING_DAYS" in workflow_env, "promote.yml no longer defines COOLING_DAYS"

    return _bash(
        script, tmp_path,
        env_overrides={
            **workflow_env,
            "GH_TOKEN": "test-token",
            "GITHUB_REPOSITORY": "zagware/zagware-scanner",
            "FAKE_LATEST_DIGEST": latest_digest,
            "FAKE_STABLE_DIGEST": stable_digest,
            "FAKE_VERSION_LABEL": version_label,
            "FAKE_RELEASE_DATE": (
                _iso_days_ago(40.04) if release_date is None else release_date
            ),
            "FAKE_GH_FAIL": "1" if gh_fails else "",
        },
        fakes={"docker": FAKE_DOCKER, "gh": FAKE_GH_RELEASE, "date": GNU_DATE_SHIM},
    )


@pytest.mark.integration
class TestCoolingPeriodRunsOnTheRelease:
    def test_old_release_is_promotable(self, tmp_path):
        proc = _run_resolve(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["skip"] == "false"
        assert out["age_days"] == "40"
        assert out["digest"] == LATEST_DIGEST
        assert out["version"] == "2.9.0"

    def test_young_release_is_refused(self, tmp_path):
        proc = _run_resolve(tmp_path, release_date=_iso_days_ago(1))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["skip"] == "true"
        assert "age_days" not in out

    def test_a_rebuild_of_a_soaked_release_is_promotable_immediately(self, tmp_path):
        """The point of the whole change. A fresh digest -- one that has never
        been :latest for a single day -- is promotable when the release it was
        built from has already soaked. Under a digest clock this was the case
        that reset the wait every time an OS CVE was fixed, which is why no
        promotion had ever completed."""
        proc = _run_resolve(tmp_path, latest_digest=OTHER_DIGEST)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["skip"] == "false"
        assert out["digest"] == OTHER_DIGEST
        assert out["age_days"] == "40"

    def test_age_comes_from_the_candidates_own_label_not_a_tag_lookup(self, tmp_path):
        """SUP-18's invariant, preserved. The version is read off the digest
        being promoted, so it cannot be a different image's -- the binding runs
        from the candidate outward, never from a tag inward."""
        script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
        code = "\n".join(ln for ln in script.splitlines()
                         if not ln.lstrip().startswith("#"))
        assert "org.opencontainers.image.version" in code
        assert '@${LATEST_DIGEST}' in code, (
            "the version must be read from the resolved digest, not from a tag"
        )
        # The only tag this step may resolve is the candidate pointer itself
        # and the outgoing :stable -- never a version tag it then trusts.
        assert ":latest" in code and ":stable" in code
        assert 'v${VERSION}"' not in code.replace(
            'releases/tags/v${VERSION}', ''
        ), "the release lookup is the only permitted use of the version string"


@pytest.mark.integration
class TestCoolingPeriodFailsClosed:
    """Every state in which the age cannot be established must abort the run,
    not skip quietly and not compute an age for the wrong image."""

    def test_missing_version_label_fails_closed(self, tmp_path):
        proc = _run_resolve(tmp_path, version_label="")
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output
        assert "age_days" not in proc.gh_output

    @pytest.mark.parametrize("bad_label", ["latest", "v2.9.0", "2.9", "main"])
    def test_malformed_version_label_fails_closed(self, bad_label, tmp_path):
        proc = _run_resolve(tmp_path, version_label=bad_label)
        assert proc.returncode != 0
        assert "age_days" not in proc.gh_output

    def test_missing_release_fails_closed(self, tmp_path):
        """An image whose label names a release that does not exist is itself
        the anomaly worth stopping on."""
        proc = _run_resolve(tmp_path, gh_fails=True)
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output
        assert "age_days" not in proc.gh_output

    def test_empty_release_date_fails_closed(self, tmp_path):
        proc = _run_resolve(tmp_path, release_date="")
        assert proc.returncode != 0
        assert "age_days" not in proc.gh_output

    def test_unparseable_release_date_fails_closed(self, tmp_path):
        proc = _run_resolve(tmp_path, release_date="not-a-date")
        assert proc.returncode != 0
        assert "skip=true" not in proc.gh_output
        assert "age_days" not in proc.gh_output


class TestCoolingPeriodStepShape:
    def test_unreachable_bsd_date_fallback_is_gone(self):
        script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
        code = [ln for ln in script.splitlines() if not ln.lstrip().startswith("#")]
        assert not any("date -jf" in ln for ln in code), (
            "-jf is a BSD flag; ubuntu-latest's GNU date rejects it, so this "
            "'fallback' could only ever turn one failure into a worse one"
        )

    def test_no_tag_keyed_lookup_survives(self):
        """SUP-18 anchor: selecting the age by a registry tag rather than by
        the candidate itself is the original defect."""
        script = _run_block(".github/workflows/promote.yml", RESOLVE_STEP)
        code = "\n".join(ln for ln in script.splitlines()
                         if not ln.lstrip().startswith("#"))
        assert 'index("latest")' not in code


# ── SUP-17: the prior :stable digest must be on record ───────────────────────

@pytest.mark.integration
class TestPromoteRecordsTheDigestItReplaces:
    def test_resolve_step_exports_the_outgoing_stable_digest(self, tmp_path):
        proc = _run_resolve(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _parse_output(proc.gh_output)["previous_stable_digest"] == STABLE_DIGEST

    def test_first_ever_promotion_records_an_empty_previous_digest(self, tmp_path):
        """No :stable tag yet -- the output must still exist (downstream steps
        reference it) and must be empty rather than absent."""
        proc = _run_resolve(tmp_path, stable_digest="")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = _parse_output(proc.gh_output)
        assert out["previous_stable_digest"] == ""
        assert out["skip"] == "false"


PREDICATE_EXPRESSIONS = {
    "steps.latest.outputs.digest": LATEST_DIGEST,
    "steps.latest.outputs.previous_stable_digest": STABLE_DIGEST,
    "steps.latest.outputs.age_days": "40",
    "steps.scan.outputs.high_count": "28",
    "steps.scan.outputs.fixable_count": "25",
    "steps.scan.outputs.blocking_count": "0",
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
                       event_name: str = "workflow_dispatch",
                       refresh_version: str = "") -> subprocess.CompletedProcess:
    script = _run_block(".github/workflows/publish.yml", TAG_STEP)
    # Everything the step needs now arrives through its own `env:` block, so
    # the shipped bash carries no GH expressions and runs here verbatim --
    # nothing has to be paraphrased to be testable.
    assert "${{" not in script, f"this step must not interpolate GH expressions:\n{script}"
    return _bash(script, tmp_path,
                 env_overrides={
                     "INPUT_TAG": input_tag,
                     "EVENT_NAME": event_name,
                     "REFRESH_VERSION": refresh_version,
                     "GITHUB_REF_NAME": "v2.9.0",
                 },
                 fakes={})


class TestDispatchTagOutputIsHeredocDelimited:
    def test_step_never_writes_a_bare_single_line_value_assignment(self):
        """Anchor regression: `echo "value=${INPUT_TAG}" >> "$GITHUB_OUTPUT"`
        is the exact construct a newline in INPUT_TAG weaponises. Both outputs
        now go through one `emit` helper, so the property is checked on the
        helper -- and on the absence of any direct write that bypasses it."""
        script = _run_block(".github/workflows/publish.yml", TAG_STEP)
        assert not re.search(r'echo\s+"(value|image_tag)=', script), (
            "outputs must be written with the heredoc delimiter form"
        )
        assert re.search(r'echo\s+"\$1<<\S+"', script), (
            "expected the documented `<name><<DELIM` heredoc output form"
        )
        direct_writes = [ln for ln in script.splitlines()
                         if 'GITHUB_OUTPUT' in ln
                         and 'emit' not in ln
                         and not ln.lstrip().startswith('#')]
        assert len(direct_writes) == 1, (
            "every GITHUB_OUTPUT write must go through emit(), so the heredoc "
            f"form cannot be bypassed by a future edit: {direct_writes!r}"
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
        # Two outputs now: `value` (the release version, which becomes the
        # image's version label) and `image_tag` (what actually gets pushed).
        # On a dispatch they are the same; the weekly refresh is where they
        # diverge. Both must use the heredoc form -- an injected newline must
        # not be able to smuggle a second output past either one.
        assert lines[0].startswith("value<<")
        delim = lines[0].split("<<", 1)[1]
        assert lines[1] == good_input
        assert lines[2] == delim
        assert lines[3] == f"image_tag<<{delim}"
        assert lines[4] == good_input
        assert lines[5] == delim
        assert len(lines) == 6

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


@pytest.mark.integration
class TestCoolingPeriodIsSevenDays:
    """The threshold itself, asserted behaviourally. The tests above use ages
    of 1 and 40 days, which straddle both the old 14 and the new 7 -- so they
    pass under either and pin nothing. These bracket the actual boundary.
    """

    def test_the_declared_period_is_seven_days(self):
        workflow = yaml.safe_load(
            (REPO_ROOT / ".github/workflows/promote.yml").read_text()
        )
        assert int(workflow["env"]["COOLING_DAYS"]) == 7

    def test_six_days_old_is_refused(self, tmp_path):
        out = _parse_output(_run_resolve(tmp_path, release_date=_iso_days_ago(6)).gh_output)
        assert out["skip"] == "true"

    def test_eight_days_old_is_promoted(self, tmp_path):
        out = _parse_output(_run_resolve(tmp_path, release_date=_iso_days_ago(8.04)).gh_output)
        assert out["skip"] == "false"
        assert out["age_days"] == "8"

    def test_no_stale_literal_threshold_remains(self):
        """Six copies of `14` used to live in this file, three of them in
        operator-facing error strings. A gate whose error message disagrees
        with the gate is worse than no message."""
        text = (REPO_ROOT / ".github/workflows/promote.yml").read_text()
        live = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
        assert "-lt 14" not in live
        assert "14-day" not in live


class TestToolCurrencyWorkflow:
    """The watch that would have caught KICS going binary-less months earlier."""

    def _doc(self):
        return yaml.safe_load(
            (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        )

    def test_runs_on_a_schedule(self):
        on = self._doc()[True] if True in self._doc() else self._doc()["on"]
        assert "schedule" in on

    def test_cannot_write_repository_contents(self):
        """It reports; a human decides. Write access to contents would let a
        bad upstream lookup rewrite our pins unattended."""
        job = self._doc()["jobs"]["currency"]
        assert job["permissions"]["contents"] == "read"
        assert job["permissions"]["issues"] == "write"

    def test_watches_every_bundled_tool(self):
        text = (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        for repo in ("Checkmarx/kics", "anchore/syft", "anchore/grype",
                     "betterleaks/betterleaks"):
            assert repo in text, f"{repo} is not watched"

    def test_watches_every_pinned_base_image(self):
        text = (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        for arg in ("WOLFI_DIGEST", "DEBIAN_DIGEST", "GO_DIGEST"):
            assert arg in text, f"{arg} pin is not checked for pullability"

    def test_escalation_requires_fixable_cves(self):
        """Escalating on unfixable findings would make the signal permanent --
        two containerd advisories in KICS have no upstream patch at all."""
        text = (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        assert "c.fixable > 0 &&" in text

    def test_unknown_release_age_is_never_treated_as_fresh(self):
        """A failed date parse previously produced days-since-epoch, which read
        as catastrophically stale; the opposite error -- reading as 0 days --
        would silently suppress the escalation this workflow exists for."""
        text = (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        assert "AGE=-1" in text
        assert "unknownAge" in text

    def test_cve_attribution_falls_back_to_latest(self):
        """:stable does not exist until a release completes its first promotion
        cycle. Without a fallback the escalation signal is dead from day one --
        the first real run of this workflow proved it, skipping CVE attribution
        entirely."""
        text = (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        assert "FALLBACK_IMAGE" in text
        assert 'for ref in "$IMAGE" "$FALLBACK_IMAGE"' in text

    def test_report_names_the_image_it_measured(self):
        """A CVE table whose basis is ambiguous invites the wrong conclusion."""
        text = (REPO_ROOT / ".github/workflows/tool-currency.yml").read_text()
        assert "scanned_ref.txt" in text
        assert "measured against" in text


class TestActionPinsAreLegible:
    """Every action is pinned to a 40-char SHA, which is the security property
    but is also unreadable: nothing in the file says whether
    `@11d5960a...` is a current release or three majors behind. That is how all
    nine pins quietly ended up on the deprecated node20 runtime. The trailing
    `# vX.Y.Z` comment is what makes drift visible to a human.
    """

    def _uses(self):
        import itertools
        files = itertools.chain(
            (REPO_ROOT / ".github/workflows").glob("*.yml"),
            (REPO_ROOT / ".github/actions").glob("*/action.yml"),
        )
        out = []
        for f in files:
            for line in f.read_text().splitlines():
                s = line.strip()
                if s.startswith("uses:") and "./" not in s:
                    out.append((f.name, s))
        return out

    def test_every_action_is_pinned_to_a_full_sha(self):
        for fname, line in self._uses():
            assert re.search(r'@[a-f0-9]{40}\b', line), f"{fname}: not SHA-pinned -- {line}"

    def test_every_pin_records_the_version_it_represents(self):
        for fname, line in self._uses():
            assert re.search(r'@[a-f0-9]{40}\s*#\s*v\d+\.\d+', line), (
                f"{fname}: SHA pin has no `# vX.Y.Z` comment, so drift is invisible -- {line}"
            )

    def test_one_sha_per_action_across_the_repo(self):
        """Two workflows pinning the same action at different SHAs means one of
        them was missed during a bump."""
        seen = {}
        for fname, line in self._uses():
            m = re.search(r'uses:\s*([\w.-]+/[\w.-]+)@([a-f0-9]{40})', line)
            if not m:
                continue
            repo, sha = m.groups()
            seen.setdefault(repo, set()).add(sha)
        drifted = {r: s for r, s in seen.items() if len(s) > 1}
        assert not drifted, f"same action pinned at different SHAs: {drifted}"


class TestMissingTagIsASkipNotAFailure:
    """GitHub runs `run:` blocks under `bash -e`. A bare command substitution
    that fails aborts the step, so a following `if [ -z "$VAR" ]` guard never
    executes. audit.yml had exactly that: the weekly audit went red on every
    run purely because :stable does not exist before the first promotion --
    an ordinary bootstrap state reported as a failure.
    """

    @pytest.mark.parametrize("workflow,tag", [
        (".github/workflows/audit.yml", "stable"),
        (".github/workflows/promote.yml", "latest"),
    ])
    def test_digest_lookup_cannot_abort_the_step(self, workflow, tag):
        text = (REPO_ROOT / workflow).read_text()
        block = re.search(
            r'imagetools inspect\s*\\\s*\n\s*ghcr\.io/zagware/zagware-scanner:'
            + tag + r'\s*\\\s*\n\s*--format[^\n]*\n',
            text,
        )
        assert block, f"{workflow}: could not find the :{tag} digest lookup"
        assert re.search(r'\|\|\s*(true|echo\s*"")', block.group(0)), (
            f"{workflow}: the :{tag} lookup can abort the step under `bash -e`, "
            f"making the following empty-digest guard unreachable"
        )

    def test_both_workflows_still_have_the_guard_they_protect(self):
        for wf, var in ((".github/workflows/audit.yml", "DIGEST"),
                        (".github/workflows/promote.yml", "LATEST_DIGEST")):
            text = (REPO_ROOT / wf).read_text()
            assert f'if [ -z "${var}" ]; then' in text, f"{wf}: empty-digest guard gone"
            assert 'skip=true' in text
