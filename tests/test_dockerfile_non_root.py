"""Test for SUP-06: the runtime image must drop to a non-root user before
ENTRYPOINT runs, plus SUP-10: every external base image is digest-pinned.

Before the SUP-06 fix there was no USER directive anywhere in the Dockerfile, so
ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"] executed as uid 0 -- this
image clones untrusted pull-request content and runs third-party binaries (kics,
syft, grype, betterleaks, osv-scanner) directly over it, so a parser bug in any
of them became root-in-container rather than an unprivileged crash.

The Dockerfile is now multi-stage with two shipped runtime images built from a
shared `base-min` stage: the minimal `core` (default) and the opt-in
`reachability` variant. The security properties locked in here therefore apply
to `base-min` (which declares ENTRYPOINT and is inherited by both) and to the
`reachability` stage, which re-drops to non-root after installing its extra
toolchain. A full docker build + `id`/binary-execution check is run in ci.yml;
this file locks the cheaply-checkable structural properties.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _stages() -> dict[str, list[str]]:
    """Map each stage name to its Dockerfile lines. A stage's name is the token
    after `AS`, or the image ref if unnamed."""
    lines = (REPO_ROOT / "Dockerfile").read_text().splitlines()
    stages: dict[str, list[str]] = {}
    cur: str | None = None
    for line in lines:
        toks = line.strip().split()
        if toks and toks[0].upper() == "FROM":
            upper = [t.upper() for t in toks]
            cur = toks[upper.index("AS") + 1] if "AS" in upper else toks[1]
            stages[cur] = [line]
        elif cur is not None:
            stages[cur].append(line)
    return stages


def _stage_names() -> set[str]:
    return set(_stages().keys())


def _runtime_stage_lines() -> list[str]:
    """The stage that declares ENTRYPOINT -- the canonical runtime image
    (base-min). `core` and `reachability` inherit from it via FROM base-min."""
    for lines in _stages().values():
        if any(l.strip().upper().startswith("ENTRYPOINT") for l in lines):
            return lines
    raise AssertionError("no stage declares ENTRYPOINT")


def _derived_runtime_stages() -> dict[str, list[str]]:
    """Runtime stages that derive from a local stage (FROM <stage-name>) and are
    actually shipped -- i.e. `core` and `reachability`, not the build stages."""
    names = _stage_names()
    out: dict[str, list[str]] = {}
    for name, lines in _stages().items():
        img = lines[0].strip().split()[1]
        if img in names:
            out[name] = lines
    return out


class TestNonRootUser:
    def test_final_stage_declares_a_user_directive(self):
        stage = _runtime_stage_lines()
        user_lines = [l for l in stage if l.strip().upper().startswith("USER ")]
        assert user_lines, "runtime stage has no USER directive -- runs as root"

    def test_user_is_not_root(self):
        # The EFFECTIVE (last) USER of every runtime stage must be non-root. A
        # mid-stage `USER root` is fine (reachability installs its toolchain as
        # root) as long as it drops back before the stage ends.
        stages = [_runtime_stage_lines()] + list(_derived_runtime_stages().values())
        for stage in stages:
            user_lines = [l.strip() for l in stage if l.strip().upper().startswith("USER ")]
            if not user_lines:
                continue  # inherits its base stage's (already-checked) USER
            user = user_lines[-1].split(None, 1)[1].strip()
            assert user not in ("root", "0", "0:0"), f"stage's effective USER is root: {user_lines[-1]!r}"

    def test_reachability_stage_ends_non_root(self):
        """The reachability variant switches to root to apk-add its toolchain --
        it MUST switch back before it becomes a runnable image."""
        reach = _derived_runtime_stages().get("reachability")
        assert reach, "no reachability stage found"
        user_lines = [l.strip() for l in reach if l.strip().upper().startswith("USER ")]
        assert user_lines, "reachability stage installs as root but never drops back"
        last_user = user_lines[-1].split(None, 1)[1].strip()
        assert last_user not in ("root", "0", "0:0"), (
            f"reachability stage's final USER is root: {user_lines[-1]!r}"
        )

    def test_user_directive_precedes_entrypoint(self):
        """A USER directive after ENTRYPOINT would never take effect for the
        entrypoint process -- order matters."""
        stage = _runtime_stage_lines()
        user_idx = next(
            (i for i, l in enumerate(stage) if l.strip().upper().startswith("USER ")), None
        )
        entrypoint_idx = next(
            (i for i, l in enumerate(stage) if l.strip().upper().startswith("ENTRYPOINT")), None
        )
        assert user_idx is not None, "no USER directive in runtime stage"
        assert entrypoint_idx is not None, "no ENTRYPOINT in runtime stage"
        assert user_idx < entrypoint_idx, (
            "USER directive must appear before ENTRYPOINT to actually apply to it"
        )

    def test_copied_binaries_and_entrypoint_are_world_executable(self):
        """COPY without --chmod inherits the source's mode, which may not be
        world-readable/executable -- the non-root user needs to run these. Every
        binary/asset COPY across the runtime stages must be explicit."""
        stages = [_runtime_stage_lines()] + list(_derived_runtime_stages().values())
        copy_lines = []
        for stage in stages:
            for l in stage:
                s = l.strip()
                if not s.upper().startswith("COPY"):
                    continue
                if "--from=" in s or "scanner.py" in s:
                    copy_lines.append(l)
        assert copy_lines, "expected COPY instructions for the bundled binaries in the runtime stages"
        for line in copy_lines:
            assert "--chmod=" in line, f"COPY lacks an explicit --chmod: {line!r}"


class TestBaseImagePinnedByDigest:
    """SUP-10: every EXTERNAL base image must pin its digest via an ARG, not a
    mutable tag. Stages that derive from a local stage (FROM <stage-name>) are
    exempt -- they inherit the already-pinned base and introduce no new registry
    pull."""

    def _resolved_from_lines(self) -> list[str]:
        lines = (REPO_ROOT / "Dockerfile").read_text().splitlines()
        args = {}
        for line in lines:
            stripped = line.strip()
            if stripped.upper().startswith("ARG ") and "=" in stripped:
                name, _, value = stripped[4:].partition("=")
                args[name.strip()] = value.strip()
        from_lines = [l.strip() for l in lines if l.strip().upper().startswith("FROM ")]
        resolved = []
        for line in from_lines:
            for name, value in args.items():
                line = line.replace("${%s}" % name, value).replace("$%s" % name, value)
            resolved.append(line)
        return resolved

    def _external_from_lines(self) -> list[str]:
        """FROM lines that pull a registry image, excluding FROM <local-stage>."""
        names = _stage_names()
        out = []
        for line in self._resolved_from_lines():
            img = line.split()[1]
            if img in names:  # derives from a prior stage -- no registry pull
                continue
            out.append(line)
        return out

    def test_every_external_from_pins_a_digest(self):
        from_lines = self._external_from_lines()
        assert from_lines, "no external FROM instructions found"
        for line in from_lines:
            assert "@sha256:" in line, f"external FROM is not pinned by digest: {line!r}"

    def test_every_base_digest_comes_from_a_named_arg(self):
        """No digest hardcoded inline: each external base has exactly one ARG to
        edit when re-pinning, so a stale pin cannot hide in the middle of the
        file. Local-stage derivations (FROM base-min) carry no digest and are
        excluded."""
        names = _stage_names()
        raw_froms = [l.strip() for l in (REPO_ROOT / "Dockerfile").read_text().splitlines()
                     if l.strip().upper().startswith("FROM ")]
        for line in raw_froms:
            if line.split()[1] in names:
                continue
            assert "${" in line, f"external FROM pins a digest inline instead of via an ARG: {line!r}"
        for line in self._external_from_lines():
            assert "@sha256:" in line, f"unresolved base pin: {line!r}"
