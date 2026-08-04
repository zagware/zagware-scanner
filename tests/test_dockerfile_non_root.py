"""Test for SUP-06: the runtime image must drop to a non-root user before
ENTRYPOINT runs.

Before the fix there was no USER directive anywhere in the Dockerfile, so
ENTRYPOINT ["python3", "/usr/local/bin/zagware-scan"] executed as uid 0 --
this image clones untrusted pull-request content and runs four third-party
binaries (kics, syft, grype, betterleaks) directly over it, so a parser bug
in any of them became root-in-container rather than an unprivileged crash.

A full docker build + `id`/binary-execution/bytecode-cache check was run
manually during development (not reproduced here -- these tests avoid a
hard Docker dependency in the unit suite); this file locks in the specific,
cheaply-checkable structural property: a non-root USER directive exists in
the final stage and takes effect before the entrypoint process starts.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _final_stage_lines() -> list[str]:
    """Return the Dockerfile lines belonging to the final (runtime) stage --
    everything after the last `FROM`, which is the non-builder stage."""
    lines = (REPO_ROOT / "Dockerfile").read_text().splitlines()
    from_indices = [i for i, l in enumerate(lines) if l.strip().upper().startswith("FROM ")]
    assert from_indices, "no FROM instruction found in Dockerfile"
    return lines[from_indices[-1]:]


class TestNonRootUser:
    def test_final_stage_declares_a_user_directive(self):
        stage = _final_stage_lines()
        user_lines = [l for l in stage if l.strip().upper().startswith("USER ")]
        assert user_lines, "final stage has no USER directive -- runs as root"

    def test_user_is_not_root(self):
        stage = _final_stage_lines()
        user_lines = [l.strip() for l in stage if l.strip().upper().startswith("USER ")]
        for line in user_lines:
            user = line.split(None, 1)[1].strip()
            assert user not in ("root", "0", "0:0"), f"USER directive sets root: {line!r}"

    def test_user_directive_precedes_entrypoint(self):
        """A USER directive after ENTRYPOINT would never take effect for the
        entrypoint process -- order matters."""
        stage = _final_stage_lines()
        user_idx = next(
            (i for i, l in enumerate(stage) if l.strip().upper().startswith("USER ")), None
        )
        entrypoint_idx = next(
            (i for i, l in enumerate(stage) if l.strip().upper().startswith("ENTRYPOINT")), None
        )
        assert user_idx is not None, "no USER directive in final stage"
        assert entrypoint_idx is not None, "no ENTRYPOINT in final stage"
        assert user_idx < entrypoint_idx, (
            "USER directive must appear before ENTRYPOINT to actually apply to it"
        )

    def test_copied_binaries_and_entrypoint_are_world_executable(self):
        """COPY without --chmod inherits the source's mode, which may not be
        world-readable/executable -- the non-root user needs to actually run
        these. Every binary/asset COPY in the final stage must be explicit."""
        stage = _final_stage_lines()
        copy_lines = [
            l for l in stage
            if l.strip().upper().startswith("COPY") and "--from=builder" in l or
               (l.strip().upper().startswith("COPY") and "scanner.py" in l)
        ]
        assert copy_lines, "expected COPY instructions for the bundled binaries in the final stage"
        for line in copy_lines:
            assert "--chmod=" in line, f"COPY lacks an explicit --chmod: {line!r}"


class TestBaseImagePinnedByDigest:
    """SUP-10: every stage must pin its base image by digest, not by a mutable
    tag -- the same argument the Dockerfile already makes for pinning KICS by
    commit SHA (a repointed tag or compromised registry namespace would
    substitute ca-certificates, git, python3, or the Go toolchain that compiles
    KICS, with no tracked-line change and no CI check noticing)."""

    def _resolved_from_lines(self) -> list[str]:
        """FROM lines with any leading ARG default (e.g. ${DEBIAN_DIGEST})
        substituted in, mirroring how Docker itself resolves a global ARG
        used in a FROM instruction."""
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

    def test_every_from_instruction_pins_a_digest(self):
        from_lines = self._resolved_from_lines()
        assert from_lines, "no FROM instructions found"
        for line in from_lines:
            assert "@sha256:" in line, f"FROM instruction is not pinned by digest: {line!r}"

    def test_every_base_digest_comes_from_a_named_arg(self):
        """Originally this asserted all stages pinned the SAME digest, which
        made sense when there were two Debian stages. There are now three
        deliberately different bases -- Wolfi at runtime (its OS packages
        contributed 105 unfixable critical/high CVEs on Debian), Debian for the
        dpkg-based download stage, and a Go toolchain to build KICS from source
        -- so sameness is the wrong invariant.

        What still matters is that no digest is hardcoded inline: each base has
        exactly one ARG to edit when re-pinning, so a stale pin cannot hide in
        the middle of the file.
        """
        text = (REPO_ROOT / "Dockerfile").read_text()
        raw_froms = [l.strip() for l in text.splitlines()
                     if l.strip().upper().startswith("FROM ")]
        for line in raw_froms:
            assert "${" in line, (
                f"FROM pins a digest inline instead of via an ARG: {line!r}"
            )
        for line in self._resolved_from_lines():
            assert "@sha256:" in line, f"unresolved base pin: {line!r}"
