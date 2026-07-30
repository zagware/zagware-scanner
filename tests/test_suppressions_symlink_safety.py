"""Tests for SEC-04: .zagware/suppressions.yaml must never be read or written
through a symlink, and must never resolve outside the scanned repository.

Threat model: a hostile PR contributor with no privilege beyond opening a PR
commits .zagware/suppressions.yaml (or the .zagware directory itself) as a
symlink to an arbitrary path. Git checks out symlinks verbatim, so nothing
upstream of these functions stops that. Without this guard: (1) arbitrary
file READ — the target's content gets parsed as key:value pairs and any
"reason"-shaped value is uploaded to the platform; (2) arbitrary file WRITE
as root — once any suppress command resolves, the scanner truncates and
rewrites the symlink target; (3) DoS — a symlink to /dev/zero never returns
from read().
"""
from __future__ import annotations

import os

import pytest

import scanner


def _make_repo(tmp_path, name="repo"):
    """A plain directory standing in for a cloned PR worktree — no real git
    needed for these tests, since the symlink guard fires before any git
    operation runs."""
    d = tmp_path / name
    d.mkdir()
    return d


class TestSafeReadSuppressionsFile:
    def test_returns_none_when_file_does_not_exist(self, tmp_path):
        repo = _make_repo(tmp_path)
        assert scanner._safe_read_suppressions_file(str(repo)) is None

    def test_reads_a_normal_regular_file(self, tmp_path):
        repo = _make_repo(tmp_path)
        (repo / ".zagware").mkdir()
        (repo / ".zagware" / "suppressions.yaml").write_text("- id: abc123\n  reason: \"fine\"\n")
        text = scanner._safe_read_suppressions_file(str(repo))
        assert text is not None
        assert "abc123" in text

    def test_refuses_symlink_to_file_outside_repo(self, tmp_path):
        """The exact SEC-04 attack: exfiltrate an arbitrary file's content by
        symlinking suppressions.yaml at it."""
        repo = _make_repo(tmp_path)
        (repo / ".zagware").mkdir()
        secret = tmp_path / "secret_outside_repo.txt"
        secret.write_text("reason: \"this should never be readable\"\n")

        os.symlink(secret, repo / ".zagware" / "suppressions.yaml")

        assert scanner._safe_read_suppressions_file(str(repo)) is None

    def test_refuses_symlink_to_file_inside_repo_too(self, tmp_path):
        """Even an in-bounds symlink is rejected — the rule is "no symlinks
        at all", not "symlinks must stay in bounds", since a legitimate
        suppressions.yaml is never a symlink."""
        repo = _make_repo(tmp_path)
        (repo / ".zagware").mkdir()
        decoy = repo / "decoy.yaml"
        decoy.write_text("- id: abc123\n  reason: \"x\"\n")
        os.symlink(decoy, repo / ".zagware" / "suppressions.yaml")

        assert scanner._safe_read_suppressions_file(str(repo)) is None

    def test_refuses_when_zagware_directory_itself_is_a_symlink(self, tmp_path):
        """A symlinked .zagware/ (not just the leaf file) escaping the repo
        must also be caught by the containment check, since is_symlink() on
        the leaf alone would be False in this case."""
        repo = _make_repo(tmp_path)
        outside = tmp_path / "outside_dir"
        outside.mkdir()
        (outside / "suppressions.yaml").write_text("- id: abc123\n  reason: \"leak\"\n")

        os.symlink(outside, repo / ".zagware", target_is_directory=True)

        assert scanner._safe_read_suppressions_file(str(repo)) is None

    def test_refuses_file_larger_than_size_cap(self, tmp_path, reload_scanner):
        mod = reload_scanner()
        repo = _make_repo(tmp_path)
        (repo / ".zagware").mkdir()
        big = "a" * (mod._MAX_SUPPRESSIONS_FILE_SIZE + 100)
        (repo / ".zagware" / "suppressions.yaml").write_text(big)

        assert mod._safe_read_suppressions_file(str(repo)) is None

    def test_load_suppressions_returns_empty_set_for_symlinked_file(self, tmp_path):
        """End-to-end through the real consumer: load_suppressions() must not
        surface any ids from a symlinked file."""
        repo = _make_repo(tmp_path)
        (repo / ".zagware").mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("- id: deadbeef01\n  reason: \"leaked\"\n")
        os.symlink(secret, repo / ".zagware" / "suppressions.yaml")

        assert scanner.load_suppressions(str(repo)) == set()


class TestApplySuppressionCommandsRefusesSymlinkWrite:
    def test_refuses_to_write_through_a_symlink(self, tmp_path):
        """The write-side half of SEC-04: even an authorized, correctly
        resolved suppress command must not truncate-and-rewrite a symlink
        target — that would be a root-level arbitrary write inside the
        container for anyone who can open a PR."""
        repo = _make_repo(tmp_path)
        (repo / ".zagware").mkdir()
        decoy = tmp_path / "decoy_outside_repo.txt"
        decoy.write_text("do not touch me")
        os.symlink(decoy, repo / ".zagware" / "suppressions.yaml")

        pushed = scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature-branch",
            [("deadbeef01", "accepted risk", "attacker", "2026-01-01T00:00:00Z")],
        )

        assert pushed is False
        assert decoy.read_text() == "do not touch me"  # untouched
        assert os.path.islink(repo / ".zagware" / "suppressions.yaml")  # untouched

    def test_refuses_when_zagware_directory_is_a_symlink(self, tmp_path):
        repo = _make_repo(tmp_path)
        outside = tmp_path / "outside_dir"
        outside.mkdir()
        os.symlink(outside, repo / ".zagware", target_is_directory=True)

        pushed = scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature-branch",
            [("deadbeef01", "accepted risk", "attacker", "2026-01-01T00:00:00Z")],
        )

        assert pushed is False
        assert list(outside.iterdir()) == []  # nothing was created through the symlink

    def test_writes_normally_when_no_symlink_is_involved(self, tmp_path, monkeypatch):
        """Positive-path control: the guard must not block the ordinary case.
        Stubs out the git operations (that's existing, unchanged behaviour,
        not part of this fix) to isolate the write-path assertion."""
        repo = _make_repo(tmp_path)

        calls = []
        monkeypatch.setattr(scanner, "_git", lambda args, cwd=None, env=None: calls.append(args))

        pushed = scanner.apply_suppression_commands(
            str(repo), "https://example.invalid/repo.git", "feature-branch",
            [("deadbeef01", "accepted risk", "maintainer", "2026-01-01T00:00:00Z")],
        )

        assert pushed is True
        content = (repo / ".zagware" / "suppressions.yaml").read_text()
        assert "deadbeef01" in content
        assert any(a[:1] == ["push"] for a in calls)


# NOTE: TestBlameSuppressionsFileRefusesSymlink was removed alongside
# _blame_suppressions_file() itself. SEC-10 deleted that git-blame attribution
# fallback outright rather than relabelling it: the scanner clones with
# --depth=1, so blame attributes every line to the single checked-out commit
# and credited whoever pushed last for suppressions added long before. Its
# symlink guard is therefore moot -- there is no longer any code path that
# shells out to `git blame` against the scanned worktree. The read/write
# symlink guards above still cover every remaining path that touches
# .zagware/suppressions.yaml.
