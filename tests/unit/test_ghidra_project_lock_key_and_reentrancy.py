"""The Ghidra project lock must serialize a project, not a path spelling.

A Ghidra project directory is single-writer: two analyzeHeadless JVMs opening
the same project corrupt it or fail on its lock file, which is why
``_project_lock`` serializes runs per project. ``test_ghidra_client.py``
proves two threads on the *same* ``Path`` object serialize, but every caller
there spells the directory identically, so the key normalization in
``_project_lock`` -- ``expanduser().resolve()`` -- is executed without being
observable: strip it out and the suite still passes, while a ``..``, symlink,
or ``~`` spelling of one project would silently get a different lock and run
concurrently. These tests pin the normalization by identity (equivalent
spellings must return the very same lock object) and pin reentrancy: the
export path acquires the lock in ``_export`` and again in ``_run_headless``
on the same thread, so a non-reentrant lock would deadlock every export --
today the suite would only ever notice that as a hang, not a failure.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import _project_lock


def test_a_dot_dot_spelling_of_the_project_maps_to_the_same_lock(
    tmp_path: Path,
) -> None:
    (tmp_path / "sub").mkdir()
    project = tmp_path / "proj"
    project.mkdir()
    spellings = [
        tmp_path / "sub" / ".." / "proj",
        tmp_path / "." / "proj",
        tmp_path / "sub" / ".." / "sub" / ".." / "proj",
    ]
    canonical = _project_lock(project)
    for spelling in spellings:
        assert _project_lock(spelling) is canonical, spelling


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs a privilege on Windows")
def test_a_symlink_spelling_of_the_project_maps_to_the_same_lock(
    tmp_path: Path,
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(project)
    assert _project_lock(alias) is _project_lock(project)


def test_a_tilde_spelling_of_the_project_maps_to_the_same_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # posixpath.expanduser reads HOME; ntpath.expanduser prefers USERPROFILE.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    project = tmp_path / "proj"
    project.mkdir()
    assert _project_lock(Path("~") / "proj") is _project_lock(project)


def test_the_project_lock_is_reentrant_for_the_nested_headless_run(
    tmp_path: Path,
) -> None:
    """``_export`` holds the lock when ``_run_headless`` re-acquires it.

    Both acquisitions happen on the same thread of one export call, so the
    lock must be reentrant; with a plain ``Lock`` the second acquire below
    returns False -- and in production the export blocks forever. Asserting
    it here turns that deadlock into a fast, named failure.
    """
    lock = _project_lock(tmp_path / "proj")
    assert lock.acquire(blocking=False)
    try:
        nested = lock.acquire(blocking=False)
        assert nested, "the export path re-acquires the project lock on the same thread"
        lock.release()
    finally:
        lock.release()
