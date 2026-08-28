"""Shared-infra guards every session -- including the non-PE backends -- hits.

The analysis repository is where an r2/ghidra/frida/apk session records which
backend it opened and where its artifacts land, so its listing and GC paths are
part of those flows, not just the debugger's. Two branches there were only ever
driven with a session filter or a valid budget: an unfiltered ``list_backends``
(the audit/console view of every session at once) and ``gc_artifacts`` refusing
a non-positive budget before it deletes oldest-first down to nothing. The
isolation command parser -- run between dynamic samples to roll the sandbox
back -- rejects a NUL only on its Windows path, which a Linux run never reaches.
Each is pinned here so the contract holds regardless of backend or platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import isolation
from headless_re_mcp.core.isolation import IsolationPolicy, _split_command
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store.sqlite_store import SessionStore

_REPOSITORIES = [SqliteAnalysisRepository, InMemoryAnalysisRepository]


# ---------------------------------------------------------------------------
# AnalysisRepository: unfiltered backend listing and the GC budget guard.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("repository_type", _REPOSITORIES)
def test_list_backends_without_a_session_returns_every_session(
    tmp_path: Path, repository_type: type
) -> None:
    """The unfiltered query backs the console/audit view of all sessions at once.

    Every session-scoped call takes the filtered branch; the None case -- one
    ordered list across sessions -- is what an operator reads to see which
    backends are live service-wide, so it has to actually span sessions.
    """
    repository = repository_type(tmp_path / "artifacts")
    repository.record_backend("session-b", "radare2", endpoint="pipe")
    repository.record_backend("session-a", "ghidra", endpoint="proj")
    repository.record_backend("session-a", "frida", pid=4242)

    everything = repository.list_backends()
    kinds = {(row["session_id"], row["kind"]) for row in everything}
    assert kinds == {
        ("session-b", "radare2"),
        ("session-a", "ghidra"),
        ("session-a", "frida"),
    }
    # A filtered read still narrows to the one session, proving the None branch
    # was the wider query and not just the same path.
    only_a = repository.list_backends("session-a")
    assert {row["kind"] for row in only_a} == {"ghidra", "frida"}


@pytest.mark.parametrize("repository_type", _REPOSITORIES)
@pytest.mark.parametrize("budget", [0, -1])
def test_gc_artifacts_refuses_a_non_positive_budget(
    tmp_path: Path, repository_type: type, budget: int
) -> None:
    """A zero/negative budget would delete oldest-first down to nothing.

    The schema caps this at the tool boundary, but the store is reached
    directly by the retention sweep too, so the store itself must refuse rather
    than treat 0 as "keep nothing" and wipe an analysis's evidence.
    """
    repository = repository_type(tmp_path / "artifacts")
    with pytest.raises(ValueError, match="max_total_bytes must be a positive integer"):
        repository.gc_artifacts(max_total_bytes=budget)


@pytest.mark.parametrize("budget", [0, -5])
def test_session_store_gc_refuses_a_non_positive_budget_directly(
    tmp_path: Path, budget: int
) -> None:
    """The repository wrapper guards before delegating, so the store's own guard
    is defense-in-depth: reached only when the backing store is called directly.
    It must refuse the same way rather than deleting oldest-first to nothing.
    """
    store = SessionStore(tmp_path / "sessions.sqlite")
    with pytest.raises(ValueError, match="max_total_bytes must be a positive integer"):
        store.gc_artifacts(max_total_bytes=budget)


# ---------------------------------------------------------------------------
# isolation._split_command: the Windows NUL rejection.
# ---------------------------------------------------------------------------
def test_split_command_rejects_a_nul_on_the_windows_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Windows parser sentinels backslashes with NUL, so a real NUL is
    ambiguous and refused. On Linux the function returns before this branch, so
    it is forced here by pretending to be on Windows.
    """
    monkeypatch.setattr(isolation, "is_windows_host", lambda: True)
    with pytest.raises(ValueError, match="must not contain NUL"):
        _split_command("revert.ps1\x00--now")


def test_split_command_keeps_windows_backslash_paths_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The reason the NUL guard exists: the Windows split sentinels backslashes
    # so shlex does not eat them, then restores them -- a drive path survives.
    monkeypatch.setattr(isolation, "is_windows_host", lambda: True)
    assert _split_command(r'C:\vm\revert.ps1 --snapshot clean') == (
        r"C:\vm\revert.ps1",
        "--snapshot",
        "clean",
    )


def test_from_settings_parses_a_string_command_via_the_splitter() -> None:
    # The public entry point: a string isolation_command is split the way an
    # operator writes it in config; a NUL-free POSIX command round-trips.
    policy = IsolationPolicy.from_settings(
        type("S", (), {"isolation_command": "revert.sh --snapshot clean"})()
    )
    assert policy.command == ("revert.sh", "--snapshot", "clean")
    assert policy.configured is True
