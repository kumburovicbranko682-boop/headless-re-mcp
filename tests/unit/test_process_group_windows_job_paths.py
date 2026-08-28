"""Hermetic coverage for the Windows job-object paths of process_group.

``assign_to_process_group`` is the safety net that makes a spawned child die
with this process on Windows. Its failure handling is exactly the part that
matters -- the module's own docstring says a net that is quietly missing is
worse than one that is loudly absent -- yet those branches only ever ran on a
real Windows box (test_supervisor pins the happy path there, skipped
everywhere else). A regression in the latching or the one-time alert would
ship silently through Linux CI.

These tests drive the real module logic on any platform by pretending
``os.name == "nt"`` and substituting kernel32 with a scripted fake, pinning:

* the job handle is created once and cached across assignments;
* creation/SetInformation failures latch ``_unavailable`` so kernel32 is not
  re-probed on every spawn, and the job handle is not leaked;
* per-pid refusals (OpenProcess, AssignProcessToJobObject) do not latch --
  the next pid must still get its chance;
* the "children will outlive us" alert fires exactly once per process, with
  the consequence spelled out;
* the process handle opened for assignment is closed on success and refusal.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from headless_re_mcp import process_group


class _OsProxy:
    """A stand-in ``os`` module with a pinned ``name``.

    Patching the global ``os.name`` would poison ``pathlib.Path`` on Python
    3.11, where ``Path()`` picks WindowsPath (uninstantiable on POSIX) from
    ``os.name``; a failing test would then crash pytest's own failure
    reporting. The proxy pins what ``process_group`` reads and forwards the
    rest to the real module.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> object:
        return getattr(os, attr)


_JOB_HANDLE = 0x40
_PROC_HANDLE = 0x90


class _FakeKernel32:
    """Scripted stand-in for the four kernel32 calls the module makes."""

    def __init__(
        self,
        *,
        create_handle: int = _JOB_HANDLE,
        set_ok: bool = True,
        open_handle: int = _PROC_HANDLE,
        assign_ok: bool = True,
        open_raises: Exception | None = None,
    ) -> None:
        self.create_calls = 0
        self.opened_pids: list[int] = []
        self.assigned: list[tuple[int, int]] = []
        self.closed: list[int] = []
        self._create_handle = create_handle
        self._set_ok = set_ok
        self._open_handle = open_handle
        self._assign_ok = assign_ok
        self._open_raises = open_raises

    def CreateJobObjectW(self, security: object, name: object) -> int:  # noqa: N802
        del security, name
        self.create_calls += 1
        return self._create_handle

    def SetInformationJobObject(  # noqa: N802
        self, handle: int, info_class: int, info: object, size: int
    ) -> int:
        del handle, info_class, info, size
        return 1 if self._set_ok else 0

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:  # noqa: N802
        del access, inherit
        if self._open_raises is not None:
            raise self._open_raises
        self.opened_pids.append(pid)
        return self._open_handle

    def AssignProcessToJobObject(self, job: int, handle: int) -> int:  # noqa: N802
        self.assigned.append((int(job), int(handle)))
        return 1 if self._assign_ok else 0

    def CloseHandle(self, handle: int) -> int:  # noqa: N802
        self.closed.append(int(handle))
        return 1


@pytest.fixture(autouse=True)
def _fresh_module_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with no cached job, no latch, and no alert sent."""
    monkeypatch.setattr(process_group, "_job", None)
    monkeypatch.setattr(process_group, "_unavailable", False)
    monkeypatch.setattr(process_group, "_reported", False)


@pytest.fixture()
def alerts(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    seen: list[tuple[str, dict[str, Any]]] = []

    def _record(
        kind: str, *, severity: str = "warning", fields: dict[str, Any] | None = None
    ) -> None:
        del severity
        seen.append((kind, dict(fields or {})))

    monkeypatch.setattr(process_group, "record_alert", _record)
    return seen


def _pretend_windows(monkeypatch: pytest.MonkeyPatch, fake: _FakeKernel32 | None) -> None:
    monkeypatch.setattr(process_group, "os", _OsProxy("nt"))
    if fake is not None:
        monkeypatch.setattr(process_group, "_kernel32", lambda: fake)


def test_success_assigns_to_the_job_and_closes_only_the_process_handle(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """The job handle must stay open -- KILL_ON_JOB_CLOSE means closing it
    kills every child -- while the per-pid process handle must not leak."""
    fake = _FakeKernel32()
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is True

    assert fake.opened_pids == [4242]
    assert fake.assigned == [(_JOB_HANDLE, _PROC_HANDLE)]
    assert fake.closed == [_PROC_HANDLE]
    assert alerts == []


def test_the_job_is_created_once_and_cached_across_assignments(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    fake = _FakeKernel32()
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(101) is True
    assert process_group.assign_to_process_group(202) is True

    assert fake.create_calls == 1
    assert fake.opened_pids == [101, 202]
    assert alerts == []


@pytest.mark.parametrize("pid", [0, -1])
def test_nonpositive_pids_are_refused_before_any_kernel32_call(
    monkeypatch: pytest.MonkeyPatch, pid: int
) -> None:
    monkeypatch.setattr(process_group, "os", _OsProxy("nt"))

    def _boom() -> object:
        raise AssertionError("kernel32 must not be touched for a bogus pid")

    monkeypatch.setattr(process_group, "_kernel32", _boom)

    assert process_group.assign_to_process_group(pid) is False


def test_job_creation_failure_latches_and_alerts_exactly_once(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """CreateJobObjectW returning NULL flips the module to unavailable: later
    spawns must not re-probe kernel32, and the operator hears about it once."""
    fake = _FakeKernel32(create_handle=0)
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is False
    assert process_group.assign_to_process_group(4243) is False

    assert fake.create_calls == 1, "the unavailable latch must stop re-probing"
    assert len(alerts) == 1
    kind, fields = alerts[0]
    assert kind == "process_group_unavailable"
    assert fields["detail"] == "the process job could not be created"
    assert fields["consequence"] == ("spawned processes will survive if this one is killed")


def test_set_information_failure_closes_the_job_handle_and_latches(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """A job without KILL_ON_JOB_CLOSE is useless; the half-built handle must
    be released rather than leaked, and the module must latch unavailable."""
    fake = _FakeKernel32(set_ok=False)
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is False

    assert fake.closed == [_JOB_HANDLE]
    assert process_group._unavailable is True
    assert len(alerts) == 1


@pytest.mark.skipif(os.name == "nt", reason="pins the no-WinDLL degradation, POSIX only")
def test_missing_windll_is_caught_and_degrades_to_a_single_alert(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """With ``os.name`` claiming Windows but no real WinDLL available, the
    AttributeError from ctypes must be swallowed into the unavailable latch --
    the safety net degrades loudly-once instead of crashing the spawn."""
    _pretend_windows(monkeypatch, None)

    assert process_group.assign_to_process_group(4242) is False

    assert process_group._unavailable is True
    assert [kind for kind, _ in alerts] == ["process_group_unavailable"]


def test_open_process_failure_reports_but_does_not_latch_the_job(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """Failing to open one pid is a property of that pid (it may already be
    gone), not of the machine: the cached job must keep serving later pids."""
    fake = _FakeKernel32(open_handle=0)
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is False
    assert alerts[0][0] == "process_group_unavailable"
    assert "cannot open pid 4242" in alerts[0][1]["detail"]
    assert process_group._unavailable is False

    # The same job serves the next pid once opening succeeds again.
    fake._open_handle = _PROC_HANDLE
    assert process_group.assign_to_process_group(4243) is True
    assert fake.create_calls == 1


def test_assignment_refusal_reports_and_closes_the_process_handle(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """AssignProcessToJobObject refusing (nested-job forbidden) must not leak
    the opened handle, and the alert must name the likely cause."""
    fake = _FakeKernel32(assign_ok=False)
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is False

    assert fake.closed == [_PROC_HANDLE]
    assert len(alerts) == 1
    assert "refused by the job" in alerts[0][1]["detail"]


def test_kernel32_exception_during_open_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """The net is best effort: an OSError out of kernel32 must become a False
    plus one alert, never an exception into the spawn path."""
    fake = _FakeKernel32(open_raises=OSError("access denied"))
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is False

    assert len(alerts) == 1
    assert "OSError" in alerts[0][1]["detail"]


def test_the_alert_fires_only_for_the_first_failure(
    monkeypatch: pytest.MonkeyPatch, alerts: list[tuple[str, dict[str, Any]]]
) -> None:
    """Two different refusals still produce one alert: the report is about the
    machine losing its net, not a per-child event stream."""
    fake = _FakeKernel32(open_handle=0)
    _pretend_windows(monkeypatch, fake)

    assert process_group.assign_to_process_group(4242) is False
    fake._assign_ok = False
    fake._open_handle = _PROC_HANDLE
    assert process_group.assign_to_process_group(4243) is False

    assert len(alerts) == 1
