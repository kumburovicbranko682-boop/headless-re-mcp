"""Coverage for the desktop-isolation job and the input-desktop window sweep.

The job object is what stops ``MB_SERVICE_NOTIFICATION`` from switching onto
the operator's desktop, so every refusal arm matters: a job that silently
failed to apply its UI restrictions would report isolation while providing
none. The Win32 calls are faked (the same pattern as the process-tree and
x64dbg transport tests) so each arm runs anywhere.
"""

from __future__ import annotations

import os
import types
from typing import Any

import pytest

import headless_re_mcp.core.desktop_isolation as iso


class _NtOsProxy:
    """Report ``name == "nt"`` while forwarding everything else to the real os."""

    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


def _pretend_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(iso, "os", _NtOsProxy())


def _install_windll(monkeypatch: pytest.MonkeyPatch, tables: dict[str, Any]) -> None:
    monkeypatch.setattr(
        iso.ctypes,
        "WinDLL",
        lambda name, use_last_error=False: tables[name],
        raising=False,
    )


# --------------------------------------------------------------------------- #
# DesktopIsolationJob.create
# --------------------------------------------------------------------------- #


def test_create_declines_off_windows() -> None:
    assert iso.DesktopIsolationJob.create() is None


def test_create_builds_a_job_with_both_limit_sets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied: list[int] = []

    def set_information(handle: Any, info_class: int, payload: Any, size: int) -> int:
        applied.append(info_class)
        return 1

    kernel32 = types.SimpleNamespace(
        CreateJobObjectW=lambda security, name: 555,
        SetInformationJobObject=set_information,
        CloseHandle=lambda handle: 1,
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})

    job = iso.DesktopIsolationJob.create()

    assert job is not None
    assert job._handle == 555
    assert applied == [
        iso._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        iso._JOB_OBJECT_BASIC_UI_RESTRICTIONS,
    ], "kill-on-close and the UI restrictions must both be applied"


def test_create_declines_when_the_job_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = types.SimpleNamespace(CreateJobObjectW=lambda security, name: 0)
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})
    assert iso.DesktopIsolationJob.create() is None


@pytest.mark.parametrize("failing_call", [1, 2])
def test_create_closes_the_handle_when_a_limit_cannot_be_applied(
    monkeypatch: pytest.MonkeyPatch, failing_call: int
) -> None:
    """A job without its restrictions is worse than no job: it must not be returned."""
    closed: list[Any] = []
    calls = {"n": 0}

    def set_information(handle: Any, info_class: int, payload: Any, size: int) -> int:
        calls["n"] += 1
        return 0 if calls["n"] == failing_call else 1

    kernel32 = types.SimpleNamespace(
        CreateJobObjectW=lambda security, name: 555,
        SetInformationJobObject=set_information,
        CloseHandle=lambda handle: closed.append(handle) or 1,
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})

    assert iso.DesktopIsolationJob.create() is None
    assert closed == [555]


def test_create_closes_the_handle_when_the_limit_call_explodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[Any] = []

    def set_information(*args: Any) -> int:
        raise OSError("job API rejected the structure")

    kernel32 = types.SimpleNamespace(
        CreateJobObjectW=lambda security, name: 555,
        SetInformationJobObject=set_information,
        CloseHandle=lambda handle: closed.append(handle) or 1,
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})

    assert iso.DesktopIsolationJob.create() is None
    assert closed == [555]


# --------------------------------------------------------------------------- #
# assign / close
# --------------------------------------------------------------------------- #


def test_assign_declines_bad_pids_and_a_closed_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = iso.DesktopIsolationJob(555)
    assert job.assign(4242) is False, "off Windows the assign must refuse"

    _pretend_windows(monkeypatch)
    assert job.assign(0) is False
    assert job.assign("7") is False  # type: ignore[arg-type]
    assert iso.DesktopIsolationJob(0).assign(4242) is False


def test_assign_places_the_process_into_the_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, Any]] = []
    kernel32 = types.SimpleNamespace(
        OpenProcess=lambda access, inherit, pid: 777,
        AssignProcessToJobObject=lambda job, process: events.append(("assign", process)) or 1,
        CloseHandle=lambda handle: events.append(("close", handle)) or 1,
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})

    assert iso.DesktopIsolationJob(555).assign(4242) is True
    assert events == [("assign", 777), ("close", 777)]


def test_assign_declines_a_process_it_cannot_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32 = types.SimpleNamespace(OpenProcess=lambda access, inherit, pid: 0)
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})
    assert iso.DesktopIsolationJob(555).assign(4242) is False


def test_close_releases_the_handle_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[Any] = []
    kernel32 = types.SimpleNamespace(CloseHandle=lambda handle: closed.append(handle) or 1)
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"kernel32": kernel32})

    job = iso.DesktopIsolationJob(555)
    job.close()
    job.close()  # the second close must not double-free

    assert closed == [555]
    assert job._handle == 0


def test_close_is_a_noop_off_windows() -> None:
    job = iso.DesktopIsolationJob(555)
    job.close()
    assert job._handle == 0


# --------------------------------------------------------------------------- #
# hide_input_desktop_windows_for_pids
# --------------------------------------------------------------------------- #


def test_hide_declines_off_windows() -> None:
    assert iso.hide_input_desktop_windows_for_pids([4242]) == []


def test_hide_declines_without_any_valid_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    _pretend_windows(monkeypatch)
    assert iso.hide_input_desktop_windows_for_pids([0, -3, "7"]) == []  # type: ignore[list-item]


def test_hide_hides_each_window_owned_by_the_allowed_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, int]] = []
    user32 = types.SimpleNamespace(
        ShowWindow=lambda hwnd, cmd: events.append(("show", hwnd)) or 1,
        SetWindowPos=lambda hwnd, after, x, y, w, h, flags: events.append(("pos", hwnd)) or 1,
    )
    _pretend_windows(monkeypatch)
    _install_windll(monkeypatch, {"user32": user32})
    monkeypatch.setattr(
        iso,
        "list_windows_for_pids",
        lambda pids: [{"hwnd": 11}, {"hwnd": 22}] if pids == [4242] else [],
    )

    hidden = iso.hide_input_desktop_windows_for_pids([4242, 4242, 0])

    assert hidden == [11, 22]
    assert events == [("show", 11), ("pos", 11), ("show", 22), ("pos", 22)]
