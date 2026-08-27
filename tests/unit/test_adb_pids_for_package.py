"""``_pids_for_package`` is the sole source of truth for "did force-stop work?".

``device.force_stop`` reports honestly only because this parser distinguishes
three outcomes on a device it cannot fully trust:

* a list of pids  -> the process is still up (``stopped: False``),
* an empty list    -> confirmed gone (``stopped: True``),
* ``None``         -> the probe itself could not run (``stopped: None`` +
  "could not read process list").

Collapse ``None`` into ``[]`` and force-stop would claim success on a read it
never made; collapse ``[]`` into ``None`` and it would hedge on a process it
watched leave. The function also has to survive a device whose ``pidof`` is
missing (older/minimal Android) by falling back to a ``ps -A`` scan, and cap
that scan so a runaway process table cannot return an unbounded list. All of
that ran only behind a live device before, so none of it was pinned. These
tests drive it with a stubbed device shell -- no adbutils, no device.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.backends.adb.client as adb
from headless_re_mcp.backends.adb.client import AdbError, _pids_for_package

_PKG = "com.example.app"


def _shell(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pidof: str | AdbError,
    ps: str | AdbError | None = None,
) -> None:
    """Route ``pidof <pkg>`` and ``ps -A`` to canned output (or a raised AdbError)."""

    def fake_shell(dev: Any, args: Any, *, timeout: float = 30.0) -> str:
        del dev, timeout
        if isinstance(args, list) and args[:1] == ["pidof"]:
            if isinstance(pidof, AdbError):
                raise pidof
            return pidof
        if args == "ps -A":
            if ps is None:
                raise AssertionError("ps -A was called but no ps output was configured")
            if isinstance(ps, AdbError):
                raise ps
            return ps
        raise AssertionError(f"unexpected shell command: {args!r}")

    monkeypatch.setattr(adb, "_device_shell", fake_shell)


def test_space_separated_pids_parse_to_ints(monkeypatch: pytest.MonkeyPatch) -> None:
    _shell(monkeypatch, pidof="1234 5678")
    assert _pids_for_package(object(), _PKG) == [1234, 5678]


def test_comma_separated_pids_parse_to_ints(monkeypatch: pytest.MonkeyPatch) -> None:
    _shell(monkeypatch, pidof="1234, 5678")
    assert _pids_for_package(object(), _PKG) == [1234, 5678]


def test_a_single_pid_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    _shell(monkeypatch, pidof="42\n")
    assert _pids_for_package(object(), _PKG) == [42]


def test_empty_pidof_output_is_confirmed_not_running(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty stdout is "process not running", which must be [] not None."""
    _shell(monkeypatch, pidof="   \n  ")
    assert _pids_for_package(object(), _PKG) == []


def test_non_numeric_pidof_noise_is_undeterminable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-empty output with no digits and no not-found marker is None, not []."""
    _shell(monkeypatch, pidof="usage: pidof [-s] name")
    assert _pids_for_package(object(), _PKG) is None


def test_a_pidof_probe_error_is_undeterminable(monkeypatch: pytest.MonkeyPatch) -> None:
    _shell(monkeypatch, pidof=AdbError("timeout", "adb timed out"))
    assert _pids_for_package(object(), _PKG) is None


@pytest.mark.parametrize("marker", ["not found", "unknown option", "no such tool"])
def test_a_missing_pidof_falls_back_to_ps_and_reads_the_pid_column(
    monkeypatch: pytest.MonkeyPatch, marker: str
) -> None:
    _shell(
        monkeypatch,
        pidof=f"/system/bin/sh: pidof: {marker}",
        ps=(
            "USER      PID  PPID  NAME\n"
            f"u0_a123  4321   567  {_PKG}\n"
            f"u0_a123  8899   567  {_PKG}:svc\n"
            "root         9     2  kworker\n"
        ),
    )
    assert _pids_for_package(object(), _PKG) == [4321, 8899]


def test_a_missing_pidof_with_no_matching_ps_line_is_confirmed_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _shell(
        monkeypatch,
        pidof="pidof: not found",
        ps="USER      PID  PPID  NAME\nroot         9     2  kworker\n",
    )
    assert _pids_for_package(object(), _PKG) == []


def test_a_ps_fallback_error_is_undeterminable(monkeypatch: pytest.MonkeyPatch) -> None:
    _shell(
        monkeypatch,
        pidof="pidof: not found",
        ps=AdbError("backend_error", "device offline"),
    )
    assert _pids_for_package(object(), _PKG) is None


def test_a_ps_line_without_a_digit_in_the_first_columns_contributes_no_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pid must come from the leading columns, not a digit buried in the name."""
    _shell(
        monkeypatch,
        pidof="pidof: not found",
        ps=f"appuser  appuser  appuser  {_PKG}-v2024\n",
    )
    assert _pids_for_package(object(), _PKG) == []


def test_the_ps_fallback_is_capped_so_a_huge_table_cannot_return_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = "".join(f"u0_a1  {1000 + i}  2  {_PKG}\n" for i in range(50))
    _shell(monkeypatch, pidof="pidof: not found", ps=rows)
    pids = _pids_for_package(object(), _PKG)
    assert pids is not None
    assert len(pids) == 16
    assert pids == [1000 + i for i in range(16)]
