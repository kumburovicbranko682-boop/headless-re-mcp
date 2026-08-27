"""ADB shell-output parsers that decide process identity and file stats.

These helpers turn raw ``pidof`` / ``ps`` / ``stat`` output into the values the
device tools act on, so their edge behaviour is load-bearing: a package with no
running process must read as an empty list (not ``None``, which means "could not
tell"), a device that lacks ``pidof`` must fall back to scanning ``ps`` and cap
the pids it returns, a probe error must degrade to ``None`` rather than raise,
and frida-server detection must answer True/False from a live device and None
only when the shell itself failed. All are driven through a fake device, no adb.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import (
    _file_mode_size,
    _frida_server_visible,
    _pids_for_package,
)


class _ShellDev:
    """A device whose shell answers from a table, or raises for listed commands."""

    def __init__(self, responses: dict[str, str], errors: tuple[str, ...] = ()) -> None:
        self._responses = responses
        self._errors = errors
        self.calls: list[str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        key = " ".join(args) if isinstance(args, list) else str(args)
        self.calls.append(key)
        if key in self._errors:
            raise RuntimeError("device offline")
        return self._responses.get(key, "")


_PKG = "com.example.app"


def test_pidof_space_separated_pids_are_parsed() -> None:
    dev = _ShellDev({f"pidof {_PKG}": "4321 4322 4400"})
    assert _pids_for_package(dev, _PKG) == [4321, 4322, 4400]


def test_pidof_comma_separated_pids_are_parsed() -> None:
    """Some pidof builds comma-separate their output; both forms must parse."""
    dev = _ShellDev({f"pidof {_PKG}": "4321,4322"})
    assert _pids_for_package(dev, _PKG) == [4321, 4322]


def test_no_running_process_reads_as_empty_not_unknown() -> None:
    """An empty pidof means the package is installed but not running.

    That is an empty list, distinct from None ("could not determine"): a caller
    targeting a process can tell "nothing to attach to" from "the probe failed".
    """
    dev = _ShellDev({f"pidof {_PKG}": "   "})
    assert _pids_for_package(dev, _PKG) == []


def test_missing_pidof_falls_back_to_scanning_ps() -> None:
    """A device without pidof is read through ps -A instead.

    pidof answers "not found"; the fallback scans ps for lines naming the
    package and reads the pid out of the leading columns.
    """
    ps = (
        "USER           PID  PPID     VSZ    RSS WCHAN  ADDR S NAME\n"
        f"u0_a123       4321   789  123456  12345 0         0 S {_PKG}\n"
        f"u0_a123       4322   789  123456  12345 0         0 S {_PKG}:remote\n"
        "root           999     1    4000    200 0         0 S /init\n"
    )
    dev = _ShellDev({f"pidof {_PKG}": "pidof: not found", "ps -A": ps})
    assert _pids_for_package(dev, _PKG) == [4321, 4322]


def test_ps_fallback_caps_the_pid_count() -> None:
    """The ps scan stops at 16 pids so a huge process list cannot run unbounded."""
    lines = ["USER PID PPID NAME"]
    for index in range(20):
        lines.append(f"u0_a1 {5000 + index} 789 {_PKG}")
    dev = _ShellDev({f"pidof {_PKG}": "unknown option", "ps -A": "\n".join(lines)})
    result = _pids_for_package(dev, _PKG)
    assert result is not None
    assert len(result) == 16
    assert result[0] == 5000


def test_pidof_error_is_reported_as_unknown() -> None:
    """A failing pidof probe degrades to None, not an exception."""
    dev = _ShellDev({}, errors=(f"pidof {_PKG}",))
    assert _pids_for_package(dev, _PKG) is None


def test_ps_fallback_error_is_reported_as_unknown() -> None:
    """When the ps fallback itself fails, the answer is None (could not tell)."""
    dev = _ShellDev({f"pidof {_PKG}": "not found"}, errors=("ps -A",))
    assert _pids_for_package(dev, _PKG) is None


def test_pidof_output_with_no_digits_is_unknown() -> None:
    """Non-numeric pidof output that is not a 'not found' marker is None.

    It is neither an empty (not running) nor a parseable pid list, so the honest
    answer is that the probe returned something unusable.
    """
    dev = _ShellDev({f"pidof {_PKG}": "garbage-without-numbers"})
    assert _pids_for_package(dev, _PKG) is None


def test_file_mode_size_reads_object_attributes() -> None:
    class _Stat:
        mode = 0o100644
        size = 2048

    assert _file_mode_size(_Stat()) == (0o100644, 2048)


def test_file_mode_size_reads_a_tuple_stat() -> None:
    """adbutils' older stat returns a (mode, size, mtime) tuple, not an object."""
    assert _file_mode_size((0o40755, 4096, 1700000000)) == (0o40755, 4096)


def test_file_mode_size_reads_a_list_stat() -> None:
    assert _file_mode_size([0o100600, 512]) == (0o100600, 512)


def test_frida_server_seen_in_ps_a() -> None:
    dev = _ShellDev({"ps -A": "root 999 1 frida-server\n"})
    assert _frida_server_visible(dev) is True


def test_frida_server_seen_only_in_short_ps() -> None:
    """If ps -A does not show it, the shorter ps listing is consulted too."""
    dev = _ShellDev({"ps -A": "root 1 0 /init", "ps": "root 999 1 frida-server"})
    assert _frida_server_visible(dev) is True


def test_frida_server_absent_is_false() -> None:
    dev = _ShellDev({"ps -A": "root 1 0 /init", "ps": "root 2 0 kthreadd"})
    assert _frida_server_visible(dev) is False


def test_frida_server_probe_failure_is_none() -> None:
    """A shell that cannot run leaves readiness unknown (None), not False."""
    dev = _ShellDev({}, errors=("ps -A",))
    assert _frida_server_visible(dev) is None
