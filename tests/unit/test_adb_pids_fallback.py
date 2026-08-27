"""The pidof->ps fallback must return real PIDs for the right process only.

``_pids_for_package`` is how the ADB backend learns whether a package is running
(force-stop verification, frida attach targeting). When the device has no
``pidof`` it falls back to parsing ``ps -A``. Two ways that parser used to lie:

* On builds whose ``ps`` prints a *numeric UID* in the USER column it returned
  the UID (first digit on the line) instead of the PID, so callers force-stopped
  or attached to a bogus pid.
* It matched the package as a bare substring, so ``com.foo`` matched the
  unrelated process ``com.foo.bar`` -- the opposite of ``pidof``'s exact match.

These tests pin both against realistic ``ps -A`` output, plus the direct
``pidof`` path and the "no ps available" degradation.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import AdbError, _pids_for_package

_PIDOF_MISSING = "/system/bin/sh: pidof: not found"

# Modern Android (toybox) `ps -A`: USER is a resolved name.
_PS_NAMED = """USER            PID   PPID     VSZ    RSS WCHAN            ADDR S NAME
root              1      0   10788   1512 0                   0 S init
u0_a123        4242    321 1234567  45678 0                   0 S com.example.app
u0_a123        4300   4242 1200000  40000 0                   0 S com.example.app:push
shell          9001   8000   11000   2000 0                   0 R ps
"""

# Older toolbox / rooted `ps`: USER column is a numeric UID.
_PS_NUMERIC_USER = """USER   PID  PPID VSIZE  RSS  WCHAN    PC   NAME
10123  4242  321  123456 45678 000000   00   com.example.app
"""


class _Dev:
    """A fake adbutils device returning canned shell output per command."""

    def __init__(self, *, pidof: str, ps: str | Exception = "") -> None:
        self._pidof = pidof
        self._ps = ps

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        if isinstance(args, list) and args[:1] == ["pidof"]:
            return self._pidof
        if args == "ps -A":
            if isinstance(self._ps, Exception):
                raise self._ps
            return self._ps
        return ""


def test_pidof_direct_hit_parses_space_and_comma_lists() -> None:
    assert _pids_for_package(_Dev(pidof="4242 4300"), "com.example.app") == [4242, 4300]
    assert _pids_for_package(_Dev(pidof="4242,4300"), "com.example.app") == [4242, 4300]


def test_pidof_empty_means_not_running() -> None:
    assert _pids_for_package(_Dev(pidof=""), "com.example.app") == []


def test_ps_fallback_named_user_reads_the_pid_column() -> None:
    # Main process and its :push service both count; the header and unrelated
    # rows do not.
    pids = _pids_for_package(_Dev(pidof=_PIDOF_MISSING, ps=_PS_NAMED), "com.example.app")
    assert pids == [4242, 4300]


def test_ps_fallback_numeric_user_column_is_not_mistaken_for_the_pid() -> None:
    # The UID 10123 must not be returned; the PID 4242 must.
    pids = _pids_for_package(_Dev(pidof=_PIDOF_MISSING, ps=_PS_NUMERIC_USER), "com.example.app")
    assert pids == [4242]


def test_ps_fallback_does_not_match_a_sibling_package() -> None:
    ps = "USER PID PPID VSZ RSS WCHAN ADDR S NAME\nu0_a1 111 1 0 0 0 0 S com.foo.bar\n"
    assert _pids_for_package(_Dev(pidof=_PIDOF_MISSING, ps=ps), "com.foo") == []


def test_ps_fallback_matches_the_exact_package() -> None:
    ps = "USER PID PPID VSZ RSS WCHAN ADDR S NAME\nu0_a1 111 1 0 0 0 0 S com.foo\n"
    assert _pids_for_package(_Dev(pidof=_PIDOF_MISSING, ps=ps), "com.foo") == [111]


def test_ps_unavailable_degrades_to_none_not_a_crash() -> None:
    dev = _Dev(pidof=_PIDOF_MISSING, ps=AdbError("backend_error", "ps failed"))
    assert _pids_for_package(dev, "com.example.app") is None
