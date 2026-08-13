"""Tie spawned children to the lifetime of this process, on Windows.

A child outlives its parent here. The supervisor terminates its own child on the
way out, but nothing runs when the supervisor is force-killed -- TerminateProcess
delivers no signal -- and stopping a scheduled task is exactly that. Measured
against a real supervise run: killing the supervisor left the web server up,
holding the port the next start would need and the debuggers it had open.

A job object with KILL_ON_JOB_CLOSE closes that: the handle dies with the
process however it dies, and the kernel takes the children with it. Everything
here is best effort, because failing to build the safety net is not a reason to
refuse to run.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from threading import Lock
from typing import Any

_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001

_lock = Lock()
_job: int | None = None
_unavailable = False


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.POINTER(wintypes.ULONG)),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kernel32() -> Any:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _ensure_job() -> int | None:
    """The process-wide job, created once. None when it cannot be had."""
    global _job, _unavailable
    with _lock:
        if _job is not None or _unavailable:
            return _job
        try:
            kernel32 = _kernel32()
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                _unavailable = True
                return None
            limits = _ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            applied = kernel32.SetInformationJobObject(
                handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            )
            if not applied:
                kernel32.CloseHandle(handle)
                _unavailable = True
                return None
            _job = int(handle)
            return _job
        except (OSError, AttributeError, ValueError):
            _unavailable = True
            return None


def assign_to_process_group(pid: int) -> bool:
    """Make ``pid`` die with this process. False when that could not be arranged.

    Already being in another job is the common refusal -- a container or a CI
    runner may have put us in one that forbids nesting -- and it is not a
    failure worth reporting past the caller.
    """
    if os.name != "nt" or pid <= 0:
        return False
    job = _ensure_job()
    if job is None:
        return False
    try:
        kernel32 = _kernel32()
        handle = kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not handle:
            return False
        try:
            return bool(kernel32.AssignProcessToJobObject(job, handle))
        finally:
            kernel32.CloseHandle(handle)
    except (OSError, AttributeError, ValueError):
        return False
