"""Process-tree helpers for UI child-PID discovery and timeout kills."""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]

_MAX_CHILD_PIDS = 16
# A timeout kill walks a launcher's descendants: jadx, apktool and Ghidra are
# scripts that start a JVM, webcrack starts node. Deeper than this is not a
# tool run, and the walk is bounded so a fork bomb cannot hold the killer.
_MAX_KILL_DESCENDANTS = 64
_MAX_KILL_DEPTH = 4
def _child_enum_limit(max_pids: int) -> int:
    """UI discovery defaults to 16; kill walks may ask for more.

    The hard cap is the kill-walk bound so a Chromium tree is not silently
    truncated to the UI page size.
    """
    return max(1, min(int(max_pids), _MAX_KILL_DESCENDANTS))


_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PROCESS_TERMINATE = 0x0001


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    )


def process_image_path(pid: int) -> str | None:
    """Return the full image path for ``pid``, or None on failure."""
    if os.name != "nt" or type(pid) is not int or pid <= 0:
        return None
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        # QueryFullProcessImageNameW
        q = kernel32.QueryFullProcessImageNameW
        q.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        q.restype = wintypes.BOOL
        if not q(handle, 0, buf, ctypes.byref(size)):
            return None
        return buf.value or None
    finally:
        kernel32.CloseHandle(handle)


def enumerate_direct_children(parent_pid: int, *, max_pids: int = _MAX_CHILD_PIDS) -> list[int]:
    """Return direct child PIDs of ``parent_pid`` (bounded)."""
    if type(parent_pid) is not int or parent_pid <= 0:
        return []
    limit = _child_enum_limit(max_pids)
    if os.name != "nt":
        return _enumerate_direct_children_proc(parent_pid, limit)
    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1, 0xFFFFFFFF):
        return []
    children: list[int] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return []
        while True:
            if int(entry.th32ParentProcessID) == int(parent_pid):
                child = int(entry.th32ProcessID)
                if child > 0 and child != parent_pid:
                    children.append(child)
                    if len(children) >= limit:
                        break
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    children.sort()
    return children


def _enumerate_direct_children_proc(parent_pid: int, limit: int) -> list[int]:
    """Linux: ``/proc/<pid>/task/<pid>/children``, then a /proc scan."""
    children_file = Path(f"/proc/{parent_pid}/task/{parent_pid}/children")
    try:
        text = children_file.read_text(encoding="ascii", errors="replace")
    except OSError:
        return _scan_proc_ppid(parent_pid, limit)
    children: list[int] = []
    for token in text.split():
        try:
            child = int(token)
        except ValueError:
            continue
        if child > 0 and child != parent_pid:
            children.append(child)
            if len(children) >= limit:
                break
    children.sort()
    return children


def _scan_proc_ppid(parent_pid: int, limit: int) -> list[int]:
    children: list[int] = []
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        child = int(entry.name)
        if child <= 0 or child == parent_pid:
            continue
        try:
            stat = (entry / "stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        close = stat.rfind(")")
        if close < 0:
            continue
        fields = stat[close + 2 :].split()
        try:
            ppid = int(fields[1])
        except (IndexError, ValueError):
            continue
        if ppid == parent_pid:
            children.append(child)
            if len(children) >= limit:
                break
    children.sort()
    return children


def collect_descendants(parent_pid: int) -> list[int]:
    """Descendant PIDs, deepest last, bounded in both breadth and depth."""
    found: list[int] = []
    seen = {int(parent_pid)}
    frontier = [int(parent_pid)]
    for _ in range(_MAX_KILL_DEPTH):
        if not frontier or len(found) >= _MAX_KILL_DESCENDANTS:
            break
        children: list[int] = []
        for pid in frontier:
            for child in enumerate_direct_children(pid, max_pids=_MAX_KILL_DESCENDANTS):
                if child in seen:
                    continue
                seen.add(child)
                children.append(child)
                found.append(child)
                if len(found) >= _MAX_KILL_DESCENDANTS:
                    break
            if len(found) >= _MAX_KILL_DESCENDANTS:
                break
        frontier = children
    return found


def collect_process_group(pgid: int) -> list[int]:
    """POSIX: live PIDs whose process group is ``pgid`` (bounded). [] on Windows.

    A tool started with ``start_new_session`` leads its own group, so its
    descendants carry that group id even after the kernel reparents an orphan to
    init. Enumerating by the recorded group finds those survivors when the
    parent/child walk no longer can, and it never trusts a reaped leader's pid:
    a member is matched on its own ``pgrp`` field, not on who its parent is.
    """
    if os.name == "nt" or not isinstance(pgid, int) or pgid <= 0:
        return []
    members: list[int] = []
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == pgid:
            continue
        try:
            stat = (entry / "stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        close = stat.rfind(")")
        if close < 0:
            continue
        # After "pid (comm)" the fields are state, ppid, pgrp, ... so pgrp is
        # index 2 -- the same parse _scan_proc_ppid uses for ppid at index 1.
        fields = stat[close + 2 :].split()
        try:
            member_pgrp = int(fields[2])
        except (IndexError, ValueError):
            continue
        if member_pgrp == pgid:
            members.append(pid)
            if len(members) >= _MAX_KILL_DESCENDANTS:
                break
    members.sort()
    return members


def terminate_process_group(pgid: int) -> list[int]:
    """POSIX: kill every live member of process group ``pgid``. [] on Windows.

    Members are enumerated by their recorded group and killed one by one, rather
    than with ``killpg(pgid)``: once the leader is reaped its pid can be reused,
    and a bare group signal on a recycled pid could hit an unrelated group. A
    per-member kill keyed on the group cannot.
    """
    killed: list[int] = []
    for pid in collect_process_group(pgid):
        with suppress(Exception):
            _kill_pid(pid)
            killed.append(pid)
    return killed


def _pid_running_posix(pid: int) -> bool:
    """POSIX: True only for a schedulable process, False for zombie/dead/gone.

    ``os.kill(pid, 0)`` reports a zombie as alive, so it cannot tell a process
    that has been killed but not yet reaped from a running one. Read the state
    field of ``/proc/<pid>/stat`` instead: 'Z'/'X'/'x' mean already dead.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return False
    close = stat.rfind(")")
    if close < 0:
        return False
    fields = stat[close + 2 :].split()
    return bool(fields) and fields[0] not in {"Z", "X", "x"}


def reap_orphaned_session_group(leader_pid: int, *, confirm_timeout_s: float = 2.0) -> list[int]:
    """POSIX: kill anything still in the session group a just-exited leader led.

    A CLI adapter started with ``start_new_session`` leads its own group, so its
    process group id equals its pid. When that leader exits cleanly the ppid walk
    sees nothing, but a helper it detached and orphaned to init keeps the group
    id and lives on -- exactly what makes an unattended run accumulate stray
    JVM/helper processes. Enumerate the group and kill any survivor. Members are
    matched on their own ``pgrp`` (never signalled with a bare ``killpg`` on a
    possibly-recycled leader pid). No-op / [] on Windows or without a group.

    SIGKILL returns before the target has finished transitioning to a zombie, so
    the killed pids are polled (bounded by ``confirm_timeout_s``) until none are
    still schedulable -- the caller can then report the group reaped without a
    race against a helper that was signalled a moment ago.
    """
    if os.name == "nt" or not isinstance(leader_pid, int) or leader_pid <= 0:
        return []
    killed = terminate_process_group(leader_pid)
    if killed:
        from time import monotonic, sleep

        deadline = monotonic() + max(0.0, confirm_timeout_s)
        while monotonic() < deadline and any(_pid_running_posix(pid) for pid in killed):
            sleep(0.02)
    return killed


def _kill_own_process_group(pid: int) -> list[int]:
    """POSIX: kill ``pid``'s process group, but only when ``pid`` leads it.

    The ppid walk cannot see a grandchild the kernel has reparented to init --
    its parent link now points at pid 1, not the launcher -- so a tool that
    orphans a worker survives a timeout. A process started with
    ``start_new_session=True`` leads its own group, and every descendant keeps
    that group id even after reparenting, so one ``killpg`` reaches them all.

    Guarded to a group leader on purpose: signalling a group we do not lead
    could take down the service's own process group. When ``pid`` is not a
    leader this returns empty and the descendant walk still runs.
    """
    if os.name == "nt":
        return []
    # getattr, not os.killpg directly: these are POSIX-only and absent from the
    # Windows type stubs the quality job checks against, so a plain reference
    # fails mypy on the hosted runner even though this branch never runs there.
    getpgid = getattr(os, "getpgid", None)
    killpg = getattr(os, "killpg", None)
    if getpgid is None or killpg is None:
        return []
    sigkill = getattr(signal, "SIGKILL", 9)
    with suppress(OSError, ProcessLookupError):
        if getpgid(pid) != pid:
            return []
    with suppress(OSError, ProcessLookupError):
        killpg(pid, sigkill)
        return [pid]
    return []


def terminate_process_tree(process: Any, *, wait_s: float = 5.0, kill_group: bool = False) -> list[int]:
    """Kill a spawned process and everything it started. Returns the killed PIDs.

    Killing only the process that was spawned is not enough here. Measured on
    this machine: kill a launcher and the process it started keeps running,
    which for jadx, apktool or Ghidra means an orphaned JVM holding CPU and a
    lock on the sample after the tool call has already returned a timeout.

    Descendants are enumerated *before* the parent dies, because that is while
    the relationship is still recorded. On POSIX the process group is signalled
    too, which reaches descendants the ppid walk cannot -- an orphan reparented
    to init keeps the group but loses the parent link. Never raises: this runs
    on a failure path that has somewhere better to be.
    """
    killed: list[int] = []
    pid = getattr(process, "pid", None)
    descendants: list[int] = []
    if isinstance(pid, int) and pid > 0:
        with suppress(Exception):
            descendants = collect_descendants(pid)
        killed.extend(_kill_own_process_group(pid))

    with suppress(OSError, AttributeError):
        if process.poll() is None:
            process.kill()
            if isinstance(pid, int):
                killed.append(pid)
    with suppress(OSError, AttributeError, ValueError, subprocess.TimeoutExpired):
        process.wait(timeout=wait_s)

    # Deepest last on the way in, so kill in reverse: a parent that respawns its
    # child cannot outlive the sweep.
    for child in reversed(descendants):
        with suppress(Exception):
            _kill_pid(child)
            killed.append(child)
    if kill_group and os.name != "nt" and isinstance(pid, int):
        with suppress(Exception):
            os.killpg(pid, 9)
    return killed


def terminate_pid_tree(pid: int) -> list[int]:
    """Kill ``pid`` and its descendants when there is no Popen handle left.

    Playwright's driver is started inside the library, so a wedged browser
    session has a PID and nothing else. Enumerate first: once the parent is
    gone the relationship is no longer in the snapshot.
    """
    if not isinstance(pid, int) or pid <= 0:
        return []
    descendants: list[int] = []
    if isinstance(pid, int) and pid > 0:
        with suppress(Exception):
            descendants = collect_descendants(pid)
    killed: list[int] = []
    killed.extend(_kill_own_process_group(pid))
    with suppress(Exception):
        _kill_pid(pid)
        killed.append(pid)
    for child in reversed(descendants):
        with suppress(Exception):
            _kill_pid(child)
            killed.append(child)
    return killed


def _kill_pid(pid: int) -> None:
    if os.name != "nt":
        os.kill(pid, 9)
        return
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(_PROCESS_TERMINATE, False, int(pid))
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 1)
    finally:
        kernel32.CloseHandle(handle)


def filter_same_image_pids(debuggee_pid: int, candidates: list[int]) -> list[int]:
    """Keep candidates whose image path matches the debuggee (casefold)."""
    base = process_image_path(debuggee_pid)
    if not base:
        return []
    key = base.casefold()
    matched: list[int] = []
    for pid in candidates:
        path = process_image_path(pid)
        if path and path.casefold() == key:
            matched.append(int(pid))
    return matched


def probe_child_window_candidates(
    debuggee_pid: int,
    *,
    list_windows_fn: Any = None,
    max_pids: int = _MAX_CHILD_PIDS,
) -> list[JsonObject]:
    """Read-only: children that own top-level windows (not an allow grant)."""
    from headless_re_mcp.core.windows import list_process_windows

    window_lister = list_windows_fn or list_process_windows
    out: list[JsonObject] = []
    for child in enumerate_direct_children(debuggee_pid, max_pids=max_pids):
        windows = window_lister(child)
        visible = [w for w in windows if w.get("visible")]
        if not windows:
            continue
        out.append(
            {
                "pid": child,
                "image": process_image_path(child),
                "window_count": len(windows),
                "visible_count": len(visible),
                "titles": [str(w.get("title") or "") for w in visible[:8]],
                "same_image": bool(
                    (process_image_path(debuggee_pid) or "").casefold()
                    == (process_image_path(child) or "").casefold()
                ),
            }
        )
    return out
