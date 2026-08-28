"""Service-level bounds shared by the facade and the surfaces split out of it.

These were duplicated once AnalysisService started shedding mixins: the same
ceiling was declared in service.py and again in the module that moved out, which
is a limit that silently disagrees with itself the first time one side is tuned.
One definition, imported by everyone who enforces it.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
from contextlib import suppress
from pathlib import Path

# Longest any single bounded debugger wait may be asked to run.
MAX_WORKFLOW_TIMEOUT = 300.0

# Rebuilding a runtime dump into a file image holds the dump, the rebuilt image
# and working copies at once. Measured on this code: a 64 MB dump peaked at 3.0x
# its size and a 256 MB one at 4.0x. The check below uses the higher figure.
PE_REBUILD_MEMORY_FACTOR = 4

# What fraction of the memory currently free the rebuild may plan to use. The
# rest is for everything else this process is in the middle of.
PE_REBUILD_MEMORY_HEADROOM = 0.8

# Refuse to dump more than this from one module in a single call.
MAX_MODULE_DUMP_BYTES = 64 * 1024 * 1024

# Static results larger than this are written to an artifact instead of inlined.
MAX_STATIC_INLINE_TEXT = 64 * 1024

# Commands accepted by one static.batch call.
MAX_STATIC_BATCH_COMMANDS = 32

# Capture directories that never enter the artifact table. Device screenshots
# and jsre unpack trees are keyed by serial or by a throwaway uuid, so the
# retention walker cannot see them; without a local cap they grow for as long
# as the service lives.
UNREGISTERED_CAPTURE_MAX_ENTRIES = 32
UNREGISTERED_CAPTURE_MAX_BYTES = 64 * 1024 * 1024
JSRE_UNPACK_MAX_ENTRIES = 8
JSRE_UNPACK_MAX_BYTES = 256 * 1024 * 1024
_DIR_SIZE_FILE_CAP = 4096


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def available_memory_bytes() -> int | None:
    """Physical memory free right now, or None when it cannot be determined.

    None means "do not guess": a caller must then allow the work rather than
    refuse it, because refusing on an unknown is how a limit turns into an
    outage on a machine that could have done the job.
    """
    try:
        if sys.platform == "win32":
            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(_MemoryStatusEx)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            return int(status.ullAvailPhys)
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        return None
    if pages < 0 or page_size < 0:
        return None
    return int(pages) * int(page_size)


def rebuild_would_exhaust_memory(dump_bytes: int) -> tuple[bool, int, int | None]:
    """Would rebuilding a dump of this size plan to use more than is free?

    Returns the verdict, the estimated peak, and the memory seen as free.
    """
    estimate = int(dump_bytes) * PE_REBUILD_MEMORY_FACTOR
    available = available_memory_bytes()
    if available is None:
        return False, estimate, None
    return estimate > available * PE_REBUILD_MEMORY_HEADROOM, estimate, available


def capped_file_size(path: Path, *, cap: int) -> tuple[int, bool]:
    """Size of a just-written file, deleting it when it is over ``cap``.

    Capture directories keep the newest entry even when it alone exceeds the
    byte budget, so a single huge screenshot or pull would sit on disk for the
    life of the process. Callers that just wrote a path should refuse it.
    Returns ``(size, over_cap)``.
    """
    try:
        size = int(path.stat().st_size)
    except OSError:
        return 0, False
    if size > cap:
        with suppress(OSError):
            path.unlink()
        return size, True
    return size, False


def prune_capped_dir(
    directory: Path,
    *,
    max_entries: int,
    max_bytes: int,
) -> int:
    """Delete oldest children until both caps hold. Never removes the newest.

    Capture directories that are not in the artifact table otherwise grow for
    as long as the service lives, and the retention walker cannot see them.
    The newest entry is kept so a caller that just wrote a path still finds it.
    """
    try:
        if not directory.is_dir():
            return 0
        children = list(directory.iterdir())
    except OSError:
        return 0
    entries: list[tuple[float, Path, int]] = []
    total = 0
    for child in children:
        try:
            stat = child.stat()
            # A subdirectory child is measured with dir_size_over_cap, not _dir_size.
            # This helper's whole job is to keep the byte ceiling sound, and _dir_size
            # bails after _DIR_SIZE_FILE_CAP (4096) files and returns that partial sum
            # -- so a child tree with more files than that reads as far smaller than it
            # is. The jsre spill root's children are js.unpack_bundle's unpack-<uuid>/
            # trees, and webcrack splits a large bundle into one file per module,
            # thousands of them; the partial sum kept ``total`` under max_bytes and the
            # byte cap silently stopped reclaiming, exactly the fail-open
            # dir_size_over_cap was written to close. It walks a tree under the cap in
            # full (accurate) and short-circuits once a single child alone crosses
            # max_bytes (bounded, with a file-count ceiling so an empty-file flood
            # cannot turn the measurement into a stat() storm); over-cap it returns a
            # floor > max_bytes, which still forces a prune. Device callers pass file
            # children, so the subdir branch is jsre-only.
            size = int(stat.st_size) if child.is_file() else dir_size_over_cap(child, max_bytes)[0]
            entries.append((float(stat.st_mtime), child, size))
            total += size
        except OSError:
            continue
    if not entries:
        return 0
    entries.sort(key=lambda item: item[0])
    removed = 0
    while len(entries) > 1 and (len(entries) > max_entries or total > max_bytes):
        _mtime, path, size = entries.pop(0)
        if _remove_entry(path):
            total = max(0, total - size)
            removed += 1
    return removed


def _dir_size(directory: Path) -> int:
    total = 0
    seen = 0
    try:
        for child in directory.rglob("*"):
            try:
                if child.is_file():
                    total += child.stat().st_size
                    seen += 1
                    if seen >= _DIR_SIZE_FILE_CAP:
                        break
            except OSError:
                continue
    except OSError:
        return total
    return total


# A decode/decompile tree with more files than this is refused outright rather
# than measured to the last byte. Even the largest real apps disassemble to a
# few hundred thousand files, so a tree past this many is not a legitimate
# capture -- and measuring one takes a stat() per file, which is the very cost
# the byte short-circuit below exists to avoid. Well above any real app so a
# genuine decode is never refused for its file count alone.
_TREE_SIZE_FILE_CEILING = 2_000_000


def dir_size_over_cap(directory: Path, cap: int) -> tuple[int, bool]:
    """Whether ``directory`` holds more than ``cap`` bytes, stopping once it does.

    Unlike ``_dir_size`` -- which bails after ``_DIR_SIZE_FILE_CAP`` files and
    returns the partial sum a caller reads as "small" -- this is for the size
    *backstop*, where under-reporting a giant tree is a fail-*open* bug. A single
    ``classes.dex`` can disassemble into hundreds of thousands of tiny ``.smali``
    files (one per class), so a hostile APK that declares an honest central
    directory still inflates far past the cap in file *count* while each file
    stays small; ``_dir_size`` would tally only its first 4096 files, land under
    the cap, and let the multi-hundred-MB tree survive.

    This short-circuits on the only fact the backstop needs -- ``total > cap`` --
    so the bomb is caught after roughly ``cap`` bytes of walking instead of
    slipping through, and a tree that never crosses the cap is walked in full,
    which is what proving "small" honestly requires. A tree with more than
    ``_TREE_SIZE_FILE_CEILING`` files is treated as over-cap (fail-closed) so the
    walk itself cannot be turned into a stat() storm by an empty-file flood.
    Returns ``(measured_bytes, over_cap)``; when ``over_cap`` is true the byte
    count is a floor, not the true total.
    """
    total = 0
    seen = 0
    try:
        for child in directory.rglob("*"):
            try:
                # Count every entry walked toward the ceiling, including
                # directories, before the is_file() filter below. Incrementing
                # ``seen`` only for files (as this once did) left an all-directories
                # tree -- an empty-dir flood a hostile archive can generate, or a
                # deep decode tree -- walking every entry with the ceiling never
                # tripping, so the stat()-storm guard did not bound that shape at
                # all. An empty-dir tree is ~0 bytes and stays under the byte cap
                # honestly; the ceiling is what keeps the *walk* bounded either way.
                seen += 1
                if seen >= _TREE_SIZE_FILE_CEILING:
                    return total, True
                if not child.is_file():
                    continue
                total += child.stat().st_size
                if total > cap:
                    return total, True
            except OSError:
                continue
    except OSError:
        return total, total > cap
    return total, total > cap


def _remove_entry(path: Path) -> bool:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    except OSError:
        return False