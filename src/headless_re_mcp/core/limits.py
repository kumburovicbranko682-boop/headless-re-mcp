"""Service-level bounds shared by the facade and the surfaces split out of it.

These were duplicated once AnalysisService started shedding mixins: the same
ceiling was declared in service.py and again in the module that moved out, which
is a limit that silently disagrees with itself the first time one side is tuned.
One definition, imported by everyone who enforces it.
"""

from __future__ import annotations

import ctypes
import os
import sys

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