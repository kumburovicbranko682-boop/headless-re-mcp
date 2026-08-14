"""Shared subprocess lifecycle helpers for IDA / x64dbg clients."""

from __future__ import annotations

import os
import subprocess
from contextlib import nullcontext
from typing import Any

from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.core.windows import describe_process_windows


def no_window_popen_kwargs() -> dict[str, Any]:
    """Return kwargs that suppress console windows on Windows."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
    return {"creationflags": creationflags, "startupinfo": startupinfo}


class ManagedSubprocessMixin:
    """Mixin expecting `_process` (Popen) and `_observed_windows` set."""

    _process: subprocess.Popen[Any]
    _observed_windows: set[str]

    @property
    def pid(self) -> int:
        return int(self._process.pid)

    @property
    def analyzer_windows(self) -> tuple[str, ...]:
        windows = describe_process_windows(self.pid)
        titles = tuple(sorted(windows))
        for title in titles:
            self._observed_windows.add(title)
        return titles

    def terminate_process(self, *, wait_timeout: float = 3.0) -> None:
        lock = getattr(self, "_lock", nullcontext())
        with lock:
            # terminate()/kill() on the spawned process leaves what it started
            # running. Measured: launcher dead after this method, sleeper still
            # alive.
            terminate_process_tree(self._process, wait_s=wait_timeout)
