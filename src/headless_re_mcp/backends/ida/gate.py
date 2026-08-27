from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from typing import Any

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.config import Settings
from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.core.windows import describe_process_windows

# Interval between analyzer-window enumerations while the gate worker runs.
# Window enumeration is a relatively expensive OS call; polling every 250 ms
# keeps overhead low without meaningfully delaying detection.
_WINDOW_POLL_INTERVAL = 0.25


@dataclass(frozen=True, slots=True)
class HeadlessGateResult:
    ok: bool
    backend: str
    payload: dict[str, Any]
    exit_code: int
    stdout: str
    stderr: str
    analyzer_windows: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "backend": self.backend,
            "payload": self.payload,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "analyzer_windows": list(self.analyzer_windows),
        }


def run_idalib_gate(
    binary: Path,
    settings: Settings | None = None,
    *,
    timeout: float = 300.0,
    decompile: bool = True,
) -> HeadlessGateResult:
    current = settings or Settings.load()
    if current.ida_home is None:
        raise RuntimeError("IDA home is not configured")

    env = os.environ.copy()
    env["PATH"] = f"{current.ida_home}{os.pathsep}{env.get('PATH', '')}"
    # On Windows a piped Python child encodes stdio with the ANSI code page,
    # and the worker emits ensure_ascii=False JSON that includes the binary's
    # path -- an NTFS name outside that code page made the worker die with
    # UnicodeEncodeError before it could report anything. Pin both ends to
    # UTF-8 so the pipe has one encoding regardless of locale.
    env["PYTHONIOENCODING"] = "utf-8:replace"
    command = [sys.executable, "-m", "headless_re_mcp.backends.ida.gate_worker"]
    if not decompile:
        command.append("--no-decompile")
    command.append(str(binary.resolve(strict=True)))

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        **no_window_popen_kwargs(),
    )

    observed: set[str] = set()
    monitor_stop = Event()

    def monitor_windows() -> None:
        # Enumerate analyzer windows on a background thread so that the main
        # thread can drain stdout/stderr via communicate(); polling here does
        # not gate pipe draining, so the worker can never deadlock on a full
        # pipe buffer.
        while not monitor_stop.wait(_WINDOW_POLL_INTERVAL):
            observed.update(describe_process_windows(process.pid))

    monitor = Thread(
        target=monitor_windows,
        name=f"ida-gate-{process.pid}",
        daemon=True,
    )
    monitor.start()

    timed_out = False
    killed: list[int] = []
    stdout, stderr = "", ""
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # process.kill() stops the gate worker and nothing else. Measured: a
        # launcher that started a sleeper returned in 0.81s after a 0.8s
        # timeout while the child was still running, holding CPU for the rest
        # of the process life.
        timed_out = True
        killed = terminate_process_tree(process)
        with suppress(subprocess.TimeoutExpired, ValueError, OSError):
            drained = process.communicate(timeout=5)
            stdout, stderr = drained
    finally:
        monitor_stop.set()
        monitor.join(timeout=2)
        observed.update(describe_process_windows(process.pid))

    if timed_out:
        payload = {
            "error": f"idalib gate timed out after {timeout} seconds",
            "killed_pids": killed,
        }
        return HeadlessGateResult(
            False,
            "ida",
            payload,
            -1,
            stdout,
            stderr,
            tuple(sorted(observed)),
        )

    payload = _last_json_line(stdout)
    ok = process.returncode == 0 and bool(payload.get("ok")) and not observed
    return HeadlessGateResult(
        ok,
        "ida",
        payload,
        int(process.returncode or 0),
        stdout,
        stderr,
        tuple(sorted(observed)),
    )


def _last_json_line(text: str) -> dict[str, Any]:
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {"error": "worker returned no JSON object"}

