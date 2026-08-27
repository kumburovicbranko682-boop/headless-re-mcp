from __future__ import annotations

import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.backends.x64dbg.client import seed_headless_event_settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.core.session import detect_pe_architecture
from headless_re_mcp.core.windows import describe_process_windows

# Interval between analyzer-window enumerations while the gate runs. Window
# enumeration is a relatively expensive OS call; polling every 250 ms keeps
# overhead low without meaningfully delaying detection.
_WINDOW_POLL_INTERVAL = 0.25


@dataclass(frozen=True, slots=True)
class XdbgHeadlessGateResult:
    ok: bool
    architecture: Architecture
    executable: str
    exit_code: int
    stdout: str
    stderr: str
    analyzer_windows: tuple[str, ...]
    command_loop_seen: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "architecture": self.architecture.value,
            "executable": self.executable,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "analyzer_windows": list(self.analyzer_windows),
            "command_loop_seen": self.command_loop_seen,
        }


def run_command_loop_gate(
    executable: Path,
    architecture: Architecture,
    *,
    timeout: float = 60.0,
) -> XdbgHeadlessGateResult:
    path = executable.resolve(strict=True)
    actual_architecture = detect_pe_architecture(path)
    if actual_architecture != architecture:
        raise ValueError(
            f"expected {architecture.value} headless executable, "
            f"got {actual_architecture.value}: {path}"
        )

    observed: set[str] = set()
    monitor_stop = Event()

    with TemporaryDirectory(prefix=f"headless-re-xdbg-{architecture.value}-") as user_dir:
        seed_headless_event_settings(Path(user_dir))
        process = subprocess.Popen(
            [str(path), "-userdir", user_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **no_window_popen_kwargs(),
        )

        def monitor_windows() -> None:
            while not monitor_stop.wait(_WINDOW_POLL_INTERVAL):
                observed.update(describe_process_windows(process.pid))

        monitor = Thread(
            target=monitor_windows,
            name=f"xdbg-gate-{architecture.value}-{process.pid}",
            daemon=True,
        )
        monitor.start()
        cleanup_deadline: float | None = None
        try:
            stdout, stderr = process.communicate(input="state\nexit\n", timeout=timeout)
        except subprocess.TimeoutExpired:
            # process.kill() stops the headless executable and nothing else.
            # Measured: a launcher that started a sleeper returned in 0.81s
            # after a 0.8s timeout while the child was still running.
            #
            # One cleanup budget covers tree termination, the pipe drain, and
            # the monitor join below.  Stacking a five-second drain on a
            # two-second join let a 100 ms gate bound take over seven seconds.
            cleanup_deadline = monotonic() + 5.0
            terminate_process_tree(process)
            stdout, stderr = "", ""
            with suppress(subprocess.TimeoutExpired, ValueError, OSError):
                drained = process.communicate(
                    timeout=max(0.0, cleanup_deadline - monotonic())
                )
                stdout, stderr = drained
        finally:
            monitor_stop.set()
            monitor_timeout = 2.0
            if cleanup_deadline is not None:
                monitor_timeout = min(
                    monitor_timeout,
                    max(0.0, cleanup_deadline - monotonic()),
                )
            monitor.join(timeout=monitor_timeout)
            observed.update(describe_process_windows(process.pid))

    command_loop_seen = "[headless] entering command loop" in stdout
    return XdbgHeadlessGateResult(
        ok=process.returncode == 0 and command_loop_seen and not observed,
        architecture=architecture,
        executable=str(path),
        exit_code=int(process.returncode if process.returncode is not None else -1),
        stdout=stdout,
        stderr=stderr,
        analyzer_windows=tuple(sorted(observed)),
        command_loop_seen=command_loop_seen,
    )
