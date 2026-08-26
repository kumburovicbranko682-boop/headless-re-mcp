from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import time
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from threading import Event, RLock, Thread
from typing import Any, TextIO

from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.process_tree import terminate_process_tree
from headless_re_mcp.core.windows import describe_process_windows
from headless_re_mcp.process_group import assign_to_process_group

JsonObject = dict[str, Any]

# First ``auto_wait`` on a cold IDB can exceed the idle startup window. Progress
# events slide that window; this cap still bounds a worker that never becomes ready.
# Bounded analysis plus PE load should finish well under this.
_MAX_IDA_STARTUP_SECONDS = 240.0
# The worker protocol normally has one response in flight. A flood of
# unsolicited JSON used to accumulate without limit whenever no request was
# receiving; retain enough headroom for progress while bounding malformed output.
_MAX_PENDING_WORKER_MESSAGES = 1_024
_MAX_WORKER_LINE_CHARS = 1_048_576


def next_receive_deadline(
    *,
    now: float,
    deadline: float,
    idle_timeout: float,
    absolute_deadline: float,
    message: JsonObject,
    extend_on_progress: bool,
) -> float:
    """Slide the receive deadline when the worker is still analysing."""
    if extend_on_progress and message.get("event") == "progress":
        return min(now + idle_timeout, absolute_deadline)
    return deadline


def startup_receive_remaining(
    *,
    now: float,
    idle_deadline: float,
    absolute_deadline: float,
    extend_on_progress: bool,
) -> float:
    """How long to keep waiting for ``ready``.

    A living worker that holds the GIL during ``open_database`` cannot emit
    progress, so startup waits on the absolute cap rather than idle silence.
    """
    if extend_on_progress:
        return absolute_deadline - now
    return min(idle_deadline, absolute_deadline) - now


class IdaWorkerError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: JsonObject | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}
        self.retryable = retryable

    @classmethod
    def from_payload(cls, payload: object) -> IdaWorkerError:
        if not isinstance(payload, dict):
            return cls("worker_protocol_error", "worker returned an invalid error payload")
        details = payload.get("details")
        return cls(
            str(payload.get("code", "backend_error")),
            str(payload.get("message", "IDA worker failed")),
            details=details if isinstance(details, dict) else {},
            retryable=bool(payload.get("retryable", False)),
        )


class IdaWorkerClient(ManagedSubprocessMixin):
    def __init__(
        self,
        binary: Path,
        settings: Settings,
        *,
        startup_timeout: float = 300.0,
    ) -> None:
        if settings.ida_home is None:
            raise IdaWorkerError("backend_unavailable", "IDA home is not configured")

        env = os.environ.copy()
        env["PATH"] = f"{settings.ida_home}{os.pathsep}{env.get('PATH', '')}"
        env["PYTHONUNBUFFERED"] = "1"
        popen_kw = no_window_popen_kwargs()

        self._process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "headless_re_mcp.backends.ida.worker",
                str(binary.resolve(strict=True)),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            **popen_kw,
        )
        # An idalib worker holds the database in memory and is measured in
        # gigabytes. Nothing closes it when this process is killed rather than
        # asked to stop, so without this a hard restart leaves one behind for
        # every session that was open.
        assign_to_process_group(self._process.pid)
        self._messages: queue.Queue[JsonObject | None] = queue.Queue(
            maxsize=_MAX_PENDING_WORKER_MESSAGES
        )
        self._message_overflow = Event()
        self._messages_dropped = 0
        self._stdout_log: deque[str] = deque(maxlen=100)
        self._stderr_log: deque[str] = deque(maxlen=100)
        self._request_lock = RLock()
        self._request_id = 0
        self._closed = False
        self._metadata: JsonObject = {}
        self._capabilities: frozenset[str] = frozenset()
        self._observed_windows: set[str] = set()

        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._stdout_thread = Thread(
            target=self._read_stdout,
            args=(self._process.stdout,),
            name=f"ida-worker-{self._process.pid}-stdout",
            daemon=True,
        )
        self._stderr_thread = Thread(
            target=self._read_stderr,
            args=(self._process.stderr,),
            name=f"ida-worker-{self._process.pid}-stderr",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

        try:
            message = self._receive(
                lambda item: item.get("event") in {"ready", "fatal"},
                startup_timeout,
                extend_on_progress=True,
                absolute_timeout=_MAX_IDA_STARTUP_SECONDS,
            )
            if message.get("event") == "fatal":
                raise IdaWorkerError.from_payload(message.get("error"))
            data = message.get("data")
            if not isinstance(data, dict):
                raise IdaWorkerError(
                    "worker_protocol_error", "IDA worker ready event has no data object"
                )
            self._metadata = data
            raw_capabilities = data.get("capabilities", [])
            if isinstance(raw_capabilities, list):
                self._capabilities = frozenset(str(item) for item in raw_capabilities)
        except BaseException:
            self.terminate()
            raise

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def exit_code(self) -> int | None:
        """None while the worker is running, matching the dynamic backend."""
        return self._process.poll()

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    @property
    def metadata(self) -> JsonObject:
        return dict(self._metadata)

    @property
    def analyzer_windows(self) -> tuple[str, ...]:
        return tuple(sorted(self._observed_windows))

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        with self._request_lock:
            if self._closed:
                raise IdaWorkerError("session_closed", "IDA worker is closed")
            if self._process.poll() is not None:
                raise self._process_exit_error()

            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "command": command, "params": params or {}}
            try:
                assert self._process.stdin is not None
                self._process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
                self._process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise self._process_exit_error() from exc

            try:
                response = self._receive(
                    lambda item: item.get("id") == request_id, timeout
                )
            except IdaWorkerError as exc:
                if exc.code in {"worker_timeout", "worker_output_overflow"}:
                    # A timed-out worker is still inside Hex-Rays, while an
                    # overflowing worker has already lost protocol messages.
                    # Neither can safely serve the next request.
                    with suppress(BaseException):
                        self.terminate()
                raise
            if response.get("ok") is not True:
                raise IdaWorkerError.from_payload(response.get("error"))
            data = response.get("data")
            if not isinstance(data, dict):
                raise IdaWorkerError(
                    "worker_protocol_error", "IDA worker response has no data object"
                )
            return data

    def close(self, *, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        lock_acquired = self._request_lock.acquire(
            timeout=max(0.0, deadline - time.monotonic())
        )
        if not lock_acquired:
            self.terminate()
            raise IdaWorkerError(
                "worker_timeout",
                f"IDA close exceeded {timeout:g}s waiting for the active request",
                retryable=True,
            )
        try:
            if self._closed:
                return
            try:
                if self._process.poll() is None:
                    self.request(
                        "close",
                        timeout=max(0.0, deadline - time.monotonic()),
                    )
            finally:
                self._closed = True
                if self._process.stdin is not None:
                    self._process.stdin.close()
                try:
                    self._process.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    self.terminate()
        finally:
            self._request_lock.release()

    def terminate(self) -> None:
        self._closed = True
        # terminate()/kill() on the worker leaves idalib children running.
        # Measured: a launcher that started a sleeper was dead after
        # terminate() while the child was still alive, holding a core and the
        # database for the rest of the process life.
        terminate_process_tree(self._process, wait_s=5.0)

    def _read_stdout(self, stream: TextIO) -> None:
        try:
            while True:
                line = stream.readline(_MAX_WORKER_LINE_CHARS + 1)
                if not line:
                    break
                stripped = line.rstrip("\r\n")
                oversized = len(stripped) > _MAX_WORKER_LINE_CHARS or (
                    len(line) > _MAX_WORKER_LINE_CHARS and not line.endswith("\n")
                )
                if oversized:
                    self._note_dropped_message()
                    self._stdout_log.append(
                        f"worker protocol line exceeded {_MAX_WORKER_LINE_CHARS} characters"
                    )
                    while line and not line.endswith("\n"):
                        line = stream.readline(_MAX_WORKER_LINE_CHARS + 1)
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    self._stdout_log.append(stripped)
                    continue
                if isinstance(payload, dict):
                    self._enqueue_message(payload)
                else:
                    self._stdout_log.append(stripped)
        finally:
            self._enqueue_message(None)

    def _enqueue_message(self, message: JsonObject | None) -> None:
        try:
            self._messages.put_nowait(message)
        except queue.Full:
            self._note_dropped_message()

    def _note_dropped_message(self) -> None:
        self._messages_dropped += 1
        self._message_overflow.set()

    def _read_stderr(self, stream: TextIO) -> None:
        for line in stream:
            self._stderr_log.append(line.rstrip("\r\n"))

    def _receive(
        self,
        predicate: Callable[[JsonObject], bool],
        timeout: float,
        *,
        extend_on_progress: bool = False,
        absolute_timeout: float | None = None,
    ) -> JsonObject:
        started = time.monotonic()
        deadline = started + timeout
        extra = absolute_timeout if absolute_timeout is not None else timeout
        absolute_deadline = started + extra
        while True:
            self._observe_windows()
            if self._message_overflow.is_set():
                raise IdaWorkerError(
                    "worker_output_overflow",
                    "IDA worker exceeded protocol output safety limits",
                    details=self._diagnostics(),
                    retryable=True,
                )
            remaining = startup_receive_remaining(
                now=time.monotonic(),
                idle_deadline=deadline,
                absolute_deadline=absolute_deadline,
                extend_on_progress=extend_on_progress,
            )
            if remaining <= 0:
                raise IdaWorkerError(
                    "worker_timeout",
                    f"IDA worker did not respond within {timeout:g} seconds",
                    details=self._diagnostics(),
                    retryable=True,
                )
            try:
                message = self._messages.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if self._process.poll() is not None:
                    raise self._process_exit_error() from None
                continue
            if message is None:
                raise self._process_exit_error()
            if predicate(message):
                self._observe_windows()
                return message
            deadline = next_receive_deadline(
                now=time.monotonic(),
                deadline=deadline,
                idle_timeout=timeout,
                absolute_deadline=absolute_deadline,
                message=message,
                extend_on_progress=extend_on_progress,
            )
            if message.get("event") == "progress":
                continue
            self._stdout_log.append(json.dumps(message, ensure_ascii=False))

    def _observe_windows(self) -> None:
        """Refuse the call while a window is up, without latching on history.

        ``analyzer_windows`` stays cumulative so a gate still fails on a window
        that opened and closed mid-analysis. Refusing on that history instead
        would retire the worker permanently over a dialog that is already gone.
        """
        windows = describe_process_windows(self._process.pid)
        if not windows:
            return
        self._observed_windows.update(windows)
        raise IdaWorkerError(
            "analyzer_window_detected",
            "IDA worker has an analyzer window open",
            details={"windows": sorted(windows)},
        )

    def _process_exit_error(self) -> IdaWorkerError:
        return IdaWorkerError(
            "worker_exited",
            f"IDA worker exited unexpectedly with code {self._process.poll()}",
            details=self._diagnostics(),
            retryable=True,
        )

    def _diagnostics(self) -> JsonObject:
        return {
            "pid": self._process.pid,
            "exit_code": self._process.poll(),
            "stdout": list(self._stdout_log),
            "stderr": list(self._stderr_log),
            "analyzer_windows": sorted(self._observed_windows),
            "pending_messages": self._messages.qsize(),
            "message_capacity": _MAX_PENDING_WORKER_MESSAGES,
            "message_line_character_limit": _MAX_WORKER_LINE_CHARS,
            "messages_dropped": self._messages_dropped,
        }