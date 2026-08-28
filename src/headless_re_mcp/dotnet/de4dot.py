"""Bounded adapter for a user-configured de4dot CLI.

Only whitelist argv is allowed (``-f`` / ``-o``). The adapter never overwrites
the input assembly, never accepts arbitrary flags, and never copies toolkit
samples. Callers must point ``HEADLESS_RE_DE4DOT`` at a GPL-licensed build they
obtained themselves.
"""

from __future__ import annotations

import os
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from typing import Any, Final

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    TimedOut,
    active_bound_cancel,
    run_bounded,
)

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT: Final[float] = 120.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 8 * 1024 * 1024
DE4DOT_SOURCE: Final[str] = "de4dot"
_READ_CHUNK_SIZE: Final[int] = 64 * 1024


class De4dotErrorCode:
    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    OUTPUT_MISSING = "output_missing"
    INPUT_MUTATED = "input_mutated"
    NOT_DOTNET = "not_dotnet"


class De4dotError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: JsonObject | None = None,
        stdout: str = "",
        stderr: str = "",
        returncode: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class De4dotResult:
    executable: str
    input_path: str
    output_path: str
    input_sha256: str
    output_sha256: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int

    def to_dict(self) -> JsonObject:
        return {
            "executable": self.executable,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "source": DE4DOT_SOURCE,
            "claims_universal_unpack": False,
        }


def _require_positive_number(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise De4dotError(
            De4dotErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive number",
            details={name: value},
        )


def _require_positive_int(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise De4dotError(
            De4dotErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive integer",
            details={name: value},
        )


def run_de4dot(
    executable: Path,
    input_path: Path,
    output_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> De4dotResult:
    """Run ``de4dot -f <input> -o <output>`` with hard bounds."""
    _require_positive_number(timeout, "timeout")
    _require_positive_int(max_file_size, "max_file_size")
    _require_positive_int(max_output_size, "max_output_size")
    exe = Path(executable).expanduser()
    # resolve() without strict=True so a missing input surfaces as the structured
    # INPUT_NOT_FOUND error below instead of a raw FileNotFoundError from resolve().
    source = Path(input_path).expanduser().resolve()
    destination = Path(output_path).expanduser()
    if not exe.is_file():
        raise De4dotError(
            De4dotErrorCode.EXECUTABLE_NOT_FOUND,
            f"de4dot executable does not exist: {exe}",
            details={"executable": str(exe)},
        )
    if not source.is_file():
        raise De4dotError(
            De4dotErrorCode.INPUT_NOT_FOUND,
            f"input assembly not found: {source}",
            details={"input_path": str(source)},
        )
    size = source.stat().st_size
    if size > max_file_size:
        raise De4dotError(
            De4dotErrorCode.INPUT_TOO_LARGE,
            f"input exceeds max_file_size={max_file_size}",
            details={"size": size, "max_file_size": max_file_size},
        )
    if destination.exists():
        raise De4dotError(
            De4dotErrorCode.INVALID_ARGUMENT,
            "output_path must not already exist",
            details={"output_path": str(destination)},
        )
    if destination.resolve() == source.resolve():
        raise De4dotError(
            De4dotErrorCode.INVALID_ARGUMENT,
            "output_path must differ from input_path",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    from headless_re_mcp.core.session import file_sha256

    before = file_sha256(source)
    if before != input_sha256:
        raise De4dotError(
            De4dotErrorCode.INPUT_MUTATED,
            "input sha256 changed before de4dot",
            details={"expected": input_sha256, "actual": before},
        )

    argv = [str(exe), "-f", str(source), "-o", str(destination)]
    started = monotonic()
    capture = _capture_process(argv, timeout=timeout, max_output_size=max_output_size)
    duration_ms = int((monotonic() - started) * 1000)

    after = file_sha256(source)
    if after != before:
        raise De4dotError(
            De4dotErrorCode.INPUT_MUTATED,
            "de4dot mutated the original input assembly",
            details={"input_path": str(source)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.stdout_exceeded or capture.stderr_exceeded:
        if destination.is_file():
            with suppress(OSError):
                destination.unlink()
        raise De4dotError(
            De4dotErrorCode.OUTPUT_LIMIT,
            "de4dot stdout/stderr exceeded bound",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.returncode != 0:
        with suppress(OSError):
            if destination.is_file():
                destination.unlink()
        raise De4dotError(
            De4dotErrorCode.PROCESS_FAILED,
            f"de4dot exited with {capture.returncode}",
            details={"argv": ["de4dot", "-f", "<input>", "-o", "<output>"]},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
            retryable=True,
        )
    if not destination.is_file():
        raise De4dotError(
            De4dotErrorCode.OUTPUT_MISSING,
            "de4dot reported success but output file is missing",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    return De4dotResult(
        executable=str(exe),
        input_path=str(source),
        output_path=str(destination.resolve()),
        input_sha256=before,
        output_sha256=file_sha256(destination),
        returncode=capture.returncode,
        stdout=capture.stdout,
        stderr=capture.stderr,
        duration_ms=duration_ms,
    )


@dataclass
class _CapturedStream:
    max_size: int
    chunks: list[bytes]
    exceeded: bool = False

    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        self.chunks = []
        self.exceeded = False

    def read_from(self, pipe: Any, limit_event: Event) -> None:
        total = 0
        try:
            while True:
                chunk = pipe.read(_READ_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_size:
                    self.exceeded = True
                    limit_event.set()
                    break
                self.chunks.append(chunk)
        except (OSError, ValueError):
            return
        finally:
            # The reader owns its pipe and closes it here once read() returns.
            # The capture thread must never close a pipe this thread might still
            # be blocked on -- that deadlocks on the stream's lock.
            with suppress(OSError, ValueError):
                pipe.close()

    def text(self) -> str:
        return b"".join(self.chunks).decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class _ProcessCapture:
    stdout: str
    stderr: str
    returncode: int
    stdout_exceeded: bool
    stderr_exceeded: bool


def _creation_options() -> dict[str, Any]:
    options: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo_type = getattr(subprocess, "STARTUPINFO", None)
        if startupinfo_type is not None:
            startupinfo = startupinfo_type()
            startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
            startupinfo.wShowWindow = 0
            options["startupinfo"] = startupinfo
    else:
        # Its own session so a timeout kill can signal the whole group, and so
        # the runner's JVM/dotnet child can be found by group even after the
        # runner exits and the kernel reparents that child to init.
        options["start_new_session"] = True
    return options


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Stop the deobfuscator and anything it started.

    de4dot and NETReactorSlayer are often invoked through a runner (dotnet, or
    a batch wrapper), and killing the runner leaves the work itself running on
    the sample this call was told to stop touching.
    """
    from headless_re_mcp.core.process_tree import terminate_process_tree

    terminate_process_tree(process, wait_s=5.0, kill_group=os.name != "nt")


def _capture_process(
    argv: list[str],
    *,
    timeout: float,
    max_output_size: int,
) -> _ProcessCapture:
    try:
        process = subprocess.Popen(argv, **_creation_options())
        from headless_re_mcp.process_group import assign_to_process_group

        pid = getattr(process, "pid", None)
        if pid:
            assign_to_process_group(int(pid))
    except FileNotFoundError as exc:
        raise De4dotError(
            De4dotErrorCode.EXECUTABLE_NOT_FOUND,
            f"de4dot executable not found: {argv[0]}",
            details={"executable": argv[0]},
        ) from exc
    except OSError as exc:
        raise De4dotError(
            De4dotErrorCode.PROCESS_FAILED,
            f"could not start de4dot: {exc}",
            details={"executable": argv[0]},
        ) from exc

    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate_process(process)
        raise De4dotError(
            De4dotErrorCode.PROCESS_FAILED,
            "de4dot process did not expose stdout/stderr pipes",
        )

    # start_new_session (POSIX) makes the runner its own group leader, so the
    # group id is the runner's pid. Used to find and kill a reparented child by
    # group after the runner exits, when the parent/child walk sees nothing.
    group_id = int(process.pid) if os.name != "nt" and process.pid else 0

    limit_event = Event()
    stdout_capture = _CapturedStream(max_output_size)
    stderr_capture = _CapturedStream(max_output_size)
    stdout_thread = Thread(
        target=stdout_capture.read_from,
        args=(stdout_pipe, limit_event),
        name="de4dot-stdout",
        daemon=True,
    )
    stderr_thread = Thread(
        target=stderr_capture.read_from,
        args=(stderr_pipe, limit_event),
        name="de4dot-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    deadline = monotonic() + timeout
    timed_out = False
    cancelled = False
    exited = False
    stop = active_bound_cancel()
    while True:
        if stop is not None and stop.is_set():
            cancelled = True
            _terminate_process(process)
            break
        if limit_event.is_set():
            _terminate_process(process)
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            timed_out = True
            _terminate_process(process)
            break
        if process.poll() is not None:
            exited = True
            break
        sleep(min(0.05, remaining))

    stdout_thread.join(timeout=2.0)
    stderr_thread.join(timeout=2.0)
    if exited:
        # The runner ended on its own; make sure it left nothing behind. On
        # Windows the job object and the Toolhelp walk cover this. On POSIX the
        # parent/child walk is blind to a child the runner orphaned to init, so
        # enumerate the session group the runner led instead.
        readers_blocked = stdout_thread.is_alive() or stderr_thread.is_alive()
        if os.name == "nt":
            from headless_re_mcp.core.process_tree import collect_descendants

            leftover_children = readers_blocked or bool(
                process.pid and collect_descendants(int(process.pid))
            )
        else:
            from headless_re_mcp.core.process_tree import collect_process_group

            leftover_children = readers_blocked or bool(
                group_id and collect_process_group(group_id)
            )
        if leftover_children:
            _terminate_process(process)
            if os.name != "nt" and group_id:
                from headless_re_mcp.core.process_tree import terminate_process_group

                terminate_process_group(group_id)
            stdout_thread.join(timeout=2.0)
            stderr_thread.join(timeout=2.0)
    # The readers close their own pipes; only close here when the reader has
    # finished, so a reader still blocked on a survivor's pipe never wedges this
    # thread on close().
    if not stdout_thread.is_alive():
        with suppress(OSError):
            stdout_pipe.close()
    if not stderr_thread.is_alive():
        with suppress(OSError):
            stderr_pipe.close()

    returncode = process.poll()
    if returncode is None:
        _terminate_process(process)
        returncode = process.poll()
    if returncode is None:
        returncode = -1

    capture = _ProcessCapture(
        stdout=stdout_capture.text(),
        stderr=stderr_capture.text(),
        returncode=returncode,
        stdout_exceeded=stdout_capture.exceeded,
        stderr_exceeded=stderr_capture.exceeded,
    )
    if cancelled:
        raise BoundedCancelled()
    if timed_out:
        raise De4dotError(
            De4dotErrorCode.TIMEOUT,
            f"de4dot timed out after {timeout}s",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
            retryable=True,
        )
    return capture


def probe_de4dot_version(executable: Path, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Best-effort version/help probe; de4dot builds vary in argv support."""
    exe = Path(executable)
    if not exe.is_file():
        return False, ""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    for args in ([str(exe)], [str(exe), "-h"], [str(exe), "--help"]):
        try:
            completed = run_bounded(args, timeout=timeout, creationflags=flags)
        except TimedOut:
            # The same binary hung. Trying -h and --help used to leave two more
            # children and triple the wait; doctor then called that READY.
            return False, ""
        except OSError:
            continue
        text = ((completed.stdout or b"") + b"\n" + (completed.stderr or b"")).decode(
            "utf-8", "replace"
        ).strip()
        lowered = text.casefold()
        if "de4dot" in lowered or completed.returncode in {0, 1}:
            return True, text[:2000]
    return False, ""
