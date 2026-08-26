"""Bounded adapter for the official UPX CLI (``upx -t`` / ``upx -d``).

Only whitelist operations are exposed. Callers supply an executable path and an
input file; the adapter never accepts arbitrary argv, never shells out, and never
overwrites the original input. Unpack output is written to a caller-chosen path
under the session artifact tree.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from typing import Any, BinaryIO, Final

from pydantic import BaseModel, ConfigDict, Field

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, active_bound_cancel

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT: Final[float] = 60.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 4 * 1024 * 1024
UPX_SOURCE: Final[str] = "upx"
_READ_CHUNK_SIZE: Final[int] = 64 * 1024
_VERSION_RE = re.compile(r"upx\s+(\d+(?:\.\d+)+)", re.IGNORECASE)


class UpxOperation(StrEnum):
    TEST = "test"
    UNPACK = "unpack"


class UpxErrorCode:
    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    OUTPUT_MISSING = "output_missing"
    INPUT_MUTATED = "input_mutated"


class UpxScanError(RuntimeError):
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


class UpxExecutableNotFoundError(UpxScanError):
    def __init__(self, executable: Path, message: str | None = None) -> None:
        super().__init__(
            UpxErrorCode.EXECUTABLE_NOT_FOUND,
            message or f"upx executable does not exist: {executable}",
            details={"executable": str(executable)},
        )


class UpxInputNotFoundError(UpxScanError):
    def __init__(self, path: Path, message: str | None = None) -> None:
        super().__init__(
            UpxErrorCode.INPUT_NOT_FOUND,
            message or f"UPX input file does not exist: {path}",
            details={"path": str(path)},
        )


class UpxInputTooLargeError(UpxScanError):
    def __init__(self, path: Path, size: int, maximum: int) -> None:
        super().__init__(
            UpxErrorCode.INPUT_TOO_LARGE,
            f"UPX input is larger than the configured limit ({size} > {maximum} bytes)",
            details={"path": str(path), "size": size, "max_file_size": maximum},
        )


class UpxTimeoutError(UpxScanError):
    def __init__(self, timeout: float, **kwargs: Any) -> None:
        super().__init__(
            UpxErrorCode.TIMEOUT,
            f"upx did not finish within {timeout:g} seconds",
            details={"timeout": timeout},
            retryable=True,
            **kwargs,
        )


class UpxOutputLimitError(UpxScanError):
    def __init__(self, maximum: int, *, stream: str, **kwargs: Any) -> None:
        super().__init__(
            UpxErrorCode.OUTPUT_LIMIT,
            f"upx {stream} exceeded the configured output limit ({maximum} bytes)",
            details={"stream": stream, "max_output_size": maximum},
            **kwargs,
        )


class UpxProcessError(UpxScanError):
    pass


class UpxResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: UpxOperation
    executable: Path
    input_path: Path
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_size: int = Field(ge=0)
    output_path: Path | None = None
    output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    output_size: int | None = Field(default=None, ge=0)
    version: str | None = None
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    started_at: datetime
    finished_at: datetime

    def to_dict(self) -> JsonObject:
        value = self.model_dump(mode="json")
        if not isinstance(value, dict):
            raise TypeError("UPX result did not serialize to an object")
        return value


@dataclass(slots=True)
class _CapturedStream:
    limit: int
    data: bytearray = field(default_factory=bytearray)
    exceeded: bool = False
    finished: Event = field(default_factory=Event)

    def read_from(self, pipe: BinaryIO, exceeded_event: Event) -> None:
        try:
            while True:
                chunk = pipe.read(_READ_CHUNK_SIZE)
                if not chunk:
                    return
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    self.exceeded = True
                    exceeded_event.set()
        except (OSError, ValueError):
            return
        finally:
            self.finished.set()

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class _ProcessCapture:
    stdout: str
    stderr: str
    returncode: int
    stdout_exceeded: bool
    stderr_exceeded: bool


def _creation_options() -> dict[str, Any]:
    options: dict[str, Any] = {
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": False,
        "close_fds": True,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        startupinfo_type = getattr(subprocess, "STARTUPINFO", None)
        if startupinfo_type is not None:
            startupinfo = startupinfo_type()
            startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
            startupinfo.wShowWindow = 0
            options["startupinfo"] = startupinfo
    else:
        options["creationflags"] = 0
    return options


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Stop upx and anything it started; the configured path may be a wrapper."""
    from headless_re_mcp.core.process_tree import terminate_process_tree

    terminate_process_tree(process, wait_s=5.0)


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
        raise UpxExecutableNotFoundError(Path(argv[0])) from exc
    except OSError as exc:
        raise UpxProcessError(
            UpxErrorCode.PROCESS_FAILED,
            f"could not start upx: {exc}",
            details={"executable": argv[0], "os_error": str(exc)},
        ) from exc

    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate_process(process)
        raise UpxProcessError(
            UpxErrorCode.PROCESS_FAILED,
            "upx process did not expose stdout/stderr pipes",
        )

    limit_event = Event()
    stdout_capture = _CapturedStream(max_output_size)
    stderr_capture = _CapturedStream(max_output_size)
    stdout_thread = Thread(
        target=stdout_capture.read_from,
        args=(stdout_pipe, limit_event),
        name="upx-stdout",
        daemon=True,
    )
    stderr_thread = Thread(
        target=stderr_capture.read_from,
        args=(stderr_pipe, limit_event),
        name="upx-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    deadline = monotonic() + timeout
    timed_out = False
    cancelled = False
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
            break
        sleep(min(0.05, remaining))

    drain_deadline = monotonic() + 2.0
    stdout_thread.join(timeout=max(0.0, drain_deadline - monotonic()))
    stderr_thread.join(timeout=max(0.0, drain_deadline - monotonic()))
    with suppress(OSError):
        stdout_pipe.close()
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
        raise UpxTimeoutError(
            timeout,
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.stdout_exceeded:
        raise UpxOutputLimitError(
            max_output_size,
            stream="stdout",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.stderr_exceeded:
        raise UpxOutputLimitError(
            max_output_size,
            stream="stderr",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    return capture


def _validate_paths(
    executable: Path,
    input_path: Path,
    *,
    max_file_size: int,
) -> tuple[Path, Path, int]:
    exe = executable.expanduser().resolve()
    if not exe.is_file():
        raise UpxExecutableNotFoundError(exe)
    path = input_path.expanduser().resolve()
    if not path.is_file():
        raise UpxInputNotFoundError(path)
    size = path.stat().st_size
    if size > max_file_size:
        raise UpxInputTooLargeError(path, size, max_file_size)
    return exe, path, size


def probe_upx_version(
    executable: Path,
    *,
    timeout: float = 5.0,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> str | None:
    exe = executable.expanduser().resolve()
    if not exe.is_file():
        raise UpxExecutableNotFoundError(exe)
    capture = _capture_process(
        [str(exe), "--version"],
        timeout=timeout,
        max_output_size=max_output_size,
    )
    match = _VERSION_RE.search(capture.stdout) or _VERSION_RE.search(capture.stderr)
    return match.group(1) if match else None


def test_upx(
    executable: Path,
    input_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> UpxResult:
    """Run ``upx -t`` against a read-only input path."""

    from headless_re_mcp.core.session import file_sha256

    exe, path, size = _validate_paths(executable, input_path, max_file_size=max_file_size)
    actual_sha = file_sha256(path)
    if actual_sha != input_sha256:
        raise UpxScanError(
            UpxErrorCode.INPUT_MUTATED,
            "UPX input changed before test",
            details={
                "path": str(path),
                "expected_sha256": input_sha256,
                "actual_sha256": actual_sha,
            },
        )
    version: str | None = None
    with suppress(UpxScanError):
        version = probe_upx_version(
            exe, timeout=min(5.0, timeout), max_output_size=max_output_size
        )

    started = datetime.now(UTC)
    capture = _capture_process(
        [str(exe), "-t", str(path)],
        timeout=timeout,
        max_output_size=max_output_size,
    )
    finished = datetime.now(UTC)
    if file_sha256(path) != input_sha256:
        raise UpxScanError(
            UpxErrorCode.INPUT_MUTATED,
            "UPX test mutated the original input",
            details={"path": str(path)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.returncode != 0:
        raise UpxProcessError(
            UpxErrorCode.PROCESS_FAILED,
            f"upx -t failed with exit status {capture.returncode}",
            details={"operation": UpxOperation.TEST.value, "path": str(path)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    return UpxResult(
        operation=UpxOperation.TEST,
        executable=exe,
        input_path=path,
        input_sha256=input_sha256,
        input_size=size,
        version=version,
        ok=True,
        stdout=capture.stdout,
        stderr=capture.stderr,
        returncode=capture.returncode,
        started_at=started,
        finished_at=finished,
    )


def unpack_upx(
    executable: Path,
    input_path: Path,
    output_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> UpxResult:
    """Run ``upx -d -o <output> <input>`` without modifying the original input."""

    from headless_re_mcp.core.session import file_sha256

    exe, path, size = _validate_paths(executable, input_path, max_file_size=max_file_size)
    actual_sha = file_sha256(path)
    if actual_sha != input_sha256:
        raise UpxScanError(
            UpxErrorCode.INPUT_MUTATED,
            "UPX input changed before unpack",
            details={
                "path": str(path),
                "expected_sha256": input_sha256,
                "actual_sha256": actual_sha,
            },
        )

    destination = output_path.expanduser().resolve()
    if destination.exists():
        raise UpxScanError(
            UpxErrorCode.INVALID_ARGUMENT,
            f"UPX output path already exists: {destination}",
            details={"output_path": str(destination)},
        )
    if destination == path:
        raise UpxScanError(
            UpxErrorCode.INVALID_ARGUMENT,
            "UPX output path must differ from the input path",
            details={"path": str(path)},
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    version = None
    with suppress(UpxScanError):
        version = probe_upx_version(exe, timeout=min(5.0, timeout), max_output_size=max_output_size)

    started = datetime.now(UTC)
    # Official UPX: decompress to a new file; keep the packed input intact.
    capture = _capture_process(
        [str(exe), "-d", "-o", str(destination), str(path)],
        timeout=timeout,
        max_output_size=max_output_size,
    )
    finished = datetime.now(UTC)

    if file_sha256(path) != input_sha256:
        if destination.is_file():
            with suppress(OSError):
                destination.unlink()
        raise UpxScanError(
            UpxErrorCode.INPUT_MUTATED,
            "UPX unpack mutated the original input",
            details={"path": str(path)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )

    if capture.returncode != 0:
        if destination.is_file():
            with suppress(OSError):
                destination.unlink()
        raise UpxProcessError(
            UpxErrorCode.PROCESS_FAILED,
            f"upx -d failed with exit status {capture.returncode}",
            details={
                "operation": UpxOperation.UNPACK.value,
                "path": str(path),
                "output_path": str(destination),
            },
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )

    if not destination.is_file():
        raise UpxScanError(
            UpxErrorCode.OUTPUT_MISSING,
            "upx reported success but produced no output file",
            details={"output_path": str(destination)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )

    output_size = destination.stat().st_size
    if output_size > max_file_size:
        with suppress(OSError):
            destination.unlink()
        raise UpxInputTooLargeError(destination, output_size, max_file_size)

    return UpxResult(
        operation=UpxOperation.UNPACK,
        executable=exe,
        input_path=path,
        input_sha256=input_sha256,
        input_size=size,
        output_path=destination,
        output_sha256=file_sha256(destination),
        output_size=output_size,
        version=version,
        ok=True,
        stdout=capture.stdout,
        stderr=capture.stderr,
        returncode=capture.returncode,
        started_at=started,
        finished_at=finished,
    )


def copy_input_for_safe_pack(source: Path, destination: Path) -> Path:
    """Copy a PE before packing fixtures; not used by unpack paths."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination.resolve()
