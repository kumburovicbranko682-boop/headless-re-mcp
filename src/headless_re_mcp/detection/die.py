"""Bounded adapter for the official Detect It Easy (``diec``) CLI.

The adapter deliberately exposes a very small command surface.  A caller gives
us one executable, one regular file, and one of the :class:`ScanMode` values;
the command line is assembled here and is never interpreted by a shell.  DIE's
JSON is treated as a protocol (rather than as human-readable output), and is
converted to the common detection finding model.

This module does not discover or configure ``diec``.  Configuration/doctor
code can use :func:`scan_with_die` (or :class:`DieCliAdapter`) once a trusted
executable path is known.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
from time import monotonic
from typing import Any, BinaryIO, Final, cast

from pydantic import BaseModel, ConfigDict, Field

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, active_bound_cancel
from headless_re_mcp.detection.models import (
    DetectionEvidence,
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    FindingSeverity,
    JsonObject,
    ScanMode,
)

# These defaults are intentionally conservative.  They are function defaults,
# not a promise that a service must use these values.
DEFAULT_TIMEOUT: Final[float] = 30.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 4 * 1024 * 1024
DIEC_SOURCE: Final[str] = "diec"

_MODE_FLAGS: Final[dict[ScanMode, str | None]] = {
    ScanMode.NORMAL: None,
    ScanMode.DEEP: "-d",
    ScanMode.HEURISTIC: "-u",
    ScanMode.AGGRESSIVE: "-g",
}
_MAX_DETECTS: Final[int] = 4096
_MAX_VALUES_PER_DETECT: Final[int] = 16_384
_MAX_TEXT: Final[int] = 32_768
_READ_CHUNK_SIZE: Final[int] = 64 * 1024


class DieErrorCode:
    """Stable string codes used by :class:`DieScanError`.

    A class of constants is used instead of another enum so callers can pass
    codes directly through JSON/error envelopes without conversion.
    """

    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    PROTOCOL_ERROR = "protocol_error"


class DieScanError(RuntimeError):
    """A structured, bounded failure while invoking or parsing ``diec``."""

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


class DieExecutableNotFoundError(DieScanError):
    def __init__(self, executable: Path, message: str | None = None) -> None:
        super().__init__(
            DieErrorCode.EXECUTABLE_NOT_FOUND,
            message or f"diec executable does not exist: {executable}",
            details={"executable": str(executable)},
        )


class DieInputNotFoundError(DieScanError):
    def __init__(self, path: Path, message: str | None = None) -> None:
        super().__init__(
            DieErrorCode.INPUT_NOT_FOUND,
            message or f"DIE input file does not exist: {path}",
            details={"path": str(path)},
        )


class DieInputTooLargeError(DieScanError):
    def __init__(self, path: Path, size: int, maximum: int) -> None:
        super().__init__(
            DieErrorCode.INPUT_TOO_LARGE,
            f"DIE input is larger than the configured limit ({size} > {maximum} bytes)",
            details={"path": str(path), "size": size, "max_file_size": maximum},
        )


class DieTimeoutError(DieScanError):
    def __init__(self, timeout: float, **kwargs: Any) -> None:
        super().__init__(
            DieErrorCode.TIMEOUT,
            f"diec did not finish within {timeout:g} seconds",
            details={"timeout": timeout},
            retryable=True,
            **kwargs,
        )


class DieOutputLimitError(DieScanError):
    def __init__(self, maximum: int, *, stream: str, **kwargs: Any) -> None:
        super().__init__(
            DieErrorCode.OUTPUT_LIMIT,
            f"diec {stream} exceeded the configured output limit ({maximum} bytes)",
            details={"stream": stream, "max_output_size": maximum},
            **kwargs,
        )


class DieProcessError(DieScanError):
    pass


class DieProtocolError(DieScanError):
    pass


class DieScanResult(BaseModel):
    """Normalized DIE output plus bounded raw process artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: Path
    size: int = Field(ge=0)
    mode: ScanMode
    findings: tuple[DetectionFinding, ...]
    source: DetectionSource
    # ``raw`` is the parsed official object.  ``raw_json`` retains the exact
    # bounded stdout payload for artifact storage/auditing by a higher layer.
    raw: JsonObject
    raw_json: str
    stdout: str
    stderr: str
    returncode: int
    scanned_at: datetime

    def to_dict(self) -> JsonObject:
        value = self.model_dump(mode="json")
        if not isinstance(value, dict):
            raise TypeError("DIE result did not serialize to an object")
        return value


@dataclass(slots=True)
class _CapturedStream:
    limit: int
    data: bytearray = field(default_factory=bytearray)
    exceeded: bool = False
    finished: Event = field(default_factory=Event)

    def read_from(self, pipe: BinaryIO, exceeded_event: Event) -> None:
        """Drain a pipe while retaining at most ``limit`` bytes.

        Once the limit is crossed we continue draining/discarding until the
        parent kills the child.  This prevents a child blocked on a full pipe
        from making cleanup itself hang.
        """

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
            # The process cleanup path may close the pipe while this thread is
            # draining it.  The bytes captured before close remain useful in an
            # error envelope.
            return
        finally:
            # The reader owns its pipe and closes it here, on its own thread,
            # once read() has returned. The capture thread must never close a
            # pipe this thread might still be blocked on -- that deadlocks on
            # the buffered stream's lock -- so this is the only safe place.
            with suppress(OSError, ValueError):
                pipe.close()
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
    """Return subprocess options that keep the Windows console hidden."""

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
        # Its own session so a timeout kill can signal the whole group and reach
        # a wrapper's child the parent/child walk would miss.
        options["start_new_session"] = True
    return options


def _capture_process(
    argv: list[str],
    *,
    timeout: float,
    max_output_size: int,
) -> _ProcessCapture:
    """Run one fixed argv and capture both streams under hard byte limits."""

    try:
        process = subprocess.Popen(argv, **_creation_options())
        from headless_re_mcp.process_group import assign_to_process_group

        pid = getattr(process, "pid", None)
        if pid:
            assign_to_process_group(int(pid))
    except FileNotFoundError as exc:
        raise DieExecutableNotFoundError(Path(argv[0])) from exc
    except OSError as exc:
        raise DieProcessError(
            DieErrorCode.PROCESS_FAILED,
            f"could not start diec: {exc}",
            details={"executable": argv[0], "os_error": str(exc)},
        ) from exc

    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate_process(process)
        raise DieProcessError(
            DieErrorCode.PROCESS_FAILED,
            "diec process did not expose stdout/stderr pipes",
        )

    limit_event = Event()
    stdout_capture = _CapturedStream(max_output_size)
    stderr_capture = _CapturedStream(max_output_size)
    stdout_thread = Thread(
        target=stdout_capture.read_from,
        args=(stdout_pipe, limit_event),
        name="diec-stdout",
        daemon=True,
    )
    stderr_thread = Thread(
        target=stderr_capture.read_from,
        args=(stderr_pipe, limit_event),
        name="diec-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    deadline = monotonic() + timeout
    timed_out = False
    limited = False
    cancelled = False
    stop = active_bound_cancel()
    try:
        while True:
            returncode = process.poll()
            if returncode is not None:
                break
            if stop is not None and stop.is_set():
                cancelled = True
                _terminate_process(process)
                returncode = process.poll()
                break
            if limit_event.is_set():
                limited = True
                _terminate_process(process)
                returncode = process.poll()
                break
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process(process)
                returncode = process.poll()
                break
            # A short wait avoids a busy loop and gives reader threads a chance
            # to observe an output limit promptly.
            try:
                returncode = process.wait(timeout=min(remaining, 0.05))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if timed_out or limited or cancelled:
            _terminate_process(process)
        else:
            # The process has exited, but wait once more for a concrete code.
            try:
                returncode = process.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                _terminate_process(process)
                returncode = process.poll()
        # Once the child has exited, let both readers consume the remaining
        # kernel pipe buffers before closing our handles.  Closing first can
        # truncate a short-lived process's final JSON bytes.  A single shared
        # budget keeps cleanup bounded: joining each reader for a full second
        # would let a grandchild that inherited (and still holds open) a pipe
        # extend the caller's deadline by seconds, one stream at a time.
        drain_deadline = monotonic() + 1.0
        stdout_thread.join(timeout=max(0.0, drain_deadline - monotonic()))
        stderr_thread.join(timeout=max(0.0, drain_deadline - monotonic()))
        # The readers close their own pipes; only close here when the reader has
        # already finished, so a reader still blocked on a survivor's pipe never
        # wedges this thread on close().
        if not stdout_thread.is_alive():
            _close_pipe(stdout_pipe)
        if not stderr_thread.is_alive():
            _close_pipe(stderr_pipe)
        stdout_thread.join(timeout=max(0.0, drain_deadline - monotonic()))
        stderr_thread.join(timeout=max(0.0, drain_deadline - monotonic()))

    if returncode is None:
        returncode = -1
    capture = _ProcessCapture(
        stdout_capture.text(),
        stderr_capture.text(),
        int(returncode),
        stdout_capture.exceeded,
        stderr_capture.exceeded,
    )
    if cancelled:
        raise BoundedCancelled()
    if timed_out:
        raise DieTimeoutError(
            timeout,
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.stdout_exceeded:
        raise DieOutputLimitError(
            max_output_size,
            stream="stdout",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.stderr_exceeded:
        raise DieOutputLimitError(
            max_output_size,
            stream="stderr",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    return capture


def _terminate_process(process: Any) -> None:
    """Stop the scanner and anything it started.

    diec is normally the executable itself, but the path is operator-supplied
    and a wrapper script is a reasonable thing to configure -- and killing a
    wrapper leaves what it launched running, which on a timeout means a scanner
    still reading the sample after the call has returned.
    """
    from headless_re_mcp.core.process_tree import terminate_process_tree

    terminate_process_tree(process, wait_s=1.0)


def _close_pipe(pipe: Any) -> None:
    with suppress(OSError, AttributeError, ValueError):
        pipe.close()


def _coerce_mode(mode: ScanMode | str) -> ScanMode:
    try:
        return mode if isinstance(mode, ScanMode) else ScanMode(mode)
    except (TypeError, ValueError) as exc:
        raise DieScanError(
            DieErrorCode.INVALID_ARGUMENT,
            f"unsupported DIE scan mode: {mode!r}",
            details={"mode": repr(mode), "allowed": [item.value for item in ScanMode]},
        ) from exc


def _validate_positive_number(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DieScanError(
            DieErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive finite number",
            details={name: repr(value)},
        )
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0:
        raise DieScanError(
            DieErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive finite number",
            details={name: converted},
        )
    return converted


def _validate_positive_integer(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DieScanError(
            DieErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive integer",
            details={name: repr(value)},
        )
    return value


def _resolve_executable(executable: Path) -> Path:
    try:
        resolved = Path(executable).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise DieExecutableNotFoundError(Path(executable)) from exc
    if not resolved.is_file():
        raise DieExecutableNotFoundError(resolved)
    return resolved


def _resolve_input(path: Path, max_file_size: int) -> tuple[Path, int]:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise DieInputNotFoundError(Path(path)) from exc
    if not resolved.is_file():
        raise DieInputNotFoundError(resolved, "DIE input must be an explicit regular file")
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise DieInputNotFoundError(resolved, f"could not stat DIE input: {exc}") from exc
    if size > max_file_size:
        raise DieInputTooLargeError(resolved, size, max_file_size)
    return resolved, size


def _bounded_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            f"DIE JSON field {field_name!r} must be a string",
            details={"field": field_name, "actual_type": type(value).__name__},
        )
    if len(value) > _MAX_TEXT:
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            f"DIE JSON field {field_name!r} is too long",
            details={"field": field_name, "max_length": _MAX_TEXT},
        )
    return value


def _required_mapping(value: object, *, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            f"DIE JSON {where} must be an object",
            details={"where": where, "actual_type": type(value).__name__},
        )
    return cast(Mapping[str, Any], value)


def _required_list(value: object, *, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            f"DIE JSON {where} must be an array",
            details={"where": where, "actual_type": type(value).__name__},
        )
    return value


def _field_text(mapping: Mapping[str, Any], field_name: str, *, where: str) -> str:
    if field_name not in mapping:
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            f"DIE JSON {where} is missing {field_name!r}",
            details={"where": where, "field": field_name},
        )
    return _bounded_text(mapping[field_name], field_name=f"{where}.{field_name}")


def _optional_text(mapping: Mapping[str, Any], field_name: str, *, where: str) -> str:
    if field_name not in mapping:
        return ""
    return _bounded_text(mapping[field_name], field_name=f"{where}.{field_name}")


def _category_for(type_name: str) -> FindingCategory:
    normalized = re.sub(r"[^a-z0-9]+", " ", type_name.casefold()).strip()
    if normalized in {"packer", "packers", "compression", "compressor"}:
        return FindingCategory.PACKER
    if normalized in {"compiler", "compilers"}:
        return FindingCategory.COMPILER
    if normalized in {"linker", "linkers"}:
        return FindingCategory.LINKER
    if normalized in {"installer", "installers", "setup"}:
        return FindingCategory.INSTALLER
    if normalized in {"obfuscator", "obfuscation"}:
        return FindingCategory.OBFUSCATOR
    if normalized in {"protector", "protection"}:
        return FindingCategory.PROTECTOR
    if normalized in {
        "runtime",
        "library",
        "interpreter",
        "virtual machine",
        "vm",
    }:
        return FindingCategory.RUNTIME
    if normalized in {
        "file",
        "file format",
        "filetype",
        "format",
        "source",
        "binary format",
    }:
        return FindingCategory.FILE_FORMAT
    return FindingCategory.ANOMALY


def _finding_from_value(
    value: Mapping[str, Any],
    *,
    detect_index: int,
    value_index: int,
    filetype: str,
    detect_info: str,
    parent_file_part: str,
    offset: str,
    size: str,
) -> DetectionFinding:
    where = f"detects[{detect_index}].values[{value_index}]"
    value_type = _field_text(value, "type", where=where)
    name = _field_text(value, "name", where=where)
    string = _field_text(value, "string", where=where)
    info = _field_text(value, "info", where=where)
    version = _field_text(value, "version", where=where)
    category = _category_for(value_type)
    summary = string.strip() or f"{value_type}: {name}"
    if category == FindingCategory.ANOMALY:
        summary = f"DIE reported {value_type}: {name}"
    details: JsonObject = {
        "filetype": filetype,
        "type": value_type,
        "info": info,
        "detect_info": detect_info,
        "version": version,
        "offset": offset,
        "size": size,
        "parentfilepart": parent_file_part,
    }
    return DetectionFinding(
        id=f"die:{detect_index}:{value_index}",
        category=category,
        name=name,
        summary=summary,
        confidence=1.0,
        severity=(
            FindingSeverity.HINT
            if category == FindingCategory.ANOMALY
            else FindingSeverity.INFO
        ),
        source=DIEC_SOURCE,
        evidence=(
            DetectionEvidence(
                kind="die_signature",
                description=string,
                details=details,
            ),
        ),
    )


def _normalize_json(payload: object) -> tuple[tuple[DetectionFinding, ...], JsonObject]:
    root = _required_mapping(payload, where="root")
    detects = _required_list(root.get("detects"), where="root.detects")
    if len(detects) > _MAX_DETECTS:
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            "DIE JSON contains too many detect records",
            details={"count": len(detects), "max": _MAX_DETECTS},
        )

    findings: list[DetectionFinding] = []
    for detect_index, raw_detect in enumerate(detects):
        detect = _required_mapping(raw_detect, where=f"detects[{detect_index}]")
        filetype = _field_text(detect, "filetype", where=f"detects[{detect_index}]")
        if not filetype.strip():
            raise DieProtocolError(
                DieErrorCode.PROTOCOL_ERROR,
                f"DIE JSON detects[{detect_index}].filetype must not be blank",
            )
        detect_where = f"detects[{detect_index}]"
        detect_info = _optional_text(detect, "info", where=detect_where)
        parent_file_part = _optional_text(detect, "parentfilepart", where=detect_where)
        offset = _optional_text(detect, "offset", where=detect_where)
        size = _optional_text(detect, "size", where=detect_where)
        values = _required_list(detect.get("values"), where=f"{detect_where}.values")
        if len(values) > _MAX_VALUES_PER_DETECT:
            raise DieProtocolError(
                DieErrorCode.PROTOCOL_ERROR,
                f"DIE JSON {detect_where}.values contains too many records",
                details={"count": len(values), "max": _MAX_VALUES_PER_DETECT},
            )

        findings.append(
            DetectionFinding(
                id=f"die:format:{detect_index}",
                category=FindingCategory.FILE_FORMAT,
                name=filetype,
                summary=f"DIE detected file format {filetype}",
                confidence=1.0,
                source=DIEC_SOURCE,
                evidence=(
                    DetectionEvidence(
                        kind="die_filetype",
                        description=f"DIE classified the input as {filetype}",
                        details={
                            "filetype": filetype,
                            "info": detect_info,
                            "offset": offset,
                            "size": size,
                            "parentfilepart": parent_file_part,
                        },
                    ),
                ),
            )
        )
        for value_index, raw_value in enumerate(values):
            value = _required_mapping(raw_value, where=f"{detect_where}.values[{value_index}]")
            findings.append(
                _finding_from_value(
                    value,
                    detect_index=detect_index,
                    value_index=value_index,
                    filetype=filetype,
                    detect_info=detect_info,
                    parent_file_part=parent_file_part,
                    offset=offset,
                    size=size,
                )
            )

    # Keep the object typed as JsonObject while retaining all unknown official
    # fields for artifact consumers.  We never mutate the subprocess payload.
    return tuple(findings), dict(root)


def _parse_json(stdout: str) -> tuple[tuple[DetectionFinding, ...], JsonObject]:
    if not stdout.strip():
        raise DieProtocolError(
            DieErrorCode.PROTOCOL_ERROR,
            "diec produced no JSON on stdout",
        )

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    # Official ``diec -j`` may emit notices before JSON, including lines that
    # begin with ``[!]``. Prefer object payloads (``{...}``) and skip false
    # array starts from those notices.
    text = stdout.lstrip("\ufeff")
    decoder = json.JSONDecoder(parse_constant=reject_constant)
    last_error: Exception | None = None
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            payload, _end = decoder.raw_decode(text[index:])
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            last_error = exc
            continue
        try:
            return _normalize_json(payload)
        except DieScanError:
            raise
        except (TypeError, ValueError) as exc:
            raise DieProtocolError(
                DieErrorCode.PROTOCOL_ERROR,
                f"could not normalize DIE JSON: {exc}",
            ) from exc
    raise DieProtocolError(
        DieErrorCode.PROTOCOL_ERROR,
        f"diec returned invalid JSON: {last_error or 'no JSON object found'}",
    )


def _build_argv(executable: Path, path: Path, mode: ScanMode) -> list[str]:
    flag = _MODE_FLAGS[mode]
    argv = [str(executable)]
    if flag is not None:
        argv.append(flag)
    # ``-j`` is intentionally fixed by this adapter.  No caller-supplied
    # switches or environment-derived arguments are accepted.
    argv.extend(("-j", str(path)))
    return argv


def scan_with_die(
    executable: Path,
    path: Path,
    *,
    mode: ScanMode | str = ScanMode.NORMAL,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> DieScanResult:
    """Run official ``diec`` once and return normalized findings.

    ``max_output_size`` applies independently to stdout and stderr.  Both
    streams are drained concurrently, so a noisy child cannot deadlock while
    the adapter enforces the limit.
    """

    normalized_mode = _coerce_mode(mode)
    timeout_value = _validate_positive_number(timeout, "timeout")
    max_file_size_value = _validate_positive_integer(max_file_size, "max_file_size")
    max_output_size_value = _validate_positive_integer(max_output_size, "max_output_size")
    executable_path = _resolve_executable(Path(executable))
    input_path, input_size = _resolve_input(Path(path), max_file_size_value)
    argv = _build_argv(executable_path, input_path, normalized_mode)
    started = monotonic()
    capture = _capture_process(
        argv,
        timeout=timeout_value,
        max_output_size=max_output_size_value,
    )
    if capture.returncode != 0:
        raise DieProcessError(
            DieErrorCode.PROCESS_FAILED,
            f"diec exited with status {capture.returncode}",
            details={"argv": argv},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    try:
        findings, raw = _parse_json(capture.stdout)
    except DieProtocolError as exc:
        raise DieProtocolError(
            exc.code,
            str(exc),
            details=exc.details,
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        ) from exc
    duration_ms = max(0, int((monotonic() - started) * 1000))
    source = DetectionSource(
        name=DIEC_SOURCE,
        status="completed",
        version=None,
        duration_ms=duration_ms,
        summary="Detect It Easy official CLI JSON scan",
    )
    return DieScanResult(
        path=input_path,
        size=input_size,
        mode=normalized_mode,
        findings=findings,
        source=source,
        raw=raw,
        raw_json=capture.stdout,
        stdout=capture.stdout,
        stderr=capture.stderr,
        returncode=capture.returncode,
        scanned_at=datetime.now(UTC),
    )


class DieCliAdapter:
    """Reusable configured wrapper around :func:`scan_with_die`."""

    def __init__(
        self,
        executable: Path,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    ) -> None:
        self.executable = Path(executable)
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.max_output_size = max_output_size

    def scan(
        self,
        path: Path,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
    ) -> DieScanResult:
        return scan_with_die(
            self.executable,
            path,
            mode=mode,
            timeout=self.timeout,
            max_file_size=self.max_file_size,
            max_output_size=self.max_output_size,
        )


# A concise alias is useful to integrations that use verb-first backend names.
scan_die = scan_with_die


__all__ = [
    "DEFAULT_MAX_FILE_SIZE",
    "DEFAULT_MAX_OUTPUT_SIZE",
    "DEFAULT_TIMEOUT",
    "DIEC_SOURCE",
    "DieCliAdapter",
    "DieErrorCode",
    "DieExecutableNotFoundError",
    "DieInputNotFoundError",
    "DieInputTooLargeError",
    "DieOutputLimitError",
    "DieProcessError",
    "DieProtocolError",
    "DieScanError",
    "DieScanResult",
    "DieTimeoutError",
    "scan_die",
    "scan_with_die",
]
