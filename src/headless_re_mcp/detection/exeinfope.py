"""Bounded optional adapter for user-supplied Exeinfo PE (second-opinion detect).

Exeinfo PE is Freeware (non-OSI) and is **not** bundled. Callers configure
``HEADLESS_RE_EXEINFOPE`` to a self-obtained official binary. This adapter:

* builds a fixed argv whitelist only (``<file>* /s /log:<path>``);
* never uses a shell and never forwards arbitrary switches;
* enforces timeout, input size, and log/output byte limits;
* monitors **visible** analyzer top-level windows and fails if main UI / modal
  forms appear (transient invisible Delphi forms + brief ``TApplication``
  "Please wait" are tolerated under ``/s``);
* best-effort parses the text log into :class:`DetectionFinding` rows with
  ``source=exeinfope`` — never merges into DIE as a single authoritative answer;
* always treats results as a cross-check (``claims_universal_unpack`` stays false
  at the service layer).

Optional user-supplied binary only; not bundled.
"""

from __future__ import annotations

import math
import os
import re
import subprocess
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
from time import monotonic
from typing import Any, BinaryIO, Final

from pydantic import BaseModel, ConfigDict, Field

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, active_bound_cancel
from headless_re_mcp.core.windows import describe_process_windows
from headless_re_mcp.detection.models import (
    DetectionEvidence,
    DetectionFinding,
    DetectionSource,
    FindingCategory,
    FindingSeverity,
    JsonObject,
    ScanMode,
)

DEFAULT_TIMEOUT: Final[float] = 30.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 4 * 1024 * 1024
DEFAULT_MAX_LOG_SIZE: Final[int] = 4 * 1024 * 1024
EXEINFOPE_SOURCE: Final[str] = "exeinfope"
_READ_CHUNK_SIZE: Final[int] = 64 * 1024
_MAX_TEXT: Final[int] = 32_768
_MAX_LOG_LINES: Final[int] = 4096

# Visible windows of these classes mean the GUI leaked past silent mode.
_BLOCKED_VISIBLE_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "TForm1",
        "TMessageForm",
        "TMultiS_GUI",
        "THelpGUI",
        "TAboutGUI",
        "TkonfigGUI",
        "TImportGUI",
        "THeader_GUI",
        "TsekcjeGUI",
        "TDasm_GUI",
        "TNET_GUI",
        "TDFM_GUI",
        "TSearchString_GUI",
        "TFileCharFlag",
        "TSViewer",
        "TAdrConvert",
        "TWinStat",
    }
)

_PACKER_HINTS: Final[tuple[str, ...]] = (
    "upx",
    "aspack",
    "mpress",
    "petite",
    "nspack",
    "pack",
    "compress",
)
_PROTECTOR_HINTS: Final[tuple[str, ...]] = (
    "themida",
    "vmprotect",
    "enigma",
    "obsidium",
    "safengine",
    "protect",
    "armor",
)
_OBFUSCATOR_HINTS: Final[tuple[str, ...]] = (
    "obfuscat",
    "confuser",
    "smartassembly",
    "babel",
    "dotfuscator",
    "reactor",
)
_INSTALLER_HINTS: Final[tuple[str, ...]] = (
    "installer",
    "nullsoft",
    "inno",
    "wise",
    "installshield",
    "sfx",
)
_COMPILER_HINTS: Final[tuple[str, ...]] = (
    "visual c++",
    "msvc",
    "borland",
    "delphi",
    "mingw",
    "gcc",
    "clang",
    "rustc",
    "rust compiler",
    "go compiler",
    "compiler",
    "linker",
)


class ExeinfopeErrorCode:
    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    PROTOCOL_ERROR = "protocol_error"
    GUI_WINDOW_DETECTED = "gui_window_detected"
    LOG_MISSING = "log_missing"


class ExeinfopeScanError(RuntimeError):
    """Structured failure while invoking or parsing Exeinfo PE."""

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


class ExeinfopeExecutableNotFoundError(ExeinfopeScanError):
    def __init__(self, executable: Path, message: str | None = None) -> None:
        super().__init__(
            ExeinfopeErrorCode.EXECUTABLE_NOT_FOUND,
            message or f"Exeinfo PE executable does not exist: {executable}",
            details={"executable": str(executable)},
        )


class ExeinfopeInputNotFoundError(ExeinfopeScanError):
    def __init__(self, path: Path, message: str | None = None) -> None:
        super().__init__(
            ExeinfopeErrorCode.INPUT_NOT_FOUND,
            message or f"Exeinfo PE input file does not exist: {path}",
            details={"path": str(path)},
        )


class ExeinfopeInputTooLargeError(ExeinfopeScanError):
    def __init__(self, path: Path, size: int, maximum: int) -> None:
        super().__init__(
            ExeinfopeErrorCode.INPUT_TOO_LARGE,
            f"Exeinfo PE input is larger than the configured limit ({size} > {maximum} bytes)",
            details={"path": str(path), "size": size, "max_file_size": maximum},
        )


class ExeinfopeTimeoutError(ExeinfopeScanError):
    def __init__(self, timeout: float, **kwargs: Any) -> None:
        super().__init__(
            ExeinfopeErrorCode.TIMEOUT,
            f"Exeinfo PE did not finish within {timeout:g} seconds",
            details={"timeout": timeout},
            retryable=True,
            **kwargs,
        )


class ExeinfopeOutputLimitError(ExeinfopeScanError):
    def __init__(self, maximum: int, *, stream: str, **kwargs: Any) -> None:
        super().__init__(
            ExeinfopeErrorCode.OUTPUT_LIMIT,
            f"Exeinfo PE {stream} exceeded the configured output limit ({maximum} bytes)",
            details={"stream": stream, "max_output_size": maximum},
            **kwargs,
        )


class ExeinfopeProcessError(ExeinfopeScanError):
    pass


class ExeinfopeProtocolError(ExeinfopeScanError):
    pass


class ExeinfopeGuiWindowError(ExeinfopeScanError):
    def __init__(self, windows: list[str], **kwargs: Any) -> None:
        super().__init__(
            ExeinfopeErrorCode.GUI_WINDOW_DETECTED,
            "Exeinfo PE created a visible analyzer top-level window",
            details={"analyzer_windows": windows},
            **kwargs,
        )


class ExeinfopeScanResult(BaseModel):
    """Normalized Exeinfo PE findings plus bounded raw log artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: Path
    size: int = Field(ge=0)
    mode: ScanMode
    findings: tuple[DetectionFinding, ...]
    source: DetectionSource
    raw_log: str
    log_path: Path
    stdout: str
    stderr: str
    returncode: int
    scanned_at: datetime
    analyzer_windows: tuple[str, ...] = ()
    claims_universal_unpack: bool = False

    def to_dict(self) -> JsonObject:
        value = self.model_dump(mode="json")
        if not isinstance(value, dict):
            raise TypeError("Exeinfo PE result did not serialize to an object")
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
            # The reader owns its pipe and closes it here once read() returns.
            # The capture thread must never close a pipe this thread might still
            # be blocked on -- that deadlocks on the stream's lock.
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
    analyzer_windows: tuple[str, ...]


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
        # Its own session so a timeout kill can signal the whole group and reach
        # a wrapper's child the parent/child walk would miss.
        options["start_new_session"] = True
    return options


def _parse_window_class(description: str) -> str:
    # describe_process_windows → "0xhwnd:ClassName:title"
    parts = description.split(":", 2)
    return parts[1] if len(parts) >= 2 else ""


def _is_visible_window(description: str, *, visible_check: Callable[[int], bool]) -> bool:
    try:
        hwnd_text = description.split(":", 1)[0]
        hwnd = int(hwnd_text, 16)
    except (ValueError, IndexError):
        return True
    try:
        return bool(visible_check(hwnd))
    except OSError:
        return True


def _visible_blocked_windows(
    descriptions: set[str],
    *,
    visible_check: Callable[[int], bool] | None = None,
) -> list[str]:
    if os.name == "nt" and visible_check is None:
        import ctypes

        visible_check = ctypes.windll.user32.IsWindowVisible  # type: ignore[attr-defined,unused-ignore]
    elif visible_check is None:
        return []

    blocked: list[str] = []
    for item in sorted(descriptions):
        class_name = _parse_window_class(item)
        if class_name not in _BLOCKED_VISIBLE_CLASSES:
            continue
        if _is_visible_window(item, visible_check=visible_check):
            blocked.append(item)
    return blocked


def _capture_process(
    argv: list[str],
    *,
    timeout: float,
    max_output_size: int,
    window_observer: Callable[[int], set[str]] | None = None,
) -> _ProcessCapture:
    try:
        process = subprocess.Popen(argv, **_creation_options())
        from headless_re_mcp.process_group import assign_to_process_group

        pid = getattr(process, "pid", None)
        if pid:
            assign_to_process_group(int(pid))
    except FileNotFoundError as exc:
        raise ExeinfopeExecutableNotFoundError(Path(argv[0])) from exc
    except OSError as exc:
        raise ExeinfopeProcessError(
            ExeinfopeErrorCode.PROCESS_FAILED,
            f"could not start Exeinfo PE: {exc}",
            details={"executable": argv[0], "os_error": str(exc)},
        ) from exc

    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate_process(process)
        raise ExeinfopeProcessError(
            ExeinfopeErrorCode.PROCESS_FAILED,
            "Exeinfo PE process did not expose stdout/stderr pipes",
        )

    observed: set[str] = set()
    stop_monitor = Event()
    observer = window_observer or describe_process_windows

    def monitor() -> None:
        while not stop_monitor.wait(0.05):
            with suppress(OSError, ValueError):
                pid = getattr(process, "pid", None)
                if pid:
                    observed.update(observer(int(pid)))

    limit_event = Event()
    stdout_capture = _CapturedStream(max_output_size)
    stderr_capture = _CapturedStream(max_output_size)
    stdout_thread = Thread(
        target=stdout_capture.read_from,
        args=(stdout_pipe, limit_event),
        name="exeinfope-stdout",
        daemon=True,
    )
    stderr_thread = Thread(
        target=stderr_capture.read_from,
        args=(stderr_pipe, limit_event),
        name="exeinfope-stderr",
        daemon=True,
    )
    monitor_thread = Thread(target=monitor, name="exeinfope-windows", daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    monitor_thread.start()

    deadline = monotonic() + timeout
    timed_out = False
    limited = False
    cancelled = False
    stop = active_bound_cancel()
    returncode: int | None = None
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
            try:
                returncode = process.wait(timeout=min(remaining, 0.05))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if timed_out or limited or cancelled:
            _terminate_process(process)
        else:
            try:
                returncode = process.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                _terminate_process(process)
                returncode = process.poll()
        stop_monitor.set()
        stdout_thread.join(timeout=1.0)
        stderr_thread.join(timeout=1.0)
        monitor_thread.join(timeout=1.0)
        # Exeinfo PE can exit 0 while a helper it spawned lingers, reparented to
        # init. Reap the launcher's session group so a completed scan leaves
        # nothing behind; a survivor also lets the readers finish so the
        # conditional close below never wedges.
        from headless_re_mcp.core.process_tree import terminate_leftover_process_tree

        terminate_leftover_process_tree(process, wait_s=1.0)
        # The readers close their own pipes; only close here when the reader has
        # finished, so a reader still blocked on a survivor's pipe never wedges
        # this thread on close().
        if not stdout_thread.is_alive():
            _close_pipe(stdout_pipe)
        if not stderr_thread.is_alive():
            _close_pipe(stderr_pipe)
        with suppress(OSError, ValueError):
            observed.update(observer(process.pid))

    if returncode is None:
        returncode = -1
    capture = _ProcessCapture(
        stdout_capture.text(),
        stderr_capture.text(),
        int(returncode),
        stdout_capture.exceeded,
        stderr_capture.exceeded,
        tuple(sorted(observed)),
    )
    if cancelled:
        raise BoundedCancelled()
    if timed_out:
        error = ExeinfopeTimeoutError(
            timeout,
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
        error.details["analyzer_windows"] = list(capture.analyzer_windows)
        raise error
    if capture.stdout_exceeded:
        raise ExeinfopeOutputLimitError(
            max_output_size,
            stream="stdout",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    if capture.stderr_exceeded:
        raise ExeinfopeOutputLimitError(
            max_output_size,
            stream="stderr",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    blocked = _visible_blocked_windows(set(capture.analyzer_windows))
    if blocked:
        raise ExeinfopeGuiWindowError(
            blocked,
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    return capture


def _terminate_process(process: Any) -> None:
    """Stop the scanner and anything it started; see die._terminate_process."""
    from headless_re_mcp.core.process_tree import terminate_process_tree

    terminate_process_tree(process, wait_s=1.0)


def _close_pipe(pipe: Any) -> None:
    with suppress(OSError, AttributeError, ValueError):
        pipe.close()


def _coerce_mode(mode: ScanMode | str) -> ScanMode:
    try:
        return mode if isinstance(mode, ScanMode) else ScanMode(mode)
    except (TypeError, ValueError) as exc:
        raise ExeinfopeScanError(
            ExeinfopeErrorCode.INVALID_ARGUMENT,
            f"unsupported Exeinfo PE scan mode: {mode!r}",
            details={"mode": repr(mode), "allowed": [item.value for item in ScanMode]},
        ) from exc


def _validate_positive_number(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExeinfopeScanError(
            ExeinfopeErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive finite number",
            details={name: repr(value)},
        )
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0:
        raise ExeinfopeScanError(
            ExeinfopeErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive finite number",
            details={name: converted},
        )
    return converted


def _validate_positive_integer(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExeinfopeScanError(
            ExeinfopeErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive integer",
            details={name: repr(value)},
        )
    return value


def _resolve_executable(executable: Path) -> Path:
    try:
        resolved = Path(executable).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise ExeinfopeExecutableNotFoundError(Path(executable)) from exc
    if not resolved.is_file():
        raise ExeinfopeExecutableNotFoundError(resolved)
    return resolved


def _resolve_input(path: Path, max_file_size: int) -> tuple[Path, int]:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise ExeinfopeInputNotFoundError(Path(path)) from exc
    if not resolved.is_file():
        raise ExeinfopeInputNotFoundError(
            resolved, "Exeinfo PE input must be an explicit regular file"
        )
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise ExeinfopeInputNotFoundError(
            resolved, f"could not stat Exeinfo PE input: {exc}"
        ) from exc
    if size > max_file_size:
        raise ExeinfopeInputTooLargeError(resolved, size, max_file_size)
    return resolved, size


def _resolve_log_path(log_path: Path) -> Path:
    resolved = Path(log_path).expanduser()
    if resolved.exists() and not resolved.is_file():
        raise ExeinfopeScanError(
            ExeinfopeErrorCode.INVALID_ARGUMENT,
            "Exeinfo PE log path must be a regular file path",
            details={"log_path": str(resolved)},
        )
    parent = resolved.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ExeinfopeScanError(
            ExeinfopeErrorCode.INVALID_ARGUMENT,
            f"could not create Exeinfo PE log directory: {exc}",
            details={"log_path": str(resolved)},
        ) from exc
    return resolved.resolve()


def _log_flag(log_path: Path) -> str:
    text = str(log_path)
    if any(ch.isspace() for ch in text):
        return f'/log:"{text}"'
    return f"/log:{text}"


def _input_mask(path: Path) -> str:
    # Exeinfo silent multifile mode requires a trailing '*' on the path token.
    text = str(path)
    return text if text.endswith("*") else f"{text}*"


def _build_argv(executable: Path, path: Path, log_path: Path) -> list[str]:
    # Fixed whitelist only — no caller switches, no /un7zip, no shell.
    return [str(executable), _input_mask(path), "/s", _log_flag(log_path)]


def _category_for(text: str) -> FindingCategory:
    normalized = text.casefold()
    if any(hint in normalized for hint in _PROTECTOR_HINTS):
        return FindingCategory.PROTECTOR
    if any(hint in normalized for hint in _OBFUSCATOR_HINTS):
        return FindingCategory.OBFUSCATOR
    if any(hint in normalized for hint in _PACKER_HINTS):
        return FindingCategory.PACKER
    if any(hint in normalized for hint in _INSTALLER_HINTS):
        return FindingCategory.INSTALLER
    if any(hint in normalized for hint in _COMPILER_HINTS):
        return FindingCategory.COMPILER
    if ".net" in normalized or "clr" in normalized:
        return FindingCategory.RUNTIME
    if "pe" in normalized or "executable" in normalized:
        return FindingCategory.FILE_FORMAT
    return FindingCategory.ANOMALY


def _name_for(description: str) -> str:
    match = re.search(
        r"\b(UPX|ASPack|MPRESS|Themida|VMProtect|Enigma|Confuser|SmartAssembly|"
        r"NET Reactor|Inno Setup|Nullsoft|MinGW|Delphi|Rust|Go)\b",
        description,
        re.I,
    )
    if match:
        return match.group(1)
    tokens = re.split(r"[\s\[\]\(\)\-/]+", description.strip())
    for token in tokens:
        if token and token.casefold() not in {"x64", "x86", "exe", "dll", "pe"}:
            return token[:128]
    return "exeinfope"


def parse_exeinfope_log(raw_log: str) -> tuple[DetectionFinding, ...]:
    """Best-effort parse of Exeinfo ``/log`` text into detection findings."""

    text = raw_log.lstrip("\ufeff")
    if len(text.encode("utf-8", errors="replace")) > DEFAULT_MAX_LOG_SIZE:
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.PROTOCOL_ERROR,
            "Exeinfo PE log exceeds the configured size limit",
            details={"max_log_size": DEFAULT_MAX_LOG_SIZE},
        )
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > _MAX_LOG_LINES:
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.PROTOCOL_ERROR,
            "Exeinfo PE log contains too many lines",
            details={"count": len(lines), "max": _MAX_LOG_LINES},
        )
    if not lines:
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.PROTOCOL_ERROR,
            "Exeinfo PE log is empty",
        )

    findings: list[DetectionFinding] = []
    for index, line in enumerate(lines):
        if len(line) > _MAX_TEXT:
            raise ExeinfopeProtocolError(
                ExeinfopeErrorCode.PROTOCOL_ERROR,
                f"Exeinfo PE log line {index} is too long",
                details={"index": index, "max_length": _MAX_TEXT},
            )
        if " - " in line:
            _file_part, description = line.split(" - ", 1)
            description = description.strip() or line
        else:
            description = line
        category = _category_for(description)
        name = _name_for(description)
        findings.append(
            DetectionFinding(
                id=f"exeinfope:{index}",
                category=category,
                name=name,
                summary=description,
                confidence=0.55,
                severity=(
                    FindingSeverity.HINT
                    if category == FindingCategory.ANOMALY
                    else FindingSeverity.INFO
                ),
                source=EXEINFOPE_SOURCE,
                evidence=(
                    DetectionEvidence(
                        kind="exeinfope_log_line",
                        description=description,
                        details={"raw_line": line, "parser": "best_effort"},
                    ),
                ),
            )
        )
    return tuple(findings)


def _read_log(log_path: Path, max_log_size: int) -> str:
    if not log_path.is_file():
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.LOG_MISSING,
            f"Exeinfo PE did not write the expected log file: {log_path}",
            details={"log_path": str(log_path)},
        )
    try:
        with log_path.open("rb") as stream:
            payload = stream.read(max_log_size + 1)
    except OSError as exc:
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.PROTOCOL_ERROR,
            f"could not read Exeinfo PE log: {exc}",
            details={"log_path": str(log_path)},
        ) from exc
    if len(payload) > max_log_size:
        error = ExeinfopeOutputLimitError(max_log_size, stream="log")
        error.details["log_path"] = str(log_path)
        error.details["size_at_least"] = len(payload)
        raise error
    return payload.decode("utf-8", errors="replace")


def scan_with_exeinfope(
    executable: Path,
    path: Path,
    *,
    log_path: Path,
    mode: ScanMode | str = ScanMode.NORMAL,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_log_size: int = DEFAULT_MAX_LOG_SIZE,
    window_observer: Callable[[int], set[str]] | None = None,
) -> ExeinfopeScanResult:
    """Run Exeinfo PE once with whitelisted argv and return normalized findings."""

    normalized_mode = _coerce_mode(mode)
    timeout_value = _validate_positive_number(timeout, "timeout")
    max_file_size_value = _validate_positive_integer(max_file_size, "max_file_size")
    max_output_size_value = _validate_positive_integer(max_output_size, "max_output_size")
    max_log_size_value = _validate_positive_integer(max_log_size, "max_log_size")
    executable_path = _resolve_executable(Path(executable))
    input_path, input_size = _resolve_input(Path(path), max_file_size_value)
    resolved_log = _resolve_log_path(Path(log_path))
    if resolved_log.exists():
        with suppress(OSError):
            resolved_log.unlink()
    argv = _build_argv(executable_path, input_path, resolved_log)
    started = monotonic()
    capture = _capture_process(
        argv,
        timeout=timeout_value,
        max_output_size=max_output_size_value,
        window_observer=window_observer,
    )
    if capture.returncode != 0:
        raise ExeinfopeProcessError(
            ExeinfopeErrorCode.PROCESS_FAILED,
            f"Exeinfo PE exited with status {capture.returncode}",
            details={
                "argv": argv,
                "analyzer_windows": list(capture.analyzer_windows),
            },
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )
    try:
        raw_log = _read_log(resolved_log, max_log_size_value)
        findings = parse_exeinfope_log(raw_log)
    except ExeinfopeScanError as exc:
        exc.details.setdefault("argv", argv)
        if not exc.stdout:
            exc.stdout = capture.stdout
        if not exc.stderr:
            exc.stderr = capture.stderr
        if exc.returncode is None:
            exc.returncode = capture.returncode
        raise
    duration_ms = max(0, int((monotonic() - started) * 1000))
    source = DetectionSource(
        name=EXEINFOPE_SOURCE,
        status="completed",
        version=None,
        duration_ms=duration_ms,
        summary="Exeinfo PE optional second-opinion log scan",
        artifact=str(resolved_log),
    )
    return ExeinfopeScanResult(
        path=input_path,
        size=input_size,
        mode=normalized_mode,
        findings=findings,
        source=source,
        raw_log=raw_log,
        log_path=resolved_log,
        stdout=capture.stdout,
        stderr=capture.stderr,
        returncode=capture.returncode,
        scanned_at=datetime.now(UTC),
        analyzer_windows=capture.analyzer_windows,
        claims_universal_unpack=False,
    )


class ExeinfopeCliAdapter:
    """Reusable configured wrapper around :func:`scan_with_exeinfope`."""

    def __init__(
        self,
        executable: Path,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
        max_log_size: int = DEFAULT_MAX_LOG_SIZE,
    ) -> None:
        self.executable = Path(executable)
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.max_output_size = max_output_size
        self.max_log_size = max_log_size

    def scan(
        self,
        path: Path,
        *,
        log_path: Path,
        mode: ScanMode | str = ScanMode.NORMAL,
    ) -> ExeinfopeScanResult:
        return scan_with_exeinfope(
            self.executable,
            path,
            log_path=log_path,
            mode=mode,
            timeout=self.timeout,
            max_file_size=self.max_file_size,
            max_output_size=self.max_output_size,
            max_log_size=self.max_log_size,
        )


scan_exeinfope = scan_with_exeinfope


__all__ = [
    "DEFAULT_MAX_FILE_SIZE",
    "DEFAULT_MAX_LOG_SIZE",
    "DEFAULT_MAX_OUTPUT_SIZE",
    "DEFAULT_TIMEOUT",
    "EXEINFOPE_SOURCE",
    "ExeinfopeCliAdapter",
    "ExeinfopeErrorCode",
    "ExeinfopeExecutableNotFoundError",
    "ExeinfopeGuiWindowError",
    "ExeinfopeInputNotFoundError",
    "ExeinfopeInputTooLargeError",
    "ExeinfopeOutputLimitError",
    "ExeinfopeProcessError",
    "ExeinfopeProtocolError",
    "ExeinfopeScanError",
    "ExeinfopeScanResult",
    "ExeinfopeTimeoutError",
    "parse_exeinfope_log",
    "scan_exeinfope",
    "scan_with_exeinfope",
]
