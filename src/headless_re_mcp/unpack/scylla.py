"""Bounded optional adapter for user-configured Scylla (x86/x64) CLI.

Whitelist argv only: ``<exe> <work-input>``. Work copy lives under a temporary
directory; the original session input is never overwritten. Configure via
``HEADLESS_RE_SCYLLA``. Not bundled; ``claims_universal_unpack`` is always false.

Many Scylla builds are GUI-first and may time out or produce no PE; probe and
run fail closed without claiming IAT recovery.
"""

from __future__ import annotations

import math
import os
import shutil
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Any, Final
from uuid import uuid4

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut, run_bounded
from headless_re_mcp.dotnet.de4dot import _capture_process

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT: Final[float] = 120.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 8 * 1024 * 1024
SCYLLA_SOURCE: Final[str] = "scylla"


class ScyllaErrorCode:
    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    OUTPUT_MISSING = "output_missing"
    OUTPUT_AMBIGUOUS = "output_ambiguous"
    INPUT_MUTATED = "input_mutated"


class ScyllaError(RuntimeError):
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
class ScyllaResult:
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
            "source": SCYLLA_SOURCE,
            "claims_universal_unpack": False,
        }


def _is_pe_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(0x40)
    except OSError:
        return False
    if len(header) < 0x40 or header[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    if pe_offset < 0x40:
        return False
    try:
        with path.open("rb") as handle:
            handle.seek(pe_offset)
            sig = handle.read(4)
    except OSError:
        return False
    return sig == b"PE\0\0"


def _collect_newest_pe(work_dir: Path, work_input: Path) -> Path:
    candidates: list[tuple[float, Path]] = []
    work_resolved = work_input.resolve()
    for path in work_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.resolve() == work_resolved:
                continue
        except OSError:
            continue
        if not _is_pe_file(path):
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        candidates.append((mtime, path))
    if not candidates:
        raise ScyllaError(
            ScyllaErrorCode.OUTPUT_MISSING,
            "Scylla produced no PE output beside the work copy",
            details={"work_dir": str(work_dir)},
        )
    candidates.sort(key=lambda item: (item[0], str(item[1])))
    newest_mtime = candidates[-1][0]
    newest = [path for mtime, path in candidates if mtime == newest_mtime]
    if len(newest) != 1:
        raise ScyllaError(
            ScyllaErrorCode.OUTPUT_AMBIGUOUS,
            "Scylla produced multiple PE outputs with the same newest mtime",
            details={
                "work_dir": str(work_dir),
                "candidates": [str(path) for path in newest],
            },
        )
    return newest[0]


def _validate_positive_number(value: float, name: str) -> float:
    """Reject a NaN/inf/non-positive deadline before spawning Scylla.

    The shared ``_capture_process`` derives ``deadline = monotonic() +
    timeout``; a NaN or inf value makes ``remaining <= 0`` never true and the
    poll loop fall to a fixed 0.05s sleep forever, so the deadline is silently
    disabled and a wedged tool holds a worker until cancellation or the output
    cap. The tool schema keeps ``0 < timeout <= 600`` but the agent transport
    calls handlers straight from model arguments, so validate here as
    die/upx/exeinfope already do at their own entry points.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScyllaError(
            ScyllaErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive finite number",
            details={name: repr(value)},
        )
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0:
        raise ScyllaError(
            ScyllaErrorCode.INVALID_ARGUMENT,
            f"{name} must be a positive finite number",
            details={name: converted},
        )
    return converted


def run_scylla(
    executable: Path,
    input_path: Path,
    output_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> ScyllaResult:
    """Run Scylla on a work copy; publish the newest PE output to output_path."""
    timeout = _validate_positive_number(timeout, "timeout")
    exe = Path(executable).expanduser()
    source = Path(input_path).expanduser().resolve(strict=True)
    destination = Path(output_path).expanduser()
    if not exe.is_file():
        raise ScyllaError(
            ScyllaErrorCode.EXECUTABLE_NOT_FOUND,
            f"Scylla executable does not exist: {exe}",
            details={"executable": str(exe)},
        )
    if not source.is_file():
        raise ScyllaError(
            ScyllaErrorCode.INPUT_NOT_FOUND,
            f"input binary not found: {source}",
            details={"input_path": str(source)},
        )
    size = source.stat().st_size
    if size > max_file_size:
        raise ScyllaError(
            ScyllaErrorCode.INPUT_TOO_LARGE,
            f"input exceeds max_file_size={max_file_size}",
            details={"size": size, "max_file_size": max_file_size},
        )
    if destination.exists():
        raise ScyllaError(
            ScyllaErrorCode.INVALID_ARGUMENT,
            "output_path must not already exist",
            details={"output_path": str(destination)},
        )
    if destination.resolve() == source.resolve():
        raise ScyllaError(
            ScyllaErrorCode.INVALID_ARGUMENT,
            "output_path must differ from input_path",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    from headless_re_mcp.core.session import file_sha256

    before = file_sha256(source)
    if before != input_sha256:
        raise ScyllaError(
            ScyllaErrorCode.INPUT_MUTATED,
            "input sha256 changed before Scylla",
            details={"expected": input_sha256, "actual": before},
        )

    work_name = f"scylla-{uuid4().hex}"
    started = monotonic()
    try:
        with TemporaryDirectory(prefix=work_name, dir=str(destination.parent)) as tmp:
            work_dir = Path(tmp)
            work_input = work_dir / source.name
            shutil.copy2(source, work_input)
            argv = [str(exe), str(work_input)]
            try:
                capture = _capture_process(
                    argv, timeout=timeout, max_output_size=max_output_size
                )
            except BoundedCancelled:
                raise
            except Exception as exc:
                code = getattr(exc, "code", ScyllaErrorCode.PROCESS_FAILED)
                raise ScyllaError(
                    str(code) if code else ScyllaErrorCode.PROCESS_FAILED,
                    str(exc),
                    details=dict(getattr(exc, "details", {}) or {}),
                    stdout=str(getattr(exc, "stdout", "") or ""),
                    stderr=str(getattr(exc, "stderr", "") or ""),
                    returncode=getattr(exc, "returncode", None),
                    retryable=bool(getattr(exc, "retryable", False)),
                ) from exc

            after = file_sha256(source)
            if after != before:
                raise ScyllaError(
                    ScyllaErrorCode.INPUT_MUTATED,
                    "Scylla mutated the original input binary",
                    details={"input_path": str(source)},
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                )
            if capture.stdout_exceeded or capture.stderr_exceeded:
                raise ScyllaError(
                    ScyllaErrorCode.OUTPUT_LIMIT,
                    "Scylla stdout/stderr exceeded bound",
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                )
            if capture.returncode != 0:
                raise ScyllaError(
                    ScyllaErrorCode.PROCESS_FAILED,
                    f"Scylla exited with {capture.returncode}",
                    details={"argv": ["scylla", "<input>"]},
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                    retryable=True,
                )

            produced = _collect_newest_pe(work_dir, work_input)
            shutil.copy2(produced, destination)
            duration_ms = int((monotonic() - started) * 1000)
            return ScyllaResult(
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
    except ScyllaError:
        with suppress(OSError):
            if destination.is_file():
                destination.unlink()
        raise


def probe_scylla(executable: Path, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Best-effort probe: file exists and process starts (GUI builds may return empty)."""
    exe = Path(executable)
    if not exe.is_file():
        return False, ""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded([str(exe)], timeout=timeout, creationflags=flags)
    except TimedOut:
        # GUI Scylla often never exits. The tree is already dead, so the
        # window is not left behind; that is not the same as "available".
        return False, "timeout_after_start"
    except OSError:
        return False, ""
    text = ((completed.stdout or b"") + b"\n" + (completed.stderr or b"")).decode(
        "utf-8", "replace"
    ).strip()
    lowered = text.casefold()
    if any(token in lowered for token in ("scylla", "usage", "iat", "import", "dump")):
        return True, text[:2000]
    if completed.returncode in {0, 1, -1}:
        return True, text[:2000] if text else "started"
    return bool(text), text[:2000]