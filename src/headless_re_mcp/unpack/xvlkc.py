"""Bounded optional adapter for user-configured XVLKC CLI.

Whitelist argv only: ``<exe> <work-input>``. Work copy lives under a temporary
directory; the original session input is never overwritten. Configure via
``HEADLESS_RE_XVLKC``. Not bundled; ``claims_universal_unpack`` is always false.
"""

from __future__ import annotations

import shutil
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Any, Final
from uuid import uuid4

from headless_re_mcp.dotnet.de4dot import _capture_process, _probe_run

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT: Final[float] = 120.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 8 * 1024 * 1024
XVLKC_SOURCE: Final[str] = "xvlkc"


class XvlkcErrorCode:
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


class XvlkcError(RuntimeError):
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
class XvlkcResult:
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
            "source": XVLKC_SOURCE,
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
    """Pick the newest PE in work_dir that is not the work input; fail-closed if ambiguous."""
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
        raise XvlkcError(
            XvlkcErrorCode.OUTPUT_MISSING,
            "XVLKC produced no PE output beside the work copy",
            details={"work_dir": str(work_dir)},
        )
    candidates.sort(key=lambda item: (item[0], str(item[1])))
    newest_mtime = candidates[-1][0]
    newest = [path for mtime, path in candidates if mtime == newest_mtime]
    if len(newest) != 1:
        raise XvlkcError(
            XvlkcErrorCode.OUTPUT_AMBIGUOUS,
            "XVLKC produced multiple PE outputs with the same newest mtime",
            details={
                "work_dir": str(work_dir),
                "candidates": [str(path) for path in newest],
            },
        )
    return newest[0]


def run_xvlkc(
    executable: Path,
    input_path: Path,
    output_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> XvlkcResult:
    """Run XVLKC on a work copy; publish the newest PE output to output_path."""
    exe = Path(executable).expanduser()
    source = Path(input_path).expanduser().resolve(strict=True)
    destination = Path(output_path).expanduser()
    if not exe.is_file():
        raise XvlkcError(
            XvlkcErrorCode.EXECUTABLE_NOT_FOUND,
            f"XVLKC executable does not exist: {exe}",
            details={"executable": str(exe)},
        )
    if not source.is_file():
        raise XvlkcError(
            XvlkcErrorCode.INPUT_NOT_FOUND,
            f"input binary not found: {source}",
            details={"input_path": str(source)},
        )
    size = source.stat().st_size
    if size > max_file_size:
        raise XvlkcError(
            XvlkcErrorCode.INPUT_TOO_LARGE,
            f"input exceeds max_file_size={max_file_size}",
            details={"size": size, "max_file_size": max_file_size},
        )
    if destination.exists():
        raise XvlkcError(
            XvlkcErrorCode.INVALID_ARGUMENT,
            "output_path must not already exist",
            details={"output_path": str(destination)},
        )
    if destination.resolve() == source.resolve():
        raise XvlkcError(
            XvlkcErrorCode.INVALID_ARGUMENT,
            "output_path must differ from input_path",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    from headless_re_mcp.core.session import file_sha256

    before = file_sha256(source)
    if before != input_sha256:
        raise XvlkcError(
            XvlkcErrorCode.INPUT_MUTATED,
            "input sha256 changed before XVLKC",
            details={"expected": input_sha256, "actual": before},
        )

    work_name = f"xvlkc-{uuid4().hex}"
    started = monotonic()
    try:
        with TemporaryDirectory(prefix=work_name, dir=str(destination.parent)) as tmp:
            work_dir = Path(tmp)
            work_input = work_dir / source.name
            shutil.copy2(source, work_input)
            # Whitelist: executable + work-copy path only.
            argv = [str(exe), str(work_input)]
            try:
                capture = _capture_process(
                    argv, timeout=timeout, max_output_size=max_output_size
                )
            except Exception as exc:
                code = getattr(exc, "code", XvlkcErrorCode.PROCESS_FAILED)
                raise XvlkcError(
                    str(code) if code else XvlkcErrorCode.PROCESS_FAILED,
                    str(exc),
                    details=dict(getattr(exc, "details", {}) or {}),
                    stdout=str(getattr(exc, "stdout", "") or ""),
                    stderr=str(getattr(exc, "stderr", "") or ""),
                    returncode=getattr(exc, "returncode", None),
                    retryable=bool(getattr(exc, "retryable", False)),
                ) from exc

            after = file_sha256(source)
            if after != before:
                raise XvlkcError(
                    XvlkcErrorCode.INPUT_MUTATED,
                    "XVLKC mutated the original input binary",
                    details={"input_path": str(source)},
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                )
            if capture.stdout_exceeded or capture.stderr_exceeded:
                raise XvlkcError(
                    XvlkcErrorCode.OUTPUT_LIMIT,
                    "XVLKC stdout/stderr exceeded bound",
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                )
            if capture.returncode != 0:
                raise XvlkcError(
                    XvlkcErrorCode.PROCESS_FAILED,
                    f"XVLKC exited with {capture.returncode}",
                    details={"argv": ["xvlkc", "<input>"]},
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                    retryable=True,
                )

            produced = _collect_newest_pe(work_dir, work_input)
            shutil.copy2(produced, destination)
            duration_ms = int((monotonic() - started) * 1000)
            return XvlkcResult(
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
    except XvlkcError:
        with suppress(OSError):
            if destination.is_file():
                destination.unlink()
        raise


def probe_xvlkc(executable: Path, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Best-effort probe (help / no-arg usage).

    ``subprocess.run(timeout=...)`` killed only the process it spawned.
    Measured: a launcher that started a sleeper, timeout 0.4s, left one
    orphan reparented to pid 1.
    """
    exe = Path(executable)
    if not exe.is_file():
        return False, ""
    try:
        completed = _probe_run([str(exe)], timeout)
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    text = (
        (completed.stdout or b"").decode("utf-8", errors="replace")
        + "\n"
        + (completed.stderr or b"").decode("utf-8", errors="replace")
    ).strip()
    lowered = text.casefold()
    if any(token in lowered for token in ("xvlk", "usage", "unpack", "input")):
        return True, text[:2000]
    if completed.returncode in {0, 1, -1} and text:
        return True, text[:2000]
    return bool(text), text[:2000]
