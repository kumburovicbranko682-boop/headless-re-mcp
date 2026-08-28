"""Bounded adapter for optional NETReactorSlayer CLI (GPL-3.0).

Whitelist argv only: ``<input> --no-pause True``. The tool writes
``{stem}_Slayed{suffix}`` beside a work copy; we never overwrite the session
input and never accept arbitrary flags. Configure via
``HEADLESS_RE_NET_REACTOR_SLAYER``.
"""

from __future__ import annotations

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

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    TimedOut,
    run_bounded,
)
from headless_re_mcp.dotnet.de4dot import _capture_process

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT: Final[float] = 120.0
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 8 * 1024 * 1024
NRS_SOURCE: Final[str] = "net_reactor_slayer"
_SLAYED_SUFFIX: Final[str] = "_Slayed"


class NetReactorSlayerErrorCode:
    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    OUTPUT_MISSING = "output_missing"
    INPUT_MUTATED = "input_mutated"


class NetReactorSlayerError(RuntimeError):
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
class NetReactorSlayerResult:
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
            "source": NRS_SOURCE,
            "claims_universal_unpack": False,
            "target": "authorized_reactor_samples_only",
        }


def run_net_reactor_slayer(
    executable: Path,
    input_path: Path,
    output_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
) -> NetReactorSlayerResult:
    """Run NETReactorSlayer on a work copy; publish ``*_Slayed`` to output_path."""
    exe = Path(executable).expanduser()
    # resolve() without strict=True so a missing input surfaces as the structured
    # INPUT_NOT_FOUND error below instead of a raw FileNotFoundError from resolve().
    source = Path(input_path).expanduser().resolve()
    destination = Path(output_path).expanduser()
    if not exe.is_file():
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND,
            f"NETReactorSlayer executable does not exist: {exe}",
            details={"executable": str(exe)},
        )
    if not source.is_file():
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.INPUT_NOT_FOUND,
            f"input assembly not found: {source}",
            details={"input_path": str(source)},
        )
    size = source.stat().st_size
    if size > max_file_size:
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.INPUT_TOO_LARGE,
            f"input exceeds max_file_size={max_file_size}",
            details={"size": size, "max_file_size": max_file_size},
        )
    if destination.exists():
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.INVALID_ARGUMENT,
            "output_path must not already exist",
            details={"output_path": str(destination)},
        )
    if destination.resolve() == source.resolve():
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.INVALID_ARGUMENT,
            "output_path must differ from input_path",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    from headless_re_mcp.core.session import file_sha256

    before = file_sha256(source)
    if before != input_sha256:
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.INPUT_MUTATED,
            "input sha256 changed before NETReactorSlayer",
            details={"expected": input_sha256, "actual": before},
        )

    work_name = f"nrs-{uuid4().hex}"
    started = monotonic()
    try:
        with TemporaryDirectory(prefix=work_name, dir=str(destination.parent)) as tmp:
            work_dir = Path(tmp)
            work_input = work_dir / source.name
            shutil.copy2(source, work_input)
            # Whitelist: assembly path + --no-pause True (avoid "Press any key").
            argv = [str(exe), str(work_input), "--no-pause", "True"]
            try:
                capture = _capture_process(
                    argv, timeout=timeout, max_output_size=max_output_size
                )
            except BoundedCancelled:
                # A caller cancel is not a tool failure; let it propagate as
                # cancellation, the way the scylla/vmp_dumper/xvlkc adapters do.
                # Remapping it here would report the same cancel as
                # process_failed and diverge from every sibling adapter.
                raise
            except Exception as exc:
                # de4dot capture raises De4dotError; remap for this adapter.
                code = getattr(exc, "code", NetReactorSlayerErrorCode.PROCESS_FAILED)
                raise NetReactorSlayerError(
                    str(code) if code else NetReactorSlayerErrorCode.PROCESS_FAILED,
                    str(exc),
                    details=dict(getattr(exc, "details", {}) or {}),
                    stdout=str(getattr(exc, "stdout", "") or ""),
                    stderr=str(getattr(exc, "stderr", "") or ""),
                    returncode=getattr(exc, "returncode", None),
                    retryable=bool(getattr(exc, "retryable", False)),
                ) from exc

            after = file_sha256(source)
            if after != before:
                raise NetReactorSlayerError(
                    NetReactorSlayerErrorCode.INPUT_MUTATED,
                    "NETReactorSlayer mutated the original input assembly",
                    details={"input_path": str(source)},
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                )
            if capture.stdout_exceeded or capture.stderr_exceeded:
                raise NetReactorSlayerError(
                    NetReactorSlayerErrorCode.OUTPUT_LIMIT,
                    "NETReactorSlayer stdout/stderr exceeded bound",
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                )
            if capture.returncode != 0:
                raise NetReactorSlayerError(
                    NetReactorSlayerErrorCode.PROCESS_FAILED,
                    f"NETReactorSlayer exited with {capture.returncode}",
                    details={
                        "argv": [
                            "NETReactorSlayer",
                            "<input>",
                            "--no-pause",
                            "True",
                        ]
                    },
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                    returncode=capture.returncode,
                    retryable=True,
                )

            slayed = work_dir / f"{work_input.stem}{_SLAYED_SUFFIX}{work_input.suffix}"
            if not slayed.is_file():
                # Best-effort: accept any new *_Slayed* file in the work dir.
                candidates = sorted(work_dir.glob(f"*{_SLAYED_SUFFIX}*"))
                if len(candidates) == 1 and candidates[0].is_file():
                    slayed = candidates[0]
                else:
                    raise NetReactorSlayerError(
                        NetReactorSlayerErrorCode.OUTPUT_MISSING,
                        "NETReactorSlayer reported success but *_Slayed output is missing",
                        details={"work_dir": str(work_dir)},
                        stdout=capture.stdout,
                        stderr=capture.stderr,
                        returncode=capture.returncode,
                    )
            shutil.copy2(slayed, destination)
            duration_ms = int((monotonic() - started) * 1000)
            return NetReactorSlayerResult(
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
    except NetReactorSlayerError:
        with suppress(OSError):
            if destination.is_file():
                destination.unlink()
        raise


def probe_net_reactor_slayer(executable: Path, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Best-effort help probe (tool prints usage when no input is given)."""
    exe = Path(executable)
    if not exe.is_file():
        return False, ""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded([str(exe)], timeout=timeout, creationflags=flags)
    except (OSError, TimedOut):
        return False, ""
    text = ((completed.stdout or b"") + b"\n" + (completed.stderr or b"")).decode(
        "utf-8", "replace"
    ).strip()
    lowered = text.casefold()
    if "netreactorslayer" in lowered or "assemblypath" in lowered or "--no-pause" in lowered:
        return True, text[:2000]
    # Many builds still exit non-zero after printing usage.
    if completed.returncode in {0, 1, -1} and "usage" in lowered:
        return True, text[:2000]
    return bool(text), text[:2000]
