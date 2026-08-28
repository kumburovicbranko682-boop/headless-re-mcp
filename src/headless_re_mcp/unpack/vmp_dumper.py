"""Bounded optional adapter for user-configured VMPDump (0xnobody/vmpdump).

Upstream: https://github.com/0xnobody/vmpdump (GPL-3.0). Works for VMProtect 3.x
**x64** only. Toolkit binary ``VMPx64Dump3.x-3.5.exe`` embeds PDB paths under
``.../GitHub/vmpdump/...`` and the same ``-ep=`` / ``-disable-reloc`` CLI.

Whitelist argv only::

    <exe> <pid> <module> [-ep=<hex>] [-disable-reloc]

``module`` may be an empty string to select the process image. Output is written
beside the live module (stdout: ``File written to: ...``); this adapter copies
that PE into the session artifact path. Original session input is never
overwritten. Configure via ``HEADLESS_RE_VMP_DUMPER``. Not bundled;
``claims_universal_unpack`` is always false; ``vm_restored`` stays false.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any, Final

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut, run_bounded
from headless_re_mcp.dotnet.de4dot import _capture_process

JsonObject = dict[str, Any]

DEFAULT_TIMEOUT: Final[float] = 120.0
DEFAULT_MAX_OUTPUT_SIZE: Final[int] = 8 * 1024 * 1024
VMP_DUMPER_SOURCE: Final[str] = "vmp_dumper"
VMPDUMP_UPSTREAM: Final[str] = "https://github.com/0xnobody/vmpdump"
VMPDUMP_LICENSE: Final[str] = "GPL-3.0"
VMPDUMP_ARCH: Final[str] = "x64"
_FILE_WRITTEN_RE: Final[re.Pattern[str]] = re.compile(
    r"File written to:\s*(.+)", re.IGNORECASE
)


class VmpDumperErrorCode:
    INVALID_ARGUMENT = "invalid_argument"
    EXECUTABLE_NOT_FOUND = "executable_not_found"
    INPUT_NOT_FOUND = "input_not_found"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PROCESS_FAILED = "process_failed"
    OUTPUT_MISSING = "output_missing"
    OUTPUT_AMBIGUOUS = "output_ambiguous"
    DEBUGGEE_REQUIRED = "debuggee_required"


class VmpDumperError(RuntimeError):
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
class VmpDumperResult:
    executable: str
    input_path: str
    output_path: str
    input_sha256: str
    output_sha256: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    dump_ok: bool
    imports_rebuilt: bool
    vm_restored: bool
    pid: int = 0
    module_name: str = ""
    mode: str = "process"

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
            "dump_ok": self.dump_ok,
            "imports_rebuilt": self.imports_rebuilt,
            "vm_restored": self.vm_restored,
            "pid": self.pid,
            "module_name": self.module_name,
            "mode": self.mode,
            "source": VMP_DUMPER_SOURCE,
            "upstream": VMPDUMP_UPSTREAM,
            "license": VMPDUMP_LICENSE,
            "supported_arch": VMPDUMP_ARCH,
            "claims_universal_unpack": False,
        }


def build_vmpdump_argv(
    executable: Path,
    *,
    pid: int,
    module_name: str = "",
    entry_point_rva: int | None = None,
    disable_reloc: bool = False,
) -> list[str]:
    """Build whitelist argv for upstream VMPDump process mode."""
    if pid <= 0:
        raise VmpDumperError(
            VmpDumperErrorCode.INVALID_ARGUMENT,
            "pid must be a positive debuggee process id",
            details={"pid": pid},
        )
    if "\x00" in module_name or any(ch in module_name for ch in ('"', "|", "&", "<", ">")):
        raise VmpDumperError(
            VmpDumperErrorCode.INVALID_ARGUMENT,
            "module_name contains disallowed characters",
            details={"module_name": module_name},
        )
    argv = [str(Path(executable).expanduser()), str(int(pid)), str(module_name)]
    if entry_point_rva is not None:
        if entry_point_rva < 0:
            raise VmpDumperError(
                VmpDumperErrorCode.INVALID_ARGUMENT,
                "entry_point_rva must be >= 0",
                details={"entry_point_rva": entry_point_rva},
            )
        argv.append(f"-ep={entry_point_rva:x}")
    if disable_reloc:
        argv.append("-disable-reloc")
    return argv


def parse_vmpdump_written_path(stdout: str, stderr: str = "") -> Path | None:
    """Extract ``File written to:`` path from VMPDump console output."""
    text = f"{stdout}\n{stderr}"
    match = _FILE_WRITTEN_RE.search(text)
    if match is None:
        return None
    raw = match.group(1).strip().strip('"')
    if not raw:
        return None
    return Path(raw)


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


def _infer_imports_rebuilt(stdout: str, stderr: str) -> bool:
    text = f"{stdout}\n{stderr}".casefold()
    positive = (
        "import rebuilt",
        "imports rebuilt",
        "iat rebuilt",
        "rebuild import",
        "fix table rebuilt",
        "successfully converted call",
        "found ",
        " calls to ",
    )
    # Prefer strong markers; "Found N calls to M imports" is VMPDump's success path.
    if "successfully converted call" in text:
        return True
    if "found " in text and " calls to " in text and " imports" in text:
        return True
    return any(token in text for token in positive[:5])


def _collect_output_pe(
    *,
    stdout: str,
    stderr: str,
    mtime_floor: float,
    search_roots: list[Path],
) -> Path:
    written = parse_vmpdump_written_path(stdout, stderr)
    if written is not None and written.is_file() and _is_pe_file(written):
        return written

    candidates: list[tuple[float, Path]] = []
    for root in search_roots:
        if not root.is_dir():
            continue
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for path in entries:
            if not path.is_file():
                continue
            name = path.name.casefold()
            if "vmpdump" not in name and ".vmpdump." not in name:
                continue
            if not _is_pe_file(path):
                continue
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            # Prefer files touched during/after this run (allow small clock skew).
            if mtime < mtime_floor:
                continue
            candidates.append((mtime, path))
    if not candidates:
        raise VmpDumperError(
            VmpDumperErrorCode.OUTPUT_MISSING,
            "VMPDump produced no PE output (no File-written path / *.VMPDump.* PE)",
            details={
                "search_roots": [str(path) for path in search_roots],
                "stdout_tail": stdout[-500:],
                "stderr_tail": stderr[-500:],
            },
            stdout=stdout,
            stderr=stderr,
        )
    candidates.sort(key=lambda item: (item[0], str(item[1])))
    newest_mtime = candidates[-1][0]
    newest = [path for mtime, path in candidates if mtime == newest_mtime]
    if len(newest) != 1:
        raise VmpDumperError(
            VmpDumperErrorCode.OUTPUT_AMBIGUOUS,
            "VMPDump produced multiple PE outputs with the same newest mtime",
            details={"candidates": [str(path) for path in newest]},
            stdout=stdout,
            stderr=stderr,
        )
    return newest[0]


def run_vmp_dumper(
    executable: Path,
    input_path: Path,
    output_path: Path,
    *,
    input_sha256: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_file_size: int = 0,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    pid: int | None = None,
    module_name: str | None = None,
    entry_point_rva: int | None = None,
    disable_reloc: bool = False,
    search_roots: list[Path] | None = None,
) -> VmpDumperResult:
    """Run upstream VMPDump against a live debuggee PID; publish PE to output_path.

    ``input_path`` / ``input_sha256`` identify the session binary for provenance
    only (never passed as argv). File-only ``exe <path>`` mode is intentionally
    unsupported — that is not the upstream CLI.
    """
    del max_file_size  # retained for call-site compatibility; unused in process mode
    exe = Path(executable).expanduser()
    # resolve() without strict=True so a missing input surfaces as the structured
    # INPUT_NOT_FOUND error below instead of a raw FileNotFoundError from resolve().
    source = Path(input_path).expanduser().resolve()
    destination = Path(output_path).expanduser()
    if not exe.is_file():
        raise VmpDumperError(
            VmpDumperErrorCode.EXECUTABLE_NOT_FOUND,
            f"VMP dumper executable does not exist: {exe}",
            details={"executable": str(exe)},
        )
    if not source.is_file():
        raise VmpDumperError(
            VmpDumperErrorCode.INPUT_NOT_FOUND,
            f"input binary not found: {source}",
            details={"input_path": str(source)},
        )
    if pid is None or pid <= 0:
        raise VmpDumperError(
            VmpDumperErrorCode.DEBUGGEE_REQUIRED,
            "VMPDump requires a live debuggee pid (process mode); "
            "file-only argv is not supported by upstream 0xnobody/vmpdump",
            details={
                "upstream": VMPDUMP_UPSTREAM,
                "supported_arch": VMPDUMP_ARCH,
                "hint": "launch/attach, pause past OEP, then unpack.vmp.dump",
            },
        )
    if destination.exists():
        raise VmpDumperError(
            VmpDumperErrorCode.INVALID_ARGUMENT,
            "output_path must not already exist",
            details={"output_path": str(destination)},
        )
    if destination.resolve() == source.resolve():
        raise VmpDumperError(
            VmpDumperErrorCode.INVALID_ARGUMENT,
            "output_path must differ from input_path",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)

    from headless_re_mcp.core.session import file_sha256

    before = file_sha256(source)
    if before != input_sha256:
        raise VmpDumperError(
            VmpDumperErrorCode.INVALID_ARGUMENT,
            "input sha256 mismatch before VMPDump",
            details={"expected": input_sha256, "actual": before},
        )

    resolved_module = "" if module_name is None else str(module_name)
    argv = build_vmpdump_argv(
        exe,
        pid=pid,
        module_name=resolved_module,
        entry_point_rva=entry_point_rva,
        disable_reloc=disable_reloc,
    )
    roots = list(search_roots or [])
    if not roots:
        roots = [source.parent]
    wall_started = monotonic()
    # st_mtime is wall-clock; keep a floor slightly before run for fallback scan.
    import time as _time

    mtime_floor = _time.time() - 2.0
    try:
        capture = _capture_process(argv, timeout=timeout, max_output_size=max_output_size)
    except BoundedCancelled:
        raise
    except Exception as exc:
        code = getattr(exc, "code", VmpDumperErrorCode.PROCESS_FAILED)
        raise VmpDumperError(
            str(code) if code else VmpDumperErrorCode.PROCESS_FAILED,
            str(exc),
            details=dict(getattr(exc, "details", {}) or {}),
            stdout=str(getattr(exc, "stdout", "") or ""),
            stderr=str(getattr(exc, "stderr", "") or ""),
            returncode=getattr(exc, "returncode", None),
            retryable=bool(getattr(exc, "retryable", False)),
        ) from exc

    if capture.stdout_exceeded or capture.stderr_exceeded:
        raise VmpDumperError(
            VmpDumperErrorCode.OUTPUT_LIMIT,
            "VMPDump stdout/stderr exceeded bound",
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )

    # Upstream returns 0 even on some parse failures; require an output PE.
    after = file_sha256(source)
    if after != before:
        raise VmpDumperError(
            VmpDumperErrorCode.INVALID_ARGUMENT,
            "session input mutated during VMPDump (unexpected)",
            details={"input_path": str(source)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        )

    try:
        produced = _collect_output_pe(
            stdout=capture.stdout,
            stderr=capture.stderr,
            mtime_floor=mtime_floor,
            search_roots=roots,
        )
    except VmpDumperError as exc:
        if capture.returncode != 0 and not exc.stdout:
            raise VmpDumperError(
                VmpDumperErrorCode.PROCESS_FAILED,
                f"VMPDump exited with {capture.returncode} and produced no PE",
                details={"argv": ["vmpdump", "<pid>", "<module>", "..."]},
                stdout=capture.stdout,
                stderr=capture.stderr,
                returncode=capture.returncode,
                retryable=True,
            ) from exc
        raise

    try:
        shutil.copy2(produced, destination)
    except OSError as exc:
        raise VmpDumperError(
            VmpDumperErrorCode.PROCESS_FAILED,
            f"failed to copy VMPDump output: {exc}",
            details={"produced": str(produced), "destination": str(destination)},
            stdout=capture.stdout,
            stderr=capture.stderr,
            returncode=capture.returncode,
        ) from exc

    # VMPDump writes beside the live module. Retention only knows the
    # artifact copy. Measured: after a successful copy, sample.VMPDump.exe
    # (1024 bytes) stayed next to the sample while destination also existed.
    produced_resolved = produced.resolve()
    if (
        produced_resolved != destination.resolve()
        and produced_resolved != source.resolve()
    ):
        with suppress(OSError):
            produced.unlink()

    duration_ms = int((monotonic() - wall_started) * 1000)
    imports_rebuilt = _infer_imports_rebuilt(capture.stdout, capture.stderr)
    return VmpDumperResult(
        executable=str(exe),
        input_path=str(source),
        output_path=str(destination.resolve()),
        input_sha256=before,
        output_sha256=file_sha256(destination),
        returncode=capture.returncode,
        stdout=capture.stdout,
        stderr=capture.stderr,
        duration_ms=duration_ms,
        dump_ok=True,
        imports_rebuilt=imports_rebuilt,
        vm_restored=False,
        pid=pid,
        module_name=resolved_module,
        mode="process",
    )


def probe_vmp_dumper(executable: Path, *, timeout: float = 5.0) -> tuple[bool, str]:
    """Best-effort probe (no-arg usage / parse-failure banner)."""
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
    markers = (
        "vmp",
        "dump",
        "usage",
        "vmprotect",
        "failed to parse",
        "-ep=",
        "disable-reloc",
        "open process",
    )
    if any(token in lowered for token in markers):
        return True, text[:2000]
    if completed.returncode in {0, 1, -1} and text:
        return True, text[:2000]
    return bool(text), text[:2000]
