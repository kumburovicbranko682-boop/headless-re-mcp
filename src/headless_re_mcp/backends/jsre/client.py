"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

JsonObject = dict[str, Any]
_MAX_INLINE = 400_000
_MAX_STDERR = 8000


class JsReError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded(cmd, timeout=timeout, creationflags=creationflags)
    except TimedOut as exc:
        # webcrack runs under node, which the launcher starts as a child, so
        # the deadline has to reach it too.
        raise JsReError(
            "timeout", "tool timed out", timeout=timeout, killed_pids=exc.killed
        ) from exc
    except OSError as exc:
        raise JsReError("backend_error", f"failed to launch {cmd[0]}: {exc}") from exc
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return stdout, stderr, int(completed.returncode)


class JsClient:
    """webcrack-backed JavaScript deobfuscation and bundle unpacking."""

    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover_webcrack()

    @property
    def available(self) -> bool:
        return self.executable is not None

    def _require_input(self, path: Path) -> Path:
        if self.executable is None:
            raise JsReError(
                "capability_unavailable", "webcrack is not configured (needs Node 22/24)"
            )
        resolved = path.expanduser()
        if not resolved.is_file():
            raise JsReError("not_found", "input file not found", path=str(resolved))
        return resolved

    def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path)
        stdout, stderr, code = _run([str(self.executable), str(resolved)], timeout=timeout)
        # Measured: exit 1 with stdout "Error: boom\n" still became
        # code="Error: boom\n", so an unattended agent treats the error
        # text as the deobfuscated program.
        if code != 0:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return {
            "code": stdout[:_MAX_INLINE],
            "truncated": len(stdout) > _MAX_INLINE,
            "bytes": len(stdout),
        }

    def beautify(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        # webcrack always unminifies; expose it under a formatting-focused name.
        return self.deobfuscate(path, timeout=timeout)

    def unpack_bundle(self, path: Path, out_dir: Path, *, timeout: float = 300.0) -> JsonObject:
        resolved = self._require_input(path)
        out_dir.mkdir(parents=True, exist_ok=True)
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir)], timeout=timeout
        )
        files = (
            sorted(str(p.relative_to(out_dir)) for p in out_dir.rglob("*") if p.is_file())
            if out_dir.is_dir()
            else []
        )
        # Measured: exit 1 with yesterday's old.js still in out_dir still
        # became a successful unpack, so an unattended agent then reads
        # last night's modules as this run's output.
        if code != 0:
            raise JsReError(
                "backend_error",
                "webcrack unpack failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        listed = files[:2000]
        return {
            "output_dir": str(out_dir),
            "file_count": len(files),
            "files": listed,
            # A caller deciding "these are all the modules" has to know
            # whether the tree ended or this list merely stopped.
            "has_more": len(files) > len(listed),
        }


class WasmClient:
    """wabt-backed WebAssembly inspection (wasm2wat, wasm-objdump)."""

    def __init__(self, wabt: Path | None = None) -> None:
        self._wasm2wat = _resolve_wabt_tool(wabt, "wasm2wat")
        self._objdump = _resolve_wabt_tool(wabt, "wasm-objdump")

    @property
    def available(self) -> bool:
        return self._wasm2wat is not None

    def _require_input(self, path: Path, tool: Path | None, name: str) -> Path:
        if tool is None:
            raise JsReError("capability_unavailable", f"{name} (wabt) is not configured")
        resolved = path.expanduser()
        if not resolved.is_file():
            raise JsReError("not_found", "wasm file not found", path=str(resolved))
        return resolved

    def wat(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code = _run([str(self._wasm2wat), str(resolved)], timeout=timeout)
        # Measured: exit 1 with stdout "(error)" still became wat="(error)",
        # so an unattended agent treats the error text as the module text.
        if code != 0:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return {
            "wat": stdout[:_MAX_INLINE],
            "truncated": len(stdout) > _MAX_INLINE,
            "bytes": len(stdout),
        }

    def info(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code = _run(
            [str(self._objdump), "-h", "-x", str(resolved)], timeout=timeout
        )
        # Measured: exit 1 with stdout "(error dump)" still became
        # objdump="(error dump)", so an unattended agent treats the error
        # text as the module dump.
        if code != 0:
            raise JsReError(
                "backend_error", "wasm-objdump failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return {"objdump": stdout[:_MAX_INLINE], "truncated": len(stdout) > _MAX_INLINE}


def _discover_webcrack() -> Path | None:
    found = shutil.which("webcrack")
    return Path(found) if found else None


def _resolve_wabt_tool(wabt: Path | None, tool: str) -> Path | None:
    exe = tool + (".exe" if os.name == "nt" else "")
    if wabt is not None:
        candidate = wabt if wabt.name.lower().startswith(tool) else wabt / exe
        if candidate.is_file():
            return candidate
        # wabt may point at the bin directory.
        alt = wabt / "bin" / exe
        if alt.is_file():
            return alt
    found = shutil.which(tool)
    return Path(found) if found else None
