"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.jsre.wasm_summary import WasmParseError
from headless_re_mcp.backends.jsre.wasm_summary import summarize as summarize_wasm

JsonObject = dict[str, Any]
_MAX_INLINE = 400_000
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000
# Output is already sliced. The child still has to load the file, and an
# unattended pass that pointed js.deobfuscate at a captured bundle started
# node on whatever sat on disk -- measured 2,097,152 bytes still reached
# run_bounded. Sixteen mebibytes is enough for a real module and not enough
# to keep a core busy for the rest of the timeout.
_MAX_INPUT_BYTES = 16 * 1024 * 1024
# Timeout ceilings mirror the MCP-schema Field(le=...) on the js.*/wasm.* tools
# these methods back (600s for deobfuscate/beautify/wat/info, 1200s for
# unpack_bundle). They are enforced here, not only in the schema, because the
# agent transport reaches these handlers through catalog.invoke ->
# handler(**arguments) with no pydantic validation: a model-supplied timeout
# would otherwise flow straight into run_bounded uncapped and an unattended node
# run could outlive the schema ceiling. The Frida backend already clamps for the
# same reason.
_MAX_TOOL_TIMEOUT_S = 600.0
_MAX_UNPACK_TIMEOUT_S = 1200.0


def _capped_file_listing(root: Path, *, cap: int) -> tuple[list[str], int, bool]:
    names: list[str] = []
    total = 0
    has_more = False
    if not root.is_dir():
        return [], 0, False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if total >= _MAX_COUNTED_FILES:
            has_more = True
            break
        total += 1
        if len(names) < cap:
            names.append(str(path.relative_to(root)))
        else:
            has_more = True
    names.sort()
    return names, total, has_more


class JsReError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_existing_file(path: Path, *, missing: str) -> Path:
    """Resolve a regular file, or refuse one that would bind the child unbounded."""
    resolved = path.expanduser()
    if not resolved.is_file():
        raise JsReError("not_found", missing, path=str(resolved))
    try:
        size = int(resolved.stat().st_size)
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    cap = _MAX_INPUT_BYTES
    if size > cap:
        raise JsReError(
            "too_large",
            f"input exceeds the {cap}-byte tool limit",
            path=str(resolved),
            size=size,
            max_file_size=cap,
        )
    return resolved


def _bounded_timeout(timeout: float, cap: float) -> float:
    """Cap a caller timeout at the tool's schema ceiling. See _MAX_*_TIMEOUT_S."""
    return min(float(timeout), cap)


def _run(cmd: list[str], *, timeout: float) -> tuple[str, str, int, bool]:
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
    return stdout, stderr, int(completed.returncode), bool(completed.stdout_truncated)


def _write_spill(spill_dir: Path, filename: str, payload: bytes) -> Path | None:
    """Write the whole payload beside the inline preview, or None on failure.

    The spill file is at most run_bounded's per-stream cap (a few MiB), so it is
    bounded; the caller keys it under the jsre artifact root, which retention
    prunes. A write that fails degrades to no path rather than to an error --
    the inline preview is still returned.
    """
    try:
        spill_dir.mkdir(parents=True, exist_ok=True)
        out = spill_dir / filename
        out.write_bytes(payload)
    except OSError:
        with suppress(OSError):
            (spill_dir / filename).unlink()
        return None
    return out


def _bounded_output(
    text: str,
    key: str,
    *,
    include_bytes: bool,
    stream_truncated: bool = False,
    spill_dir: Path | None = None,
    spill_ext: str = "txt",
) -> JsonObject:
    """Inline a bounded prefix and, when it was cut, spill the whole payload.

    ``truncated`` says the inline ``key`` text was cut at the inline cap. When
    that happens and a ``spill_dir`` is given, the full output is written to
    ``<key>-<uuid>.<spill_ext>`` there and its path returned as ``<key>_path``
    so the caller can still read the whole thing -- the single-file js.*/wasm.*
    tools otherwise had no recourse past the 400 KB inline cut. ``capture_
    truncated`` is a distinct, harder stop: the child's output overran
    run_bounded's per-stream cap, so even the spilled file is only a prefix.
    """
    payload = text.encode("utf-8", errors="replace")
    over_inline = len(payload) > _MAX_INLINE
    result: JsonObject = {
        key: payload[:_MAX_INLINE].decode("utf-8", errors="ignore"),
        "truncated": over_inline,
    }
    if include_bytes:
        result["bytes"] = len(payload)
    if stream_truncated:
        result["capture_truncated"] = True
    if over_inline and spill_dir is not None:
        spilled = _write_spill(spill_dir, f"{key}-{uuid4().hex}.{spill_ext}", payload)
        if spilled is not None:
            result[f"{key}_path"] = str(spilled)
    return result


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
        return _require_existing_file(path, missing="input file not found")

    def deobfuscate(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path)
        stdout, stderr, code, cut = _run(
            [str(self.executable), str(resolved)],
            timeout=_bounded_timeout(timeout, _MAX_TOOL_TIMEOUT_S),
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(
            stdout, "code", include_bytes=True, stream_truncated=cut, spill_dir=spill_dir
        )

    def beautify(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        # webcrack always unminifies; expose it under a formatting-focused name.
        return self.deobfuscate(path, timeout=timeout, spill_dir=spill_dir)

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        resolved = self._require_input(path)
        out_dir.mkdir(parents=True, exist_ok=True)
        stdout, stderr, code, _cut = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir)],
            timeout=_bounded_timeout(timeout, _MAX_UNPACK_TIMEOUT_S),
        )
        files, file_count, listed_more = _capped_file_listing(out_dir, cap=_MAX_COUNTED_FILES)
        if code != 0 and not files:
            raise JsReError(
                "backend_error",
                "webcrack unpack failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_LISTED_FILES))
        window = files[start : start + cap]
        return {
            "output_dir": str(out_dir),
            "file_count": file_count,
            "files": window,
            "count": len(window),
            "total": file_count,
            "offset": start,
            "has_more": start + len(window) < file_count,
            "listing_truncated": listed_more,
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
        return _require_existing_file(path, missing="wasm file not found")

    def wat(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code, cut = _run(
            [str(self._wasm2wat), str(resolved)],
            timeout=_bounded_timeout(timeout, _MAX_TOOL_TIMEOUT_S),
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(
            stdout,
            "wat",
            include_bytes=True,
            stream_truncated=cut,
            spill_dir=spill_dir,
            spill_ext="wat",
        )

    def info(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code, cut = _run(
            [str(self._objdump), "-h", "-x", str(resolved)],
            timeout=_bounded_timeout(timeout, _MAX_TOOL_TIMEOUT_S),
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm-objdump failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(
            stdout, "objdump", include_bytes=False, stream_truncated=cut, spill_dir=spill_dir
        )

    def summary(
        self, path: Path, *, max_imports: int = 1000, max_exports: int = 1000
    ) -> JsonObject:
        """Structured import/export/section view, parsed in-process (no wabt).

        Unlike wat()/info() this needs no wabt tool -- it reads the module's
        binary sections directly -- so it stays available when wabt is not
        configured. The file-size cap still applies; the parse is bounded and a
        module the parser cannot read is reported as invalid_params, not a crash.
        """
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        try:
            return summarize_wasm(data, max_imports=max_imports, max_exports=max_exports)
        except WasmParseError as exc:
            raise JsReError(
                "invalid_params", f"not a readable wasm module: {exc}", path=str(resolved)
            ) from exc


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
