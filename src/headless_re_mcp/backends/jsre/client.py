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

from headless_re_mcp.backends.common.bounded_run import (
    InvalidTimeout,
    TimedOut,
    clamp_cli_timeout,
    run_bounded,
)

JsonObject = dict[str, Any]
_MAX_INLINE = 400_000
# Per the tool schema: js.deobfuscate / js.beautify / wasm.* declare le=600,
# js.unpack_bundle le=1200. Each caller passes its own ceiling into _run.
_MAX_TIMEOUT_S = 600.0
_MAX_UNPACK_TIMEOUT_S = 1200.0
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000
# Output is already sliced. The child still has to load the file, and an
# unattended pass that pointed js.deobfuscate at a captured bundle started
# node on whatever sat on disk -- measured 2,097,152 bytes still reached
# run_bounded. Sixteen mebibytes is enough for a real module and not enough
# to keep a core busy for the rest of the timeout.
_MAX_INPUT_BYTES = 16 * 1024 * 1024
# Every WebAssembly binary opens with these four bytes. Checking them before
# launching wasm2wat / wasm-objdump turns a cryptic tool failure and a wasted
# subprocess into a precise invalid_params -- the same reason the size cap
# refuses input up front rather than handing it to the child.
_WASM_MAGIC = b"\x00asm"
# wasm.imports parses the module's import section in pure Python, so it works
# with no wabt installed. Bounded like every other scan: a collect cap on
# distinct entries, a page cap matching the tool schema and a per-name clamp.
_MAX_WASM_IMPORTS_COLLECT = 5000
_MAX_WASM_IMPORTS_PAGE = 1000
_MAX_WASM_NAME_LEN = 512
# import descriptor kind byte -> external-kind name (WASM core spec).
_WASM_IMPORT_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}
_WASM_IMPORT_SECTION_ID = 2


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


def _looks_like_wasm(path: Path) -> bool:
    """Whether the file opens with the four-byte WebAssembly magic."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) == _WASM_MAGIC
    except OSError:
        return False


class _WasmParseError(Exception):
    """A read ran past the buffer or hit a byte the grammar does not allow.

    Raised only inside the WASM parser and always caught there: a malformed or
    truncated module yields the entries decoded so far with truncated=true,
    never a stack trace or a misaligned tail read as real imports.
    """


def _read_uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one LEB128 unsigned int (u32 range) at pos; return (value, next)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _WasmParseError("unexpected end of buffer")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 35:
            raise _WasmParseError("leb128 too long for u32")


def _read_wasm_name(data: bytes, pos: int) -> tuple[str, int]:
    """Read a WASM name (u32 length prefix + UTF-8 bytes); clamp its length."""
    length, pos = _read_uleb(data, pos)
    end = pos + length
    if length < 0 or end > len(data):
        raise _WasmParseError("name runs past the buffer")
    text = data[pos:end].decode("utf-8", errors="replace")
    return text[:_MAX_WASM_NAME_LEN], end


def _skip_wasm_limits(data: bytes, pos: int) -> int:
    """Skip a limits record (flag byte, min, optional max) for table/memory."""
    if pos >= len(data):
        raise _WasmParseError("limits truncated")
    flag = data[pos]
    pos += 1
    _, pos = _read_uleb(data, pos)
    if flag & 0x01:
        _, pos = _read_uleb(data, pos)
    return pos


def _skip_import_desc(data: bytes, pos: int, kind: int) -> int:
    """Consume the kind-specific descriptor so the next entry stays aligned."""
    if kind == 0:  # func: typeidx
        _, pos = _read_uleb(data, pos)
        return pos
    if kind == 1:  # table: reftype byte, then limits
        if pos >= len(data):
            raise _WasmParseError("table type truncated")
        return _skip_wasm_limits(data, pos + 1)
    if kind == 2:  # memory: limits
        return _skip_wasm_limits(data, pos)
    if kind == 3:  # global: valtype byte + mutability byte
        if pos + 2 > len(data):
            raise _WasmParseError("global type truncated")
        return pos + 2
    raise _WasmParseError(f"unknown import kind {kind}")


def _parse_import_section(data: bytes) -> tuple[list[JsonObject], bool, bool]:
    """Parse an import section body into rows; return (rows, scan_more, truncated)."""
    rows: list[JsonObject] = []
    scan_more = False
    try:
        count, pos = _read_uleb(data, 0)
        for _ in range(count):
            if len(rows) >= _MAX_WASM_IMPORTS_COLLECT:
                scan_more = True
                break
            module, pos = _read_wasm_name(data, pos)
            name, pos = _read_wasm_name(data, pos)
            if pos >= len(data):
                raise _WasmParseError("import kind truncated")
            kind = data[pos]
            pos += 1
            pos = _skip_import_desc(data, pos, kind)
            rows.append(
                {
                    "module": module,
                    "name": name,
                    "kind": _WASM_IMPORT_KINDS.get(kind, "unknown"),
                }
            )
    except _WasmParseError:
        return rows, scan_more, True
    return rows, scan_more, False


def parse_wasm_imports(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's imports (the JS<->WASM boundary), wabt-free.

    Reads the .wasm binary directly in pure Python, so unlike wasm.info / wasm
    .wat it needs no wabt installed. Imports are what a module pulls from its
    host -- the JS functions, memories, tables and globals it cannot run without
    -- and reading them is the fastest way to see what a module actually does
    (a memory import plus env.emscripten_* says one thing; a lone crypto shim
    says another). Each row is module, name and kind (func, table, memory or
    global) in binary order, which is the order that assigns each import its
    index. Returns imports, count, total, offset and has_more so a filled page
    is not read as every import; total is capped at 5000 with scan_capped when
    more may exist, and truncated is true when a malformed or short module cut
    the parse (the entries read so far are still returned). A file that is not a
    WebAssembly module is refused as invalid_params, and one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
    rows: list[JsonObject] = []
    scan_more = False
    truncated = False
    section_body: bytes | None = None
    try:
        pos = 8  # 4-byte magic + 4-byte version
        total = len(raw)
        while pos < total:
            sec_id = raw[pos]
            pos += 1
            size, pos = _read_uleb(raw, pos)
            end = pos + size
            if end > total:
                truncated = True
                break
            if sec_id == _WASM_IMPORT_SECTION_ID:
                section_body = raw[pos:end]
                break
            pos = end
    except _WasmParseError:
        truncated = True
    if section_body is not None:
        rows, scan_more, body_truncated = _parse_import_section(section_body)
        truncated = truncated or body_truncated
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_IMPORTS_PAGE))
    window = rows[start : start + cap]
    return {
        "imports": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _run(
    cmd: list[str], *, timeout: float, maximum: float = _MAX_TIMEOUT_S
) -> tuple[str, str, int]:
    try:
        timeout = clamp_cli_timeout(timeout, maximum=maximum)
    except InvalidTimeout as exc:
        raise JsReError("invalid_params", str(exc)) from exc
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


def _bounded_output(text: str, key: str, *, include_bytes: bool) -> JsonObject:
    payload = text.encode("utf-8", errors="replace")
    result: JsonObject = {
        key: payload[:_MAX_INLINE].decode("utf-8", errors="ignore"),
        "truncated": len(payload) > _MAX_INLINE,
    }
    if include_bytes:
        result["bytes"] = len(payload)
    return result


def _note_nonzero_exit(result: JsonObject, *, code: int, stderr: str) -> JsonObject:
    """Say when the tool exited non-zero but still produced output.

    These CLIs are kept on the "return what we got" path on purpose -- webcrack
    exits non-zero on a partial deobfuscation while still emitting usable code,
    and wasm-objdump can print sections before it trips on a later one. But a
    clean pass and a bail-out that happened to print something were otherwise
    indistinguishable: the reply carried no exit status, so an unattended agent
    read a truncated-because-the-tool-died result as the finished article.
    ``tool_failed`` is distinct from ``truncated`` (which is only ever "we cut
    the text at the inline cap"): it means the child itself signalled failure,
    so the output may be incomplete for a reason we cannot see.
    """
    if code != 0:
        result["exit_code"] = code
        result["tool_failed"] = True
        result["stderr"] = stderr[:_MAX_STDERR]
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

    def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path)
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved)], timeout=timeout, maximum=_MAX_TIMEOUT_S
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "code", include_bytes=True), code=code, stderr=stderr
        )

    def beautify(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        # webcrack always unminifies; expose it under a formatting-focused name.
        return self.deobfuscate(path, timeout=timeout)

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
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir)],
            timeout=timeout,
            maximum=_MAX_UNPACK_TIMEOUT_S,
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
        result: JsonObject = {
            "output_dir": str(out_dir),
            "file_count": file_count,
            "files": window,
            "count": len(window),
            "total": file_count,
            "offset": start,
            "has_more": start + len(window) < file_count,
            "listing_truncated": listed_more,
        }
        return _note_nonzero_exit(result, code=code, stderr=stderr)


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
        resolved = _require_existing_file(path, missing="wasm file not found")
        # The size cap runs first (above): an oversized non-module is still
        # refused as too_large, not misreported as a bad-magic file.
        if not _looks_like_wasm(resolved):
            raise JsReError(
                "invalid_params",
                "not a WebAssembly module: missing the \\0asm magic",
                path=str(resolved),
            )
        return resolved

    def wat(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code = _run([str(self._wasm2wat), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "wat", include_bytes=True), code=code, stderr=stderr
        )

    def info(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code = _run(
            [str(self._objdump), "-h", "-x", str(resolved)], timeout=timeout
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm-objdump failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "objdump", include_bytes=False), code=code, stderr=stderr
        )


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
