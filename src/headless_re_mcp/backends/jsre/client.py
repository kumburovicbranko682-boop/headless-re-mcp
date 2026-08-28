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


def _bounded_output(
    text: str,
    key: str,
    *,
    include_bytes: bool,
    spill_dir: Path | None = None,
    spill_stem: str = "output",
    spill_suffix: str = ".txt",
) -> JsonObject:
    payload = text.encode("utf-8", errors="replace")
    truncated = len(payload) > _MAX_INLINE
    result: JsonObject = {
        key: payload[:_MAX_INLINE].decode("utf-8", errors="ignore"),
        "truncated": truncated,
    }
    if include_bytes:
        result["bytes"] = len(payload)
    if truncated and spill_dir is not None:
        # The inline slice is a preview; the rest of a deobfuscated bundle or WAT
        # dump is unrecoverable from it, and these outputs routinely run to
        # megabytes (a 600 KB minified bundle unminifies past 900 KB). Spill the
        # whole thing to an artifact, the same escape hatch web.network.get gives
        # an oversized response body, so "truncated" still means "readable in
        # full", not "lost". Best-effort: a spill that cannot be written leaves
        # the preview and the truncated flag exactly as before.
        with suppress(OSError):
            spill_dir.mkdir(parents=True, exist_ok=True)
            artifact = spill_dir / f"{spill_stem}-{uuid4().hex}{spill_suffix}"
            artifact.write_bytes(payload)
            result["artifact_path"] = str(artifact)
            result["artifact_bytes"] = len(payload)
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
        stdout, stderr, code = _run([str(self.executable), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(
            stdout,
            "code",
            include_bytes=True,
            spill_dir=spill_dir,
            spill_stem="deobfuscated",
            spill_suffix=".js",
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
        # webcrack refuses to write into a directory that already exists unless
        # --force is given, and the caller pre-creates ``out_dir`` (a unique
        # per-run tree) so retention pruning has a stable path to reclaim. Pass
        # -f so the pre-created directory is the one webcrack overwrites instead
        # of aborting with "output directory already exists".
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir), "-f"], timeout=timeout
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


_WASM_MAGIC = b"\x00asm"
# The four external kinds an import/export can carry (WebAssembly spec 5.5.5).
_WASM_EXTERNAL_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}
_WASM_SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}
# WebAssembly value types (spec 5.3.1) plus the two reference types, used to
# render a function signature like "(i32, i32) -> i32".
_WASM_VALTYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
# Cap the import/export lists so a crafted module with a huge vec count cannot
# make one summary build an unbounded envelope; the declared count is still
# reported so the truncation is disclosed.
_MAX_WASM_ITEMS = 4096
# The function index space can legitimately be large, so signature resolution
# tracks more entries than the display cap -- but still bounded so a crafted
# Function section cannot make the index map grow without limit.
_MAX_WASM_FUNCS = 200_000
_MAX_WASM_NAME = 512


class _WasmParseError(Exception):
    """A structural fault in the module bytes, mapped to a clean JsReError."""


def _read_wasm_valtypes(data: bytes, pos: int, end: int) -> tuple[list[str], int]:
    count, pos = _read_uleb128(data, pos)
    out: list[str] = []
    for _ in range(count):
        if pos >= end:
            raise _WasmParseError("valtype overruns section")
        vt = data[pos]
        pos += 1
        out.append(_WASM_VALTYPES.get(vt, f"0x{vt:02x}"))
    return out, pos


def _read_wasm_functype(data: bytes, pos: int, end: int) -> tuple[str, int]:
    if pos >= end:
        raise _WasmParseError("type entry truncated")
    form = data[pos]
    pos += 1
    if form != 0x60:
        # Only ordinary function types carry a param/result signature; the GC
        # proposal's struct/array/rec forms cannot be rendered this way, so bail
        # out of type detailing rather than misread their bytes.
        raise _WasmParseError(f"unsupported type form 0x{form:02x}")
    params, pos = _read_wasm_valtypes(data, pos, end)
    results, pos = _read_wasm_valtypes(data, pos, end)
    if not results:
        rendered = "()"
    elif len(results) == 1:
        rendered = results[0]
    else:
        rendered = "(" + ", ".join(results) + ")"
    return f"({', '.join(params)}) -> {rendered}", pos


def _wasm_sig_for(type_index: int, types: list[str]) -> str | None:
    if 0 <= type_index < len(types):
        return types[type_index]
    return None


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _WasmParseError("truncated LEB128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise _WasmParseError("LEB128 too long")


def _read_wasm_name(data: bytes, pos: int, end: int) -> tuple[str, int]:
    length, pos = _read_uleb128(data, pos)
    if length < 0 or pos + length > end:
        raise _WasmParseError("name overruns section")
    raw = data[pos : pos + length]
    pos += length
    text = raw.decode("utf-8", "replace")
    return text[:_MAX_WASM_NAME], pos


def _skip_wasm_limits(data: bytes, pos: int) -> int:
    flags = data[pos]
    pos += 1
    _, pos = _read_uleb128(data, pos)  # min
    if flags & 1:
        _, pos = _read_uleb128(data, pos)  # max
    return pos


def _parse_wasm_summary(data: bytes, *, module: str) -> JsonObject:
    """Parse a module's import/export/section structure straight from the bytes.

    The WebAssembly binary format is versioned and stable, so walking its section
    table for the import and export vectors needs no external tool and cannot
    drift with a wabt release. Any structural fault becomes a clean
    ``backend_error`` rather than a crash, matching the fault contract the
    subprocess-backed readers use.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("backend_error", "not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    n = len(data)
    counts: dict[str, int] = {}
    imports: list[JsonObject] = []
    exports: list[JsonObject] = []
    types: list[str] = []
    # Function index -> type index, imported funcs first then defined funcs, so an
    # export's index can be resolved to a signature.
    func_types: list[int] = []
    imports_truncated = False
    exports_truncated = False
    types_truncated = False
    try:
        while pos < n:
            sec_id = data[pos]
            pos += 1
            sec_size, pos = _read_uleb128(data, pos)
            sec_end = pos + sec_size
            if sec_size < 0 or sec_end > n:
                raise _WasmParseError("section overruns module")
            name = _WASM_SECTION_NAMES.get(sec_id, f"section_{sec_id}")
            if sec_id == 0:
                # A custom section is name-prefixed free-form bytes with no vec
                # count; tally its presence and skip the payload.
                counts["custom"] = counts.get("custom", 0) + 1
                pos = sec_end
                continue
            count, body = _read_uleb128(data, pos)
            counts[name] = count
            if sec_id == 1:  # Type: the module's function signatures
                p = body
                # A type-table fault is local: stop detailing signatures rather
                # than failing the whole summary, since imports/exports still read.
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(types) >= _MAX_WASM_ITEMS:
                            types_truncated = True
                            break
                        sig, p = _read_wasm_functype(data, p, sec_end)
                        types.append(sig)
            elif sec_id == 3:  # Function: one type index per defined function
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(func_types) >= _MAX_WASM_FUNCS:
                            break
                        ti, p = _read_uleb128(data, p)
                        func_types.append(ti)
            elif sec_id == 2:  # Import
                p = body
                for _ in range(count):
                    mod_name, p = _read_wasm_name(data, p, sec_end)
                    fld_name, p = _read_wasm_name(data, p, sec_end)
                    if p >= sec_end:
                        raise _WasmParseError("import entry truncated")
                    kind = data[p]
                    p += 1
                    entry: JsonObject = {
                        "module": mod_name,
                        "name": fld_name,
                        "kind": _WASM_EXTERNAL_KINDS.get(kind, str(kind)),
                    }
                    if kind == 0:  # func: type index
                        entry["type_index"], p = _read_uleb128(data, p)
                        # An imported function occupies the low func index space,
                        # so record its type before any defined function.
                        if len(func_types) < _MAX_WASM_FUNCS:
                            func_types.append(int(entry["type_index"]))
                        import_sig = _wasm_sig_for(int(entry["type_index"]), types)
                        if import_sig is not None:
                            entry["signature"] = import_sig
                    elif kind == 1:  # table: elem type byte + limits
                        p = _skip_wasm_limits(data, p + 1)
                    elif kind == 2:  # memory: limits
                        p = _skip_wasm_limits(data, p)
                    elif kind == 3:  # global: value type byte + mutability byte
                        p += 2
                    else:
                        raise _WasmParseError(f"unknown import kind {kind}")
                    if len(imports) < _MAX_WASM_ITEMS:
                        imports.append(entry)
                    else:
                        imports_truncated = True
            elif sec_id == 7:  # Export
                p = body
                for _ in range(count):
                    exp_name, p = _read_wasm_name(data, p, sec_end)
                    if p >= sec_end:
                        raise _WasmParseError("export entry truncated")
                    kind = data[p]
                    p += 1
                    idx, p = _read_uleb128(data, p)
                    export: JsonObject = {
                        "name": exp_name,
                        "kind": _WASM_EXTERNAL_KINDS.get(kind, str(kind)),
                        "index": idx,
                    }
                    if kind == 0 and idx < len(func_types):
                        # Canonical section order puts Type/Import/Function before
                        # Export, so the func index map is complete here.
                        type_index = func_types[idx]
                        export_sig = _wasm_sig_for(type_index, types)
                        if export_sig is not None:
                            export["type_index"] = type_index
                            export["signature"] = export_sig
                    if len(exports) < _MAX_WASM_ITEMS:
                        exports.append(export)
                    else:
                        exports_truncated = True
            # Resync at the declared section boundary either way, so a malformed
            # entry cannot desynchronise the walk of the following sections.
            pos = sec_end
    except _WasmParseError as exc:
        raise JsReError("backend_error", f"malformed WebAssembly module: {exc}") from exc
    except IndexError as exc:  # a read ran off the end despite the guards
        raise JsReError(
            "backend_error", "malformed WebAssembly module: unexpected end of data"
        ) from exc
    result: JsonObject = {
        "module": module,
        "version": version,
        "imports": imports,
        "exports": exports,
        "types": types,
        "import_count": counts.get("import", 0),
        "export_count": counts.get("export", 0),
        "function_count": counts.get("function", 0),
        "memory_count": counts.get("memory", 0),
        "global_count": counts.get("global", 0),
        "table_count": counts.get("table", 0),
        "type_count": counts.get("type", 0),
        "sections": counts,
    }
    if imports_truncated:
        result["imports_truncated"] = True
    if exports_truncated:
        result["exports_truncated"] = True
    if types_truncated:
        result["types_truncated"] = True
    return result


class WasmClient:
    """wabt-backed WebAssembly inspection (wasm2wat, wasm-objdump)."""

    def __init__(self, wabt: Path | None = None) -> None:
        self._wasm2wat = _resolve_wabt_tool(wabt, "wasm2wat")
        self._objdump = _resolve_wabt_tool(wabt, "wasm-objdump")
        self._decompile = _resolve_wabt_tool(wabt, "wasm-decompile")

    @property
    def available(self) -> bool:
        return self._wasm2wat is not None

    def _require_input(self, path: Path, tool: Path | None, name: str) -> Path:
        if tool is None:
            raise JsReError("capability_unavailable", f"{name} (wabt) is not configured")
        return _require_existing_file(path, missing="wasm file not found")

    def summary(self, path: Path, *, timeout: float = 30.0) -> JsonObject:
        """Structured module surface: imports, exports and per-section counts.

        Where wasm.wat / wasm.info / wasm.decompile hand back text a caller has to
        read, this parses the module binary itself into machine-readable lists --
        what the module imports from its host (the JS glue, ``env.<name>``) and
        what it exports back (the functions and memory a page calls) -- the
        WebAssembly analogue of a PE/ELF import and export table. Function imports
        and exports also carry a resolved ``signature`` (e.g. ``(i32, i32) -> i32``)
        and ``type_index`` recovered from the Type and Function sections, and
        ``types`` lists the module's whole signature table. It reads the bytes
        directly, so it needs no wabt installed and cannot drift with a wabt
        version; a malformed module faults cleanly rather than crashing. ``timeout``
        is accepted for signature symmetry with the wabt-backed readers but the
        parse is a bounded in-process walk.
        """
        _ = timeout
        resolved = _require_existing_file(path, missing="wasm file not found")
        return _parse_wasm_summary(resolved.read_bytes(), module=resolved.name)

    def wat(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code = _run([str(self._wasm2wat), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _bounded_output(
            stdout,
            "wat",
            include_bytes=True,
            spill_dir=spill_dir,
            spill_stem="module",
            spill_suffix=".wat",
        )

    def decompile(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._decompile, "wasm-decompile")
        assert self._decompile is not None
        stdout, stderr, code = _run([str(self._decompile), str(resolved)], timeout=timeout)
        # wasm-decompile, like wasm2wat, writes its diagnostic to stderr and
        # leaves stdout empty on a bad module, so an empty stdout with a non-zero
        # exit is the failure. A valid module always yields at least a
        # declaration, so "empty output" never means "success" here.
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error",
                "wasm-decompile failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        return _bounded_output(
            stdout,
            "code",
            include_bytes=True,
            spill_dir=spill_dir,
            spill_stem="decompiled",
            spill_suffix=".dcmp",
        )

    def info(
        self, path: Path, *, timeout: float = 120.0, spill_dir: Path | None = None
    ) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code = _run(
            [str(self._objdump), "-h", "-x", str(resolved)], timeout=timeout
        )
        # wasm-objdump reports a malformed module by exiting non-zero and writing
        # the diagnostic to STDOUT (e.g. "0000004: error: bad magic value"), not
        # stderr the way wasm2wat does. The "and not stdout" guard its sibling
        # tools use therefore never fired here, so a failed inspection returned
        # ok with the error text handed back as the objdump payload -- an agent
        # would read "bad magic value" as section analysis. A non-zero exit is
        # the failure; surface whichever stream actually carried the diagnostic.
        if code != 0:
            diagnostic = (stderr or stdout).strip()
            raise JsReError(
                "backend_error",
                "wasm-objdump failed",
                exit_code=code,
                stderr=diagnostic[:_MAX_STDERR],
            )
        return _bounded_output(
            stdout,
            "objdump",
            include_bytes=False,
            spill_dir=spill_dir,
            spill_stem="objdump",
            spill_suffix=".txt",
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
