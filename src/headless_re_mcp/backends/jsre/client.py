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
from headless_re_mcp.backends.common.json_budget import fit_json_list, fit_json_text
from headless_re_mcp.backends.jsre.wasm_format import (
    WasmParseError,
    parse_data_strings,
    parse_elements,
    parse_exports,
    parse_functions,
    parse_globals,
    parse_imports,
    parse_names,
    parse_sections,
)

JsonObject = dict[str, Any]
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
# Default and ceiling for one page of parsed import/export entries.
_WASM_ENTRY_DEFAULT = 200
_WASM_ENTRY_CAP = 2000
# Default minimum printable-run length for wasm.strings, and the ceiling a
# caller may raise it to (matches the per-string clip in the parser).
_WASM_STRINGS_MIN_DEFAULT = 4
_WASM_STRINGS_MIN_CAP = 256
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


def _bounded_output(text: str, key: str, *, include_bytes: bool) -> JsonObject:
    # Bound by the JSON-encoded size, not the raw byte count: the transport
    # discards the whole result (for a ~16 KiB summary) once the *encoded*
    # envelope outruns the budget, so a raw cap above that budget -- the old
    # 400 KB one was -- guaranteed the useful output was thrown away instead of
    # returned cleanly truncated. fit_json_text leaves room for the other fields.
    inline, original_bytes, truncated = fit_json_text(text)
    result: JsonObject = {key: inline, "truncated": truncated}
    if include_bytes:
        result["bytes"] = original_bytes
    return result


def _note_nonzero_exit(result: JsonObject, *, code: int, stderr: str) -> JsonObject:
    """Say when the tool exited non-zero but still produced output.

    webcrack and wabt are kept on the "return what we got" path: the ``_run``
    guards only fail hard when the exit is non-zero *and* nothing came back, so a
    non-zero exit that still printed something (webcrack half-unpacks and emits
    what it managed; wasm2wat/wasm-objdump can bail on a later section after
    writing earlier ones) was returned indistinguishable from a clean pass. An
    agent then read truncated WAT, a short objdump, or a partial deobfuscation as
    the finished result. ``tool_failed`` -- the same flag jadx raises for its own
    partial decompiles -- says the child itself signalled failure, so the output
    may be incomplete for a reason this side cannot see.
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
        stdout, stderr, code = _run([str(self.executable), str(resolved)], timeout=timeout)
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
        # --force is required, not optional. webcrack's -o handler is
        # `if (force || !existsSync(output)) rm(output); else error("output
        # directory already exists")` -- it refuses to write into a directory
        # that already exists. We just created out_dir (and the service hands a
        # fresh unique path per call), so without --force every unpack exits
        # non-zero having written nothing, i.e. the whole tool is dead on any
        # webcrack carrying that guard. --force makes it clear and rewrite the
        # directory it owns. The flag lives in the same handler as the guard, so
        # any webcrack that trips the guard also honours --force.
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir), "--force"],
            timeout=timeout,
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
        # Bound the window by its JSON-encoded size too, not only the count cap: a
        # caller can ask for up to 2000 paths and a deep bundle's paths can sum
        # past the result budget, whereupon the transport discards the whole
        # listing for a ~16 KiB summary. Trimming here shrinks the window before
        # has_more is computed, so a page that was budget-cut still reports more to
        # fetch and the caller can advance past it.
        window, _dropped, budget_cut = fit_json_list(window)
        result: JsonObject = {
            "output_dir": str(out_dir),
            "file_count": file_count,
            "files": window,
            "count": len(window),
            "total": file_count,
            "offset": start,
            "has_more": start + len(window) < file_count,
            "listing_truncated": listed_more or budget_cut,
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
        return _require_existing_file(path, missing="wasm file not found")

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

    def sections(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Structured section map of a .wasm module (id/name/size/offset[/count]).

        Reads the module's top-level section layout directly from the binary, so
        it needs no wabt and cannot drift with a wabt version; an input over
        16 MiB is refused as too_large. This is the dependency-free equivalent of
        the section table wasm.info prints as wasm-objdump text.
        """
        data = self._read_module(path)
        try:
            entries, incomplete = parse_sections(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _WASM_ENTRY_CAP))
        window = entries[start : start + cap]
        window, _dropped, _budget_cut = fit_json_list(window)
        return {
            "sections": window,
            "count": len(window),
            "total": len(entries),
            "offset": start,
            "has_more": start + len(window) < len(entries),
            "incomplete": incomplete,
        }

    def functions(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Structured defined-function table (absolute index/type/signature/name).

        Reads the Function section directly and resolves each entry against the
        Type, Import and custom name sections, so it needs no wabt and cannot
        drift with a wabt version; an input over 16 MiB is refused as too_large.
        Indices are absolute (imported functions counted first), matching the
        name section and call instructions.
        """
        data = self._read_module(path)
        try:
            entries, declared, incomplete = parse_functions(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        return _paged_entries(
            entries, "functions", declared, incomplete, offset=offset, limit=limit
        )

    def elements(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Structured element segments (the indirect-call table population).

        Reads the Element section directly, so it needs no wabt and cannot drift
        with a wabt version; an input over 16 MiB is refused as too_large. Each
        segment's funcs are the function indices it writes into a table -- the
        call_indirect dispatch targets, in the module's absolute function-index
        space (imported functions first, matching wasm.functions).
        """
        data = self._read_module(path)
        try:
            entries, declared, incomplete = parse_elements(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        return _paged_entries(entries, "elements", declared, incomplete, offset=offset, limit=limit)

    def globals(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Structured defined-global table (absolute index/type/mutable/init).

        Reads the Global section directly, so it needs no wabt and cannot drift
        with a wabt version; an input over 16 MiB is refused as too_large. Each
        row's init decodes the initializer constant (the literal a stack-pointer
        or heap-base global is set to) when it is a simple const or reference.
        Indices are absolute (imported globals counted first).
        """
        data = self._read_module(path)
        try:
            entries, declared, incomplete = parse_globals(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        return _paged_entries(entries, "globals", declared, incomplete, offset=offset, limit=limit)

    def imports(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Structured Import section (module/name/kind + per-kind type detail).

        Unlike wat/info this needs no wabt: it reads the module's binary Import
        section directly, so it works on any host and cannot drift with a wabt
        version. The file/size guard still applies.
        """
        data = self._read_module(path)
        try:
            entries, declared, incomplete = parse_imports(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        return _paged_entries(entries, "imports", declared, incomplete, offset=offset, limit=limit)

    def exports(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Structured Export section (name/kind/index). No wabt required."""
        data = self._read_module(path)
        try:
            entries, declared, incomplete = parse_exports(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        return _paged_entries(entries, "exports", declared, incomplete, offset=offset, limit=limit)

    def names(
        self, path: Path, *, offset: int = 0, limit: int = _WASM_ENTRY_DEFAULT
    ) -> JsonObject:
        """Function-index -> name map from the custom "name" section (no wabt).

        Symbolises a stripped-but-named module: without this section internal
        functions are only indices. present reports whether the module carries a
        name section at all, distinct from one that is present but names no
        functions. function_names is paged and bounded like imports/exports.
        """
        data = self._read_module(path)
        try:
            present, module_name, function_names, incomplete = parse_names(data)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _WASM_ENTRY_CAP))
        window = function_names[start : start + cap]
        window, _dropped, _budget_cut = fit_json_list(window)
        return {
            "present": present,
            "module_name": module_name,
            "function_names": window,
            "count": len(window),
            "total": len(function_names),
            "offset": start,
            "has_more": start + len(window) < len(function_names),
            "incomplete": incomplete,
        }

    def strings(
        self,
        path: Path,
        *,
        min_length: int = _WASM_STRINGS_MIN_DEFAULT,
        contains: str | None = None,
        offset: int = 0,
        limit: int = _WASM_ENTRY_DEFAULT,
    ) -> JsonObject:
        """Printable strings from a module's Data section (no wabt).

        Pulls maximal printable-ASCII runs of at least min_length characters from
        the Data-section segments -- the literal pool a module ships (URLs,
        format strings, error text) -- reading the binary directly, so it works
        on any host and cannot drift with a wabt version. Strings are distinct
        and sorted; contains keeps only those holding that case-insensitive
        substring (a blank filter is ignored). data_segments is how many segments
        were scanned, and incomplete flags a Data section truncated mid-walk or
        that hit the collection cap, so a short list is never read as the whole
        literal pool.
        """
        data = self._read_module(path)
        min_len = max(1, min(int(min_length), _WASM_STRINGS_MIN_CAP))
        try:
            strings, segments, incomplete = parse_data_strings(data, min_len=min_len)
        except WasmParseError as exc:
            raise JsReError("backend_error", str(exc), path=str(path)) from exc
        needle = contains.casefold() if contains and contains.strip() else None
        if needle is not None:
            strings = [text for text in strings if needle in text.casefold()]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _WASM_ENTRY_CAP))
        window = strings[start : start + cap]
        window, _dropped, _budget_cut = fit_json_list(window)
        result: JsonObject = {
            "strings": window,
            "count": len(window),
            "total": len(strings),
            "offset": start,
            "min_length": min_len,
            "data_segments": segments,
            "has_more": start + len(window) < len(strings),
            "incomplete": incomplete,
        }
        if needle is not None:
            result["filtered"] = True
        return result

    def _read_module(self, path: Path) -> bytes:
        # Existence and the 16 MiB input cap apply exactly as for the wabt tools,
        # but no wabt executable is required -- the parse is in-process.
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            return resolved.read_bytes()
        except OSError as exc:
            raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc


def _paged_entries(
    entries: list[JsonObject],
    key: str,
    declared: int,
    incomplete: bool,
    *,
    offset: int,
    limit: int,
) -> JsonObject:
    """Page a parsed import/export list and bound it by encoded size.

    total is what the parser actually recovered (and can page); declared is the
    count the module's section header claimed. incomplete is true when the two
    diverge because the module was truncated mid-parse or its declared count
    exceeded the entry cap -- so a short list is never read as the whole surface.
    A budget trim shrinks the window and shows up as has_more, letting the caller
    page past it, exactly like the sibling list tools.
    """
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _WASM_ENTRY_CAP))
    window = entries[start : start + cap]
    window, _dropped, _budget_cut = fit_json_list(window)
    return {
        key: window,
        "count": len(window),
        "total": len(entries),
        "offset": start,
        "declared": declared,
        "has_more": start + len(window) < len(entries),
        "incomplete": incomplete,
    }


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
