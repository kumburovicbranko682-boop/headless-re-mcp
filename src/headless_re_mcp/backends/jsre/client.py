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
from headless_re_mcp.backends.jsre.js_sourcemap import (
    SourceMapError,
    decode_data_uri,
    extract_source,
    find_source_mapping_url,
    flatten_sources,
    is_probably_map_json,
    is_remote_url,
    list_sources,
    parse_source_map,
)
from headless_re_mcp.backends.jsre.js_strings import extract_endpoints as extract_js_endpoints
from headless_re_mcp.backends.jsre.js_strings import extract_secrets as extract_js_secrets
from headless_re_mcp.backends.jsre.js_strings import extract_strings as extract_js_strings
from headless_re_mcp.backends.jsre.wasm_summary import WasmParseError
from headless_re_mcp.backends.jsre.wasm_summary import parse_data_endpoints as parse_wasm_endpoints
from headless_re_mcp.backends.jsre.wasm_summary import parse_data_secrets as parse_wasm_secrets
from headless_re_mcp.backends.jsre.wasm_summary import parse_data_strings as parse_wasm_strings
from headless_re_mcp.backends.jsre.wasm_summary import parse_function_names as parse_wasm_names
from headless_re_mcp.backends.jsre.wasm_summary import parse_functions as parse_wasm_functions
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
# Page ceiling for wasm.names, mirroring the tool's Field(le=...) so the agent
# transport (which reaches the handler without pydantic validation) is bounded
# here too, exactly like the apk/web/proxy backends.
_MAX_WASM_NAMES_PAGE = 2000
# Same rationale for wasm.strings.
_MAX_WASM_STRINGS_PAGE = 2000
# Same rationale for wasm.endpoints.
_MAX_WASM_ENDPOINTS_PAGE = 2000
# Same rationale for wasm.secrets.
_MAX_WASM_SECRETS_PAGE = 2000
# Same rationale for wasm.functions.
_MAX_WASM_FUNCTIONS_PAGE = 2000
# Same rationale for js.strings.
_MAX_JS_STRINGS_PAGE = 2000
# Same rationale for js.endpoints.
_MAX_JS_ENDPOINTS_PAGE = 2000
# Same rationale for js.secrets.
_MAX_JS_SECRETS_PAGE = 2000
# js.sourcemap list-page ceiling, same transport rationale as the others.
_MAX_JS_SOURCEMAP_PAGE = 2000
# A single original source returned in extract mode is clipped here so one huge
# recovered file cannot make the response unbounded; content_truncated says so.
_MAX_SOURCEMAP_CONTENT_BYTES = 2 * 1024 * 1024


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

    def strings(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        min_length: int = 3,
        name_filter: str = "",
    ) -> JsonObject:
        """Extract string literals from a JavaScript file, without webcrack.

        Dependency-free (no Node/webcrack): the source is read and lexed in
        process, so this stays available when webcrack is not configured -- the
        way the wasm.summary/names/strings trio stays available without wabt.
        \\x/\\u escapes are decoded, which unmasks a URL an obfuscator hid as a
        hex-escaped string. Paged; total is the count that matched the filter,
        and scan_capped marks a file with more literals than the collect ceiling.
        """
        resolved = _require_existing_file(path, missing="input file not found")
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        source = raw.decode("utf-8", errors="replace")
        rows, scan_capped = extract_js_strings(
            source, min_length=min_length, name_filter=name_filter
        )
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_JS_STRINGS_PAGE))
        window = rows[start : start + capped]
        return {
            "strings": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_capped,
        }

    def endpoints(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        include_paths: bool = True,
    ) -> JsonObject:
        """Extract network endpoints (URLs, hosts, request paths) from JS, no webcrack.

        Dependency-free, built on the same lexer as strings(): URLs and request
        paths are pulled from string literals (escape-decoded, comment/regex
        safe), deduplicated and aggregated by occurrence. Paged; total is the
        count that matched the filter, hosts is the distinct URL host set, and
        scan_capped marks a file with more distinct endpoints than the ceiling.
        """
        resolved = _require_existing_file(path, missing="input file not found")
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        source = raw.decode("utf-8", errors="replace")
        endpoints, hosts, hosts_truncated, scan_capped = extract_js_endpoints(
            source, include_paths=include_paths, name_filter=name_filter
        )
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_JS_ENDPOINTS_PAGE))
        window = endpoints[start : start + capped]
        return {
            "endpoints": window,
            "count": len(window),
            "total": len(endpoints),
            "offset": start,
            "has_more": start + len(window) < len(endpoints),
            "hosts": hosts,
            "hosts_truncated": hosts_truncated,
            "scan_capped": scan_capped,
        }

    def secrets(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        include_generic: bool = False,
    ) -> JsonObject:
        """Detect embedded credentials in a JavaScript file, without webcrack.

        Dependency-free, built on the same lexer as strings()/endpoints(): a set
        of high-precision credential detectors (plus an opt-in high-entropy
        catch-all) is run over the string literals, escape-decoded and
        comment/regex safe. Paged; total is the count that matched the filter,
        detectors is the distinct detector set present, and scan_capped marks a
        file with more distinct findings than the collect ceiling.
        """
        resolved = _require_existing_file(path, missing="input file not found")
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        source = raw.decode("utf-8", errors="replace")
        secrets, detectors, scan_capped = extract_js_secrets(
            source, name_filter=name_filter, include_generic=include_generic
        )
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_JS_SECRETS_PAGE))
        window = secrets[start : start + capped]
        return {
            "secrets": window,
            "count": len(window),
            "total": len(secrets),
            "offset": start,
            "has_more": start + len(window) < len(secrets),
            "detectors": detectors,
            "scan_capped": scan_capped,
        }

    def _load_map_text(self, source: str, resolved: Path) -> tuple[str, str]:
        """Resolve the map document for ``resolved``; returns (json_text, origin).

        ``resolved`` may be the ``.map`` itself, or a JS file whose trailing
        ``sourceMappingURL`` points at an inline data: URI or an adjacent file. A
        remote (http/protocol-relative) reference is refused with guidance rather
        than fetched, because this backend does no network I/O.
        """
        if is_probably_map_json(source):
            return source, "file"
        url = find_source_mapping_url(source)
        if url is None:
            raise JsReError(
                "not_found",
                "input is neither a source map nor a JS file with a sourceMappingURL",
                path=str(resolved),
            )
        if url.startswith("data:"):
            try:
                return decode_data_uri(url, max_bytes=_MAX_INPUT_BYTES), "inline"
            except SourceMapError as exc:
                raise JsReError(exc.code, exc.message, path=str(resolved)) from exc
        if is_remote_url(url):
            raise JsReError(
                "capability_unavailable",
                "source map is at a remote URL; fetch it and pass the .map file",
                path=str(resolved),
                url=url,
            )
        candidate = (resolved.parent / url).expanduser()
        map_file = _require_existing_file(candidate, missing="referenced source map not found")
        try:
            return map_file.read_bytes().decode("utf-8", errors="replace"), f"external:{url}"
        except OSError as exc:
            raise JsReError(
                "backend_error", f"referenced source map unreadable: {exc}", path=str(map_file)
            ) from exc

    def sourcemap(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        extract: str = "",
    ) -> JsonObject:
        """Recover original sources from a JS source map, without webcrack.

        Dependency-free: the file is read and parsed in process, so it stays
        available when webcrack is not configured. Accepts the ``.map`` itself, or
        a ``.js`` whose trailing sourceMappingURL is an inline data: URI or an
        adjacent file (a remote URL is refused with guidance, not fetched). In the
        default list mode it returns one row per original source; in extract mode
        (extract set) it returns that source's full original text from
        sourcesContent. Flat maps and index maps (``sections``) are both handled.
        """
        resolved = _require_existing_file(path, missing="input file not found")
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        source = raw.decode("utf-8", errors="replace")
        map_text, origin = self._load_map_text(source, resolved)
        try:
            data = parse_source_map(map_text)
            sources, contents, meta = flatten_sources(data)
        except SourceMapError as exc:
            raise JsReError(exc.code, exc.message, path=str(resolved)) from exc
        if extract:
            return extract_source(
                sources,
                contents,
                meta,
                origin,
                extract,
                content_cap=_MAX_SOURCEMAP_CONTENT_BYTES,
            )
        return list_sources(
            sources,
            contents,
            meta,
            origin,
            offset=offset,
            limit=limit,
            name_filter=name_filter,
            page_cap=_MAX_JS_SOURCEMAP_PAGE,
        )


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

    def names(
        self, path: Path, *, offset: int = 0, limit: int = 200, name_filter: str = ""
    ) -> JsonObject:
        """Function-index -> name mapping from the module's ``name`` section.

        Also dependency-free (no wabt). When the module was stripped of its name
        section, has_name_section is False and the list is empty -- the answer,
        not an error. The list is paged; total is the count that matched the
        filter, and scan_capped marks a namemap larger than the collect ceiling.
        """
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        try:
            module_name, entries, has_section, scan_capped = parse_wasm_names(
                data, name_filter=name_filter
            )
        except WasmParseError as exc:
            raise JsReError(
                "invalid_params", f"not a readable wasm module: {exc}", path=str(resolved)
            ) from exc
        entries.sort(key=lambda item: int(item["index"]))
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_WASM_NAMES_PAGE))
        window = entries[start : start + capped]
        return {
            "module_name": module_name,
            "has_name_section": has_section,
            "names": window,
            "count": len(window),
            "total": len(entries),
            "offset": start,
            "has_more": start + len(window) < len(entries),
            "scan_capped": scan_capped,
        }

    def functions(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        include_imports: bool = True,
    ) -> JsonObject:
        """Function table (index -> name, signature, size, origin), no wabt.

        The inventory companion to summary()/names(): it joins the type, import,
        function and code sections into one function-index-ordered table, then
        layers export names and the name section over it. Dependency-free, paged;
        total is the count that matched the filter, summary carries the module's
        pre-filter totals, and scan_capped marks a section past the collect
        ceiling.
        """
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        try:
            rows, summary, scan_capped = parse_wasm_functions(
                data, include_imports=include_imports, name_filter=name_filter
            )
        except WasmParseError as exc:
            raise JsReError(
                "invalid_params", f"not a readable wasm module: {exc}", path=str(resolved)
            ) from exc
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_WASM_FUNCTIONS_PAGE))
        window = rows[start : start + capped]
        return {
            "functions": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "summary": summary,
            "scan_capped": scan_capped,
        }

    def strings(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        min_length: int = 4,
        name_filter: str = "",
    ) -> JsonObject:
        """Printable strings from the module's data (rodata) section, no wabt.

        The content companion to summary()/names(): rodata is where a module's
        URLs, error messages and format strings live. Dependency-free, paged;
        total is the count that matched the filter, has_data_section is False
        when the module ships no data section (the answer, not an error), and
        scan_capped marks a section with more strings than the collect ceiling.
        """
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        try:
            rows, has_data, scan_capped = parse_wasm_strings(
                data, min_length=min_length, name_filter=name_filter
            )
        except WasmParseError as exc:
            raise JsReError(
                "invalid_params", f"not a readable wasm module: {exc}", path=str(resolved)
            ) from exc
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_WASM_STRINGS_PAGE))
        window = rows[start : start + capped]
        return {
            "has_data_section": has_data,
            "strings": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_capped,
        }

    def endpoints(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        include_paths: bool = True,
    ) -> JsonObject:
        """Network endpoints (URLs, hosts, request paths) from the data section, no wabt.

        The endpoint companion to strings(): it runs the same URL/path recogniser
        js.endpoints/apk.endpoints use over the module's rodata runs, so a wasm
        module gives up the backends it reaches without wabt. Dependency-free,
        paged; total is the count that matched the filter, hosts is the distinct
        URL host set, has_data_section is False when the module ships no data
        section (the answer, not an error), and scan_capped marks a module with
        more distinct endpoints than the ceiling.
        """
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        try:
            endpoints, hosts, hosts_truncated, has_data, scan_capped = parse_wasm_endpoints(
                data, include_paths=include_paths, name_filter=name_filter
            )
        except WasmParseError as exc:
            raise JsReError(
                "invalid_params", f"not a readable wasm module: {exc}", path=str(resolved)
            ) from exc
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_WASM_ENDPOINTS_PAGE))
        window = endpoints[start : start + capped]
        return {
            "has_data_section": has_data,
            "endpoints": window,
            "count": len(window),
            "total": len(endpoints),
            "offset": start,
            "has_more": start + len(window) < len(endpoints),
            "hosts": hosts,
            "hosts_truncated": hosts_truncated,
            "scan_capped": scan_capped,
        }

    def secrets(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        include_generic: bool = False,
    ) -> JsonObject:
        """Embedded credentials in the module's data (rodata) section, no wabt.

        The credential companion to strings()/endpoints(): it runs the same
        high-precision detector table js.secrets/apk.secrets use over the module's
        rodata runs, so a wasm module that baked in a key gives it up without
        wabt. Dependency-free, paged; total is the count that matched the filter,
        detectors is the distinct detector set present, has_data_section is False
        when the module ships no data section (the answer, not an error), and
        scan_capped marks a module with more distinct findings than the ceiling.
        """
        resolved = _require_existing_file(path, missing="wasm file not found")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        try:
            secrets, detectors, has_data, scan_capped = parse_wasm_secrets(
                data, name_filter=name_filter, include_generic=include_generic
            )
        except WasmParseError as exc:
            raise JsReError(
                "invalid_params", f"not a readable wasm module: {exc}", path=str(resolved)
            ) from exc
        start = max(0, int(offset))
        capped = max(1, min(int(limit), _MAX_WASM_SECRETS_PAGE))
        window = secrets[start : start + capped]
        return {
            "has_data_section": has_data,
            "secrets": window,
            "count": len(window),
            "total": len(secrets),
            "offset": start,
            "has_more": start + len(window) < len(secrets),
            "detectors": detectors,
            "scan_capped": scan_capped,
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
