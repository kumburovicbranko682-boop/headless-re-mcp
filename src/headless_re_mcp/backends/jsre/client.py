"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import os
import re
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
# js.strings reads string literals straight from the source with no external
# tool. Bound the literal count scanned, the per-string length kept, the search
# term, the page and the template-nesting depth so a hostile or machine-
# generated bundle cannot make one call build an unbounded reply or recurse away.
_MIN_JS_STRING_LEN = 1
_MAX_JS_STRING_LEN = 8192
_MAX_JS_STRINGS_SCAN = 200_000
_MAX_JS_STRINGS_PAGE = 5000
_MAX_JS_STRINGS_CONTAINS = 256
_MAX_JS_TEMPLATE_DEPTH = 32
_JS_CATEGORIES = frozenset({"url", "path", "text"})
# A '/' begins a regex literal (rather than division) only in expression
# position -- i.e. right after one of these, or at the very start of input.
_JS_REGEX_PRECEDERS = frozenset("([{,;:?=!&|^~+-*/%<>")
_JS_URL_RE = re.compile(r"^(?:https?|wss?|ftp)://", re.IGNORECASE)
_JS_PATH_RE = re.compile(r"^/[A-Za-z0-9._~%/:@!$&'()*+,;=\-{}?#\[\]]*$")
_JS_SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
    "/": "/",
    "\n": "",  # line continuation: backslash-newline is removed
    "\r": "",
}
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


def _unescape_js(raw: str) -> str:
    """Resolve the common JS string escapes so a value is readable, best-effort.

    Handles \\n \\t \\r \\b \\f \\v \\0, the escaped quotes/backslash/slash,
    \\xHH, \\uHHHH and \\u{...}, and drops the backslash from a line
    continuation. An unknown escape keeps the following character verbatim; a
    malformed hex/unicode escape is left as-is rather than raising.
    """
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1]
        if nxt == "x" and i + 4 <= n:
            with suppress(ValueError):
                out.append(chr(int(raw[i + 2 : i + 4], 16)))
                i += 4
                continue
        if nxt == "u":
            if i + 2 < n and raw[i + 2] == "{":
                close = raw.find("}", i + 3)
                if close != -1:
                    with suppress(ValueError):
                        cp = int(raw[i + 3 : close], 16)
                        if 0 <= cp <= 0x10FFFF:
                            out.append(chr(cp))
                            i = close + 1
                            continue
            elif i + 6 <= n:
                with suppress(ValueError):
                    out.append(chr(int(raw[i + 2 : i + 6], 16)))
                    i += 6
                    continue
        out.append(_JS_SIMPLE_ESCAPES.get(nxt, nxt))
        i += 2
    return "".join(out)


def _js_regex_allowed(last_sig: str) -> bool:
    return last_sig == "" or last_sig in _JS_REGEX_PRECEDERS


def _scan_js_quoted(text: str, i: int, n: int, quote: str) -> tuple[str, int]:
    """Read a '...' / \"...\" literal starting at the opening quote; returns (value, next)."""
    i += 1
    buf: list[str] = []
    while i < n:
        c = text[i]
        if c == "\\":
            if i + 1 < n:
                buf.append(text[i : i + 2])
                i += 2
                continue
            i += 1
            break
        if c == quote:
            i += 1
            return _unescape_js("".join(buf)), i
        if c == "\n":  # a plain string literal cannot hold a raw newline
            return _unescape_js("".join(buf)), i
        buf.append(c)
        i += 1
    return _unescape_js("".join(buf)), i


def _scan_js_regex(text: str, i: int, n: int) -> int | None:
    """If text[i]=='/' opens a single-line regex, return the index after its flags.

    Returns None when no terminating '/' is found before the line ends, so the
    caller can fall back to treating the '/' as a division operator.
    """
    j = i + 1
    in_class = False
    while j < n:
        c = text[j]
        if c == "\n":
            return None
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < n and text[j].isalpha():
                j += 1
            return j
        j += 1
    return None


def _scan_js_string_literals(text: str, *, max_literals: int) -> tuple[list[str], bool]:
    """Collect every string / template-quasi literal in JS source, in order.

    A single pass that skips line and block comments and regex literals (so a
    quote inside one is not mistaken for a string start), reads ' and " strings,
    and walks template literals -- emitting each static quasi and recursing into
    ${...} interpolations so nested strings are found too. Returns the raw list
    (with duplicates) and whether the literal cap stopped the scan early.
    """
    out: list[str] = []
    state = {"capped": False}
    n = len(text)

    def emit(value: str) -> None:
        if state["capped"]:
            return
        if len(out) >= max_literals:
            state["capped"] = True
            return
        out.append(value)

    def emit_quasi(buf: list[str]) -> None:
        if buf:
            value = _unescape_js("".join(buf))
            if value:
                emit(value)

    def scan_template(i: int, depth: int) -> int:
        i += 1  # past the opening backtick
        buf: list[str] = []
        while i < n:
            c = text[i]
            if c == "\\":
                if i + 1 < n:
                    buf.append(text[i : i + 2])
                    i += 2
                    continue
                i += 1
                break
            if c == "`":
                i += 1
                break
            if c == "$" and i + 1 < n and text[i + 1] == "{":
                emit_quasi(buf)
                buf = []
                i = scan_interp(i + 2, depth + 1)
                continue
            buf.append(c)
            i += 1
        emit_quasi(buf)
        return i

    def scan_interp(i: int, depth: int) -> int:
        if depth > _MAX_JS_TEMPLATE_DEPTH:
            brace = 1
            while i < n and brace > 0:
                if text[i] == "{":
                    brace += 1
                elif text[i] == "}":
                    brace -= 1
                i += 1
            return i
        brace = 1
        while i < n and brace > 0:
            c = text[i]
            if c == "/" and i + 1 < n and text[i + 1] == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if c == "/" and i + 1 < n and text[i + 1] == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
                continue
            if c in ("'", '"'):
                value, i = _scan_js_quoted(text, i, n, c)
                if value:
                    emit(value)
                continue
            if c == "`":
                i = scan_template(i, depth + 1)
                continue
            if c == "{":
                brace += 1
            elif c == "}":
                brace -= 1
            i += 1
        return i

    i = 0
    last_sig = ""
    while i < n and not state["capped"]:
        c = text[i]
        if c in " \t\r\n\f\v":
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(n, i + 2)
            continue
        if c == "/" and _js_regex_allowed(last_sig):
            end = _scan_js_regex(text, i, n)
            i = end if end is not None else i + 1
            last_sig = "/"
            continue
        if c in ("'", '"'):
            value, i = _scan_js_quoted(text, i, n, c)
            emit(value)
            last_sig = c
            continue
        if c == "`":
            i = scan_template(i, 0)
            last_sig = "`"
            continue
        last_sig = c
        i += 1
    return out, state["capped"]


def _classify_js_string(value: str) -> str:
    """Bucket a literal as a url, an endpoint path, or plain text for triage."""
    v = value.strip()
    if _JS_URL_RE.match(v):
        return "url"
    if v.startswith("//") and "." in v and " " not in v and len(v) > 3:
        return "url"  # protocol-relative //host/path
    if len(v) > 1 and " " not in v and "\n" not in v and _JS_PATH_RE.match(v):
        return "path"
    return "text"


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

    def strings(
        self,
        path: Path,
        *,
        min_length: int = _MIN_JS_STRING_LEN,
        category: str = "",
        contains: str = "",
        offset: int = 0,
        limit: int = 200,
    ) -> JsonObject:
        """Extract and classify string literals from a JS file, no webcrack needed.

        js.deobfuscate needs Node/webcrack and returns the whole unminified body;
        this reads the source directly (so it works with no external tool) and
        answers the first question of web-app triage -- what endpoints, URLs,
        keys and messages a bundle carries. It is the JS analogue of apk.strings
        / wasm.strings: a single-pass scan that pulls the content of every string
        and template literal (skipping comments and regex literals so their
        contents are not mistaken for strings), then dedups by value with an
        occurrence count and buckets each into a ``category`` -- ``url`` (http,
        https, ws, wss, ftp or protocol-relative), ``path`` (a leading-slash
        endpoint) or ``text``. ``category`` filters the listing to one bucket,
        ``contains`` is a case-insensitive substring, and ``min_length`` drops
        short noise.

        Answers with strings (each value, count, category, and truncated when the
        value was cut at 8192 chars), count, total, offset and has_more for
        paging over the filtered set, distinct (all unique literals before
        filtering), category_counts (the url/path/text breakdown of the length/
        contains-filtered set, so it is informative even under a category filter),
        min_length and scan_capped (set once the 200000-literal ceiling stopped
        the scan). The list field is strings, not results.
        """
        if category and category not in _JS_CATEGORIES:
            raise JsReError(
                "invalid_params",
                "category must be url, path, text or empty",
                category=category,
            )
        if not isinstance(contains, str):
            contains = ""
        if len(contains) > _MAX_JS_STRINGS_CONTAINS:
            raise JsReError(
                "invalid_params",
                f"contains must be at most {_MAX_JS_STRINGS_CONTAINS} chars",
            )
        min_len = max(1, int(min_length))
        resolved = _require_existing_file(path, missing="input file not found")
        try:
            raw_bytes = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        text = raw_bytes.decode("utf-8", errors="replace")
        literals, scan_capped = _scan_js_string_literals(
            text, max_literals=_MAX_JS_STRINGS_SCAN
        )
        counts: dict[str, int] = {}
        truncated_values: set[str] = set()
        for value in literals:
            # Round-trip through utf-8 so a lone surrogate from a \\uD800 escape
            # cannot break JSON serialisation of the envelope later.
            safe = value.encode("utf-8", "replace").decode("utf-8")
            if len(safe) > _MAX_JS_STRING_LEN:
                safe = safe[:_MAX_JS_STRING_LEN]
                truncated_values.add(safe)
            counts[safe] = counts.get(safe, 0) + 1
        distinct = len(counts)
        needle = contains.lower()
        category_counts = {"url": 0, "path": 0, "text": 0}
        categorized: list[tuple[str, int, str]] = []
        for value, count in counts.items():
            if len(value) < min_len:
                continue
            if needle and needle not in value.lower():
                continue
            cat = _classify_js_string(value)
            category_counts[cat] += 1
            categorized.append((value, count, cat))
        selected = (
            [row for row in categorized if row[2] == category] if category else categorized
        )
        total = len(selected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_JS_STRINGS_PAGE))
        window = selected[start : start + cap]
        strings_out: list[JsonObject] = []
        for value, count, cat in window:
            item: JsonObject = {"value": value, "count": count, "category": cat}
            if value in truncated_values:
                item["truncated"] = True
            strings_out.append(item)
        result: JsonObject = {
            "path": str(resolved),
            "strings": strings_out,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "distinct": distinct,
            "category_counts": category_counts,
            "min_length": min_len,
            "scan_capped": scan_capped,
        }
        if category:
            result["category"] = category
        if contains:
            result["contains"] = contains
        return result


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


def _read_sleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Read a signed LEB128 (used by i32.const/i64.const in a data offset expr)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _WasmParseError("truncated SLEB128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if byte & 0x40:  # sign bit set: extend to a negative value
                result |= -(1 << shift)
            return result, pos
        if shift > 63:
            raise _WasmParseError("SLEB128 too long")


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


# The "name" custom section (WebAssembly binary Appendix, plus the extended
# name section proposal): subsection ids to a human space name. 0/1/2 are the
# standard ones; 3..11 come from the extended proposal that LLVM/wasm-tools emit.
_WASM_NAME_SUBSECTIONS = {
    0: "module",
    1: "function",
    2: "local",
    3: "label",
    4: "type",
    5: "table",
    6: "memory",
    7: "global",
    8: "elem",
    9: "data",
    10: "field",
    11: "tag",
}
# Subsections encoded as a plain namemap (index -> name). module(0) is a bare
# name; local(2)/label(3)/field(10) are indirect namemaps handled separately.
_WASM_NAMEMAP_SPACES = frozenset({4, 5, 6, 7, 8, 9, 11})
# Cap materialised name entries per space and flattened local entries, so a
# crafted or genuinely huge name section cannot build an unbounded envelope; the
# declared vec count is still reported so the truncation stays honest.
_MAX_WASM_NAME_ENTRIES = 50_000
_MAX_WASM_LOCAL_ENTRIES = 50_000


def _read_wasm_namemap(
    data: bytes, pos: int, end: int, cap: int
) -> tuple[list[JsonObject], int, bool]:
    """Read a WebAssembly namemap (vec of (index, name)) bounded to ``cap``.

    Returns the entries (sorted by index), the declared vec count (the real
    total, even when the list was capped) and whether the cap clipped it.
    """
    count, pos = _read_uleb128(data, pos)
    items: list[JsonObject] = []
    truncated = False
    for _ in range(count):
        if len(items) >= cap:
            truncated = True
            break
        if pos >= end:
            raise _WasmParseError("name map overruns subsection")
        index, pos = _read_uleb128(data, pos)
        text, pos = _read_wasm_name(data, pos, end)
        items.append({"index": index, "name": text})
    items.sort(key=lambda item: item["index"])
    return items, count, truncated


def _read_wasm_local_names(
    data: bytes, pos: int, end: int, cap: int
) -> tuple[list[JsonObject], bool]:
    """Read the local-name indirect namemap (vec of (funcidx, namemap)).

    Flattened to (function, index, name) rows, sorted by (function, index) and
    bounded to ``cap`` total rows so one function with thousands of locals cannot
    make the reply unbounded.
    """
    outer, pos = _read_uleb128(data, pos)
    out: list[JsonObject] = []
    truncated = False
    for _ in range(outer):
        if pos >= end:
            raise _WasmParseError("local name map overruns subsection")
        func_index, pos = _read_uleb128(data, pos)
        inner, pos = _read_uleb128(data, pos)
        for _ in range(inner):
            if len(out) >= cap:
                truncated = True
                break
            if pos >= end:
                raise _WasmParseError("local name entry overruns subsection")
            local_index, pos = _read_uleb128(data, pos)
            text, pos = _read_wasm_name(data, pos, end)
            out.append({"function": func_index, "index": local_index, "name": text})
        if truncated:
            break
    out.sort(key=lambda item: (item["function"], item["index"]))
    return out, truncated


def _parse_wasm_names(data: bytes, *, module: str) -> JsonObject:
    """Recover symbol names from the module's ``name`` custom section.

    wasm.summary reads the type/import/export tables, which name only what a
    module exposes to its host; the ``name`` custom section (WebAssembly binary
    Appendix, extended by the LLVM/wasm-tools proposal) is what carries the
    original *internal* names -- the functions, locals, globals, types and data
    segments a compiler emitted, which are otherwise anonymous indices. Recovering
    them turns a wall of ``func[142]`` into readable code, so this is the single
    most useful artifact a debug-info-bearing module ships.

    The walk finds the custom section named ``name`` and parses its subsections:
    the module name (0), the function namemap (1), the local indirect namemap (2)
    and the extended single-level namemaps (type/table/memory/global/elem/data/
    tag). A fault inside one subsection is local -- it is recorded and the walk
    resyncs to the declared subsection boundary, so a malformed local map never
    costs the function names before it. A structurally broken module faults
    cleanly as ``backend_error``, matching the summary reader's contract.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("backend_error", "not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    n = len(data)
    module_name = ""
    functions: list[JsonObject] = []
    functions_total = 0
    functions_truncated = False
    locals_list: list[JsonObject] = []
    locals_truncated = False
    other_spaces: dict[str, list[JsonObject]] = {}
    spaces_truncated: set[str] = set()
    subsections: list[JsonObject] = []
    has_name_section = False
    try:
        while pos < n:
            sec_id = data[pos]
            pos += 1
            sec_size, pos = _read_uleb128(data, pos)
            sec_end = pos + sec_size
            if sec_size < 0 or sec_end > n:
                raise _WasmParseError("section overruns module")
            if sec_id != 0:
                # Only a custom section can carry names; resync past any other.
                pos = sec_end
                continue
            cust_name, cpos = _read_wasm_name(data, pos, sec_end)
            if cust_name != "name":
                pos = sec_end
                continue
            has_name_section = True
            sp = cpos
            while sp < sec_end:
                sub_id = data[sp]
                sp += 1
                sub_size, sp = _read_uleb128(data, sp)
                sub_end = sp + sub_size
                if sub_size < 0 or sub_end > sec_end:
                    raise _WasmParseError("name subsection overruns section")
                kind = _WASM_NAME_SUBSECTIONS.get(sub_id, f"subsection_{sub_id}")
                record: JsonObject = {"id": sub_id, "kind": kind, "size": sub_size}
                with suppress(_WasmParseError):
                    if sub_id == 0:
                        module_name, _ = _read_wasm_name(data, sp, sub_end)
                    elif sub_id == 1:
                        functions, functions_total, functions_truncated = _read_wasm_namemap(
                            data, sp, sub_end, _MAX_WASM_NAME_ENTRIES
                        )
                        record["count"] = functions_total
                    elif sub_id == 2:
                        locals_list, locals_truncated = _read_wasm_local_names(
                            data, sp, sub_end, _MAX_WASM_LOCAL_ENTRIES
                        )
                        record["count"] = len(locals_list)
                    elif sub_id in _WASM_NAMEMAP_SPACES:
                        items, declared, trunc = _read_wasm_namemap(
                            data, sp, sub_end, _MAX_WASM_NAME_ENTRIES
                        )
                        other_spaces[kind] = items
                        record["count"] = declared
                        if trunc:
                            spaces_truncated.add(kind)
                subsections.append(record)
                sp = sub_end
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
        "has_name_section": has_name_section,
        "module_name": module_name,
        "functions": functions,
        "function_count": len(functions),
        "locals": locals_list,
        "other_spaces": other_spaces,
        "subsections": subsections,
    }
    if functions_truncated:
        result["functions_truncated"] = True
        result["functions_total"] = functions_total
    if locals_truncated:
        result["locals_truncated"] = True
    if spaces_truncated:
        result["spaces_truncated"] = sorted(spaces_truncated)
    return result


# wasm.strings bounds: the shortest run reported, the longest kept per string,
# how many strings one reply collects, and the default paging window.
_MIN_WASM_STRING_LEN = 4
_MAX_WASM_STRING_LEN = 4096
_MAX_WASM_STRINGS_SCAN = 50_000
_MAX_WASM_STRINGS_PAGE = 5000
# The printable ASCII band a run must stay within to count as a string, matching
# a classic `strings -a` pass; a high byte (UTF-8 lead/continuation, or binary)
# breaks the run.
_WASM_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09}


def _read_wasm_const_offset(data: bytes, pos: int, end: int) -> tuple[int | None, int]:
    """Parse a data segment's offset const-expr, returning (offset, pos_after_end).

    The active data segment's placement is a constant expression terminated by
    ``end`` (0x0B). The overwhelmingly common form is ``i32.const N``, which
    yields the memory offset N; ``global.get`` (an imported base) leaves the
    offset unknown (None). The parser has to consume the whole expression exactly
    -- not scan for 0x0B, whose byte can appear inside an SLEB immediate -- so it
    can find the byte vector that follows; an opcode it cannot model raises so the
    caller stops rather than misreading the following bytes as a string.
    """
    offset: int | None = None
    while True:
        if pos >= end:
            raise _WasmParseError("const expr overruns data segment")
        op = data[pos]
        pos += 1
        if op == 0x0B:  # end
            return offset, pos
        if op == 0x41:  # i32.const
            offset, pos = _read_sleb128(data, pos)
        elif op == 0x42:  # i64.const
            _, pos = _read_sleb128(data, pos)
        elif op == 0x43:  # f32.const
            pos += 4
        elif op == 0x44:  # f64.const
            pos += 8
        elif op == 0x23:  # global.get: an imported base, so the offset is unknown
            _, pos = _read_uleb128(data, pos)
            offset = None
        else:
            raise _WasmParseError(f"unsupported const-expr opcode 0x{op:02x}")


def _extract_wasm_strings(
    blob: bytes,
    *,
    segment: int,
    base: int | None,
    min_length: int,
    out: list[JsonObject],
    remaining: int,
) -> int:
    """Append printable runs from one data blob to ``out``; returns how many left.

    ``base`` is the segment's memory offset when known, so each run reports its
    absolute linear-memory address; a run longer than the per-string cap is cut
    and flagged. Collection stops once ``remaining`` reaches zero.
    """
    run = bytearray()
    run_start = 0
    n = len(blob)
    i = 0
    while i <= n:
        byte = blob[i] if i < n else None
        if byte is not None and byte in _WASM_PRINTABLE:
            if not run:
                run_start = i
            run.append(byte)
            if len(run) >= _MAX_WASM_STRING_LEN:
                # Emit the capped run and keep scanning from here so a huge blob
                # of printable bytes cannot build one unbounded string.
                remaining = _emit_wasm_string(
                    run, run_start, segment, base, min_length, out, remaining, truncated=True
                )
                run = bytearray()
                if remaining <= 0:
                    return 0
        else:
            if run:
                remaining = _emit_wasm_string(
                    run, run_start, segment, base, min_length, out, remaining, truncated=False
                )
                run = bytearray()
                if remaining <= 0:
                    return 0
        i += 1
    return remaining


def _emit_wasm_string(
    run: bytearray,
    run_start: int,
    segment: int,
    base: int | None,
    min_length: int,
    out: list[JsonObject],
    remaining: int,
    *,
    truncated: bool,
) -> int:
    if len(run) < min_length:
        return remaining
    entry: JsonObject = {
        "string": run.decode("ascii", "replace"),
        "segment": segment,
        "segment_offset": run_start,
        "offset": (base + run_start) if base is not None else None,
    }
    if truncated:
        entry["value_truncated"] = True
    out.append(entry)
    return remaining - 1


def _parse_wasm_strings(data: bytes, *, module: str, min_length: int) -> JsonObject:
    """Extract printable strings from a module's Data section.

    A wasm module's string literals, URLs, format strings and embedded constants
    live in its Data section's segments, exactly where a native binary keeps its
    .rodata -- but no reader here surfaced them, so a wasm was the one target with
    no ``strings`` pass. This walks the Data section, decodes each segment's
    placement (an active segment's ``i32.const`` offset gives an absolute memory
    address; a passive one has none) and scans the bytes for printable ASCII runs
    at least ``min_length`` long, the wasm analogue of r2.strings / apk.strings.
    Reads the bytes directly (no wabt); a malformed module faults cleanly.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("backend_error", "not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    n = len(data)
    strings: list[JsonObject] = []
    remaining = _MAX_WASM_STRINGS_SCAN
    segments = 0
    scanned_bytes = 0
    scan_capped = False
    try:
        while pos < n:
            sec_id = data[pos]
            pos += 1
            sec_size, pos = _read_uleb128(data, pos)
            sec_end = pos + sec_size
            if sec_size < 0 or sec_end > n:
                raise _WasmParseError("section overruns module")
            if sec_id != 11:  # only the Data section carries segment bytes
                pos = sec_end
                continue
            count, p = _read_uleb128(data, pos)
            for _ in range(count):
                if p >= sec_end:
                    raise _WasmParseError("data segment truncated")
                flags, p = _read_uleb128(data, p)
                base: int | None
                if flags == 0:  # active, memory 0, offset const-expr
                    base, p = _read_wasm_const_offset(data, p, sec_end)
                elif flags == 1:  # passive: no placement
                    base = None
                elif flags == 2:  # active with explicit memory index
                    _, p = _read_uleb128(data, p)  # memidx
                    base, p = _read_wasm_const_offset(data, p, sec_end)
                else:
                    raise _WasmParseError(f"unknown data segment flags {flags}")
                seg_len, p = _read_uleb128(data, p)
                if seg_len < 0 or p + seg_len > sec_end:
                    raise _WasmParseError("data segment bytes overrun section")
                blob = data[p : p + seg_len]
                p += seg_len
                scanned_bytes += seg_len
                if remaining > 0:
                    remaining = _extract_wasm_strings(
                        blob,
                        segment=segments,
                        base=base,
                        min_length=min_length,
                        out=strings,
                        remaining=remaining,
                    )
                    if remaining <= 0:
                        scan_capped = True
                segments += 1
            pos = sec_end
    except _WasmParseError as exc:
        raise JsReError("backend_error", f"malformed WebAssembly module: {exc}") from exc
    except IndexError as exc:  # a read ran off the end despite the guards
        raise JsReError(
            "backend_error", "malformed WebAssembly module: unexpected end of data"
        ) from exc
    return {
        "module": module,
        "version": version,
        "strings": strings,
        "total": len(strings),
        "data_segments": segments,
        "scanned_bytes": scanned_bytes,
        "min_length": min_length,
        "scan_capped": scan_capped,
    }


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

    def names(self, path: Path, *, timeout: float = 30.0) -> JsonObject:
        """Recover internal symbol names from the module's ``name`` section.

        Where wasm.summary names only imports/exports, this reads the ``name``
        custom section for the original function/local/global/type/data names a
        compiler emitted, mapping anonymous indices back to readable identifiers.
        Reads the bytes directly (no wabt), and a malformed module faults cleanly.
        ``timeout`` is accepted for signature symmetry but the parse is a bounded
        in-process walk.
        """
        _ = timeout
        resolved = _require_existing_file(path, missing="wasm file not found")
        return _parse_wasm_names(resolved.read_bytes(), module=resolved.name)

    def strings(
        self,
        path: Path,
        *,
        min_length: int = _MIN_WASM_STRING_LEN,
        offset: int = 0,
        limit: int = 200,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Extract printable strings from the module's Data section.

        The wasm analogue of r2.strings / apk.strings: it surfaces the string
        literals, URLs, format strings and constants a module keeps in its data
        segments, each with its absolute memory offset when the segment is active.
        Reads the bytes directly (no wabt); a malformed module faults cleanly.
        """
        _ = timeout
        resolved = _require_existing_file(path, missing="wasm file not found")
        clamped = max(1, min(int(min_length), 1024))
        parsed = _parse_wasm_strings(
            resolved.read_bytes(), module=resolved.name, min_length=clamped
        )
        collected: list[JsonObject] = parsed["strings"]
        total = len(collected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_WASM_STRINGS_PAGE))
        window = collected[start : start + cap]
        parsed["strings"] = window
        parsed["count"] = len(window)
        parsed["total"] = total
        parsed["offset"] = start
        parsed["has_more"] = start + len(window) < total
        return parsed

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
