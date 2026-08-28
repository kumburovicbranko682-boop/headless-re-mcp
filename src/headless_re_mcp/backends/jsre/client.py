"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import bisect
import os
import re
import shutil
import struct
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
# js.imports reads a module's dependency edges straight from the source with no
# external tool. Bound the edges collected, the page, the named bindings kept
# per import, the specifier length, the unique-specifier summary and the
# look-ahead window used to find `from "spec"`, so a hostile or machine-
# generated bundle cannot make one call build an unbounded reply.
_MAX_JS_IMPORTS_SCAN = 100_000
_MAX_JS_IMPORTS_PAGE = 2000
_MAX_JS_IMPORT_NAMES = 256
_MAX_JS_SPECIFIER_LEN = 4096
_MAX_JS_SPECIFIERS_SUMMARY = 2000
_JS_IMPORT_FROM_WINDOW = 8192
_JS_IMPORT_KINDS = frozenset({"import", "export_from", "dynamic_import", "require"})
_JS_NAME_RE = re.compile(r"[A-Za-z_$][\w$]*")
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


def _js_line_starts(text: str) -> list[int]:
    """Offsets where each source line begins, for O(log n) line lookups."""
    starts = [0]
    idx = text.find("\n")
    while idx != -1:
        starts.append(idx + 1)
        idx = text.find("\n", idx + 1)
    return starts


def _js_is_ident_char(c: str) -> bool:
    return c.isalnum() or c in "_$" or ord(c) > 127


def _js_read_word(text: str, i: int, n: int) -> tuple[str, int]:
    """Read a maximal identifier / keyword run starting at i; ('', i) if none."""
    j = i
    while j < n and _js_is_ident_char(text[j]):
        j += 1
    return text[i:j], j


def _js_skip_ws_comments(text: str, i: int, n: int) -> int:
    """Advance past any run of whitespace and // or /* */ comments."""
    while i < n:
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
        break
    return i


def _clip_specifier(value: str) -> str:
    return value[:_MAX_JS_SPECIFIER_LEN]


def _js_skip_template(text: str, i: int, n: int, depth: int = 0) -> int:
    """Return the index just past the template literal whose backtick is at i.

    Walks ${...} interpolations (skipping strings, comments and nested
    templates inside them) so a } or ` sitting in a string cannot end the
    template early and desync the caller.
    """
    i += 1  # past the opening backtick
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2 if i + 1 < n else 1
            continue
        if c == "`":
            return i + 1
        if c == "$" and i + 1 < n and text[i + 1] == "{":
            i = _js_skip_interp(text, i + 2, n, depth + 1)
            continue
        i += 1
    return i


def _js_skip_interp(text: str, i: int, n: int, depth: int) -> int:
    """Return the index just past a template ${...} whose body starts at i."""
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
            _, i = _scan_js_quoted(text, i, n, c)
            continue
        if c == "`":
            i = _js_skip_template(text, i, n, depth)
            continue
        if c == "{":
            brace += 1
        elif c == "}":
            brace -= 1
        i += 1
    return i


def _js_read_specifier_literal(text: str, i: int, n: int) -> tuple[str | None, int]:
    """If text[i] opens a string / no-interpolation template, return its value.

    A template that contains ${...} is a computed specifier, so it yields None
    (the caller then records no concrete edge).
    """
    if i >= n:
        return None, i
    c = text[i]
    if c in ("'", '"'):
        value, j = _scan_js_quoted(text, i, n, c)
        return _clip_specifier(value), j
    if c == "`":
        j = i + 1
        buf: list[str] = []
        while j < n:
            ch = text[j]
            if ch == "\\" and j + 1 < n:
                buf.append(text[j + 1])
                j += 2
                continue
            if ch == "`":
                return _clip_specifier(_unescape_js("".join(buf))), j + 1
            if ch == "$" and j + 1 < n and text[j + 1] == "{":
                return None, i  # computed template specifier
            buf.append(ch)
            j += 1
        return None, i
    return None, i


def _js_find_from_specifier(
    text: str, p: int, n: int, window_end: int
) -> tuple[str | None, int]:
    """Scan an import/export clause for `from "spec"`.

    Returns (specifier, index-of-the-`from`-keyword) or (None, -1). Brace depth
    is tracked so a `from` used as a binding name -- import {from} from "x" --
    is not mistaken for the module keyword, and strings / comments / templates
    are skipped so their contents never trigger a false match.
    """
    i = p
    depth = 0
    while i < window_end and i < n:
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
            _, i = _scan_js_quoted(text, i, n, c)
            continue
        if c == "`":
            i = _js_skip_template(text, i, n)
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth = max(0, depth - 1)
            i += 1
            continue
        if c == ";" and depth == 0:
            return None, -1
        if depth == 0 and _js_is_ident_char(c) and not c.isdigit():
            word, j = _js_read_word(text, i, n)
            if word == "from":
                k = _js_skip_ws_comments(text, j, n)
                spec, _ = _js_read_specifier_literal(text, k, n)
                return (spec, i) if spec is not None else (None, -1)
            i = j
            continue
        i += 1
    return None, -1


def _js_strip_comments(s: str) -> str:
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        if s[i] == "/" and i + 1 < n and s[i + 1] == "/":
            i += 2
            while i < n and s[i] != "\n":
                i += 1
        elif s[i] == "/" and i + 1 < n and s[i + 1] == "*":
            i += 2
            while i + 1 < n and not (s[i] == "*" and s[i + 1] == "/"):
                i += 1
            i = min(n, i + 2)
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _parse_js_import_bindings(
    clause: str,
) -> tuple[str | None, str | None, list[str]]:
    """Pull (default, namespace, named-imports) from an import/export clause.

    Best-effort: the specifier and kind are always exact, these binding names
    are a convenience. Handles ``default``, ``* as ns``, ``{ a, b as c }`` and
    a leading TypeScript ``type`` modifier before ``{`` / ``*``.
    """
    s = _js_strip_comments(clause)
    n = len(s)
    default: str | None = None
    namespace: str | None = None
    names: list[str] = []

    def skip_ws(i: int) -> int:
        while i < n and s[i].isspace():
            i += 1
        return i

    def read_word(i: int) -> tuple[str, int]:
        j = i
        while j < n and (s[j].isalnum() or s[j] in "_$"):
            j += 1
        return s[i:j], j

    i = skip_ws(0)
    if i < n and s[i] not in "{*":
        word, j = read_word(i)
        if word == "type":  # TS `import type ...` modifier
            k = skip_ws(j)
            if k < n and s[k] in "{*":
                i = k
            elif word:
                default, i = word, skip_ws(j)
        elif word:
            default = word
            i = skip_ws(j)
        if i < n and s[i] == ",":
            i = skip_ws(i + 1)
    if i < n and s[i] == "*":
        i = skip_ws(i + 1)
        kw, j = read_word(i)
        if kw == "as":
            i = skip_ws(j)
            ns, _ = read_word(i)
            if ns:
                namespace = ns
    elif i < n and s[i] == "{":
        close = s.find("}", i + 1)
        inner = s[i + 1 : close if close != -1 else n]
        for part in inner.split(","):
            m = _JS_NAME_RE.search(part)
            if m is None:
                continue
            name = m.group(0)
            if name == "type":  # `import { type X }` -- take the real name
                rest = part[m.end() :]
                m2 = _JS_NAME_RE.search(rest)
                if m2 is not None:
                    name = m2.group(0)
            names.append(name)
            if len(names) >= _MAX_JS_IMPORT_NAMES:
                break
    return default, namespace, names


def _js_import_lookahead(text: str, kw_end: int, n: int) -> JsonObject | None:
    """Classify what follows a top-level ``import`` keyword into one edge."""
    p = _js_skip_ws_comments(text, kw_end, n)
    if p >= n:
        return None
    ch = text[p]
    if ch == ".":  # import.meta -- not a dependency
        return None
    if ch == "(":  # dynamic import()
        q = _js_skip_ws_comments(text, p + 1, n)
        spec, _ = _js_read_specifier_literal(text, q, n)
        if spec is None:
            return None
        return {"kind": "dynamic_import", "specifier": spec}
    if ch in ("'", '"', "`"):  # side-effect import "mod"
        spec, _ = _js_read_specifier_literal(text, p, n)
        if spec is None:
            return None
        return {"kind": "import", "specifier": spec}
    spec, from_start = _js_find_from_specifier(
        text, p, n, min(n, p + _JS_IMPORT_FROM_WINDOW)
    )
    if spec is None:
        return None
    edge: JsonObject = {"kind": "import", "specifier": spec}
    default, namespace, names = _parse_js_import_bindings(text[p:from_start])
    if default:
        edge["default"] = default
    if namespace:
        edge["namespace"] = namespace
    if names:
        edge["names"] = names
    return edge


def _js_export_lookahead(text: str, kw_end: int, n: int) -> JsonObject | None:
    """Detect a re-export (``export ... from "mod"``) after an ``export`` word."""
    p = _js_skip_ws_comments(text, kw_end, n)
    if p >= n or text[p] not in "*{":
        return None  # export default / declarations carry no dependency edge
    spec, from_start = _js_find_from_specifier(
        text, p, n, min(n, p + _JS_IMPORT_FROM_WINDOW)
    )
    if spec is None:
        return None
    edge: JsonObject = {"kind": "export_from", "specifier": spec}
    _, namespace, names = _parse_js_import_bindings(text[p:from_start])
    if namespace:
        edge["namespace"] = namespace
    if names:
        edge["names"] = names
    return edge


def _js_require_lookahead(text: str, kw_end: int, n: int) -> JsonObject | None:
    """Detect a CommonJS ``require("mod")`` call after a ``require`` word."""
    p = _js_skip_ws_comments(text, kw_end, n)
    if p >= n or text[p] != "(":
        return None
    q = _js_skip_ws_comments(text, p + 1, n)
    spec, _ = _js_read_specifier_literal(text, q, n)
    if spec is None:
        return None
    return {"kind": "require", "specifier": spec}


def _scan_js_imports(text: str, *, max_edges: int) -> tuple[list[JsonObject], bool]:
    """Collect a module's dependency edges (import / export-from / require).

    One left-to-right pass that skips comments, regex literals and string /
    template literals (so a keyword inside one is never read as code), then --
    when ``import``, ``export`` or ``require`` appears in code position -- looks
    ahead to classify the edge without moving the main cursor past the keyword,
    so the clause is still re-scanned normally and cannot desync. Returns the
    edges in source order and whether the edge cap stopped the scan early.
    """
    edges: list[JsonObject] = []
    n = len(text)
    line_starts = _js_line_starts(text)
    state = {"capped": False}

    def add(edge: JsonObject | None, start: int) -> None:
        if edge is None or state["capped"]:
            return
        if len(edges) >= max_edges:
            state["capped"] = True
            return
        edge["line"] = bisect.bisect_right(line_starts, start)
        edges.append(edge)

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
            _, i = _scan_js_quoted(text, i, n, c)
            last_sig = c
            continue
        if c == "`":
            i = _js_skip_template(text, i, n)
            last_sig = "`"
            continue
        if _js_is_ident_char(c) and not c.isdigit():
            word, j = _js_read_word(text, i, n)
            prev_dot = last_sig == "."
            if word == "import" and not prev_dot:
                add(_js_import_lookahead(text, j, n), i)
            elif word == "export" and not prev_dot:
                add(_js_export_lookahead(text, j, n), i)
            elif word == "require":
                add(_js_require_lookahead(text, j, n), i)
            last_sig = word[-1] if word else c
            i = j
            continue
        last_sig = c
        i += 1
    return edges, state["capped"]


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

    def imports(
        self,
        path: Path,
        *,
        kind: str = "",
        contains: str = "",
        offset: int = 0,
        limit: int = 200,
    ) -> JsonObject:
        """Extract a JS/ES module's dependency edges, no webcrack needed.

        Reads the source directly (so it works with no external tool) and
        answers the module-graph question of web-app triage -- which modules,
        packages and URLs a file pulls in. The JS analogue of r2.imports /
        wasm.summary imports: a single pass (skipping comments, regex and
        string/template literals so a keyword inside one is never read as code)
        finds every static ``import`` (side-effect, default, ``* as ns`` and
        named), ``export ... from`` re-export, dynamic ``import("mod")`` and
        CommonJS ``require("mod")``. Only edges with a literal specifier are
        recorded; a computed ``import(expr)`` / ``require(expr)`` is skipped.

        Each edge carries specifier, kind (import, export_from,
        dynamic_import or require), line, and -- for static imports and named
        re-exports -- default, namespace and names when present. kind filters
        the listing to one mechanism and contains is a case-insensitive
        substring over the specifier.

        Answers with imports (the edge list, paged), count, total, offset and
        has_more over the filtered set, specifiers (the sorted unique module
        list for the whole file, capped at 2000), distinct (its true size),
        kind_counts (the import/export_from/dynamic_import/require breakdown for
        the whole file) and scan_capped (set once the 100000-edge ceiling
        stopped the scan). The list field is imports, not results.
        """
        if kind and kind not in _JS_IMPORT_KINDS:
            raise JsReError(
                "invalid_params",
                "kind must be import, export_from, dynamic_import, require or empty",
                kind=kind,
            )
        if not isinstance(contains, str):
            contains = ""
        if len(contains) > _MAX_JS_STRINGS_CONTAINS:
            raise JsReError(
                "invalid_params",
                f"contains must be at most {_MAX_JS_STRINGS_CONTAINS} chars",
            )
        resolved = _require_existing_file(path, missing="input file not found")
        try:
            raw_bytes = resolved.read_bytes()
        except OSError as exc:
            raise JsReError(
                "backend_error", f"input unreadable: {exc}", path=str(resolved)
            ) from exc
        text = raw_bytes.decode("utf-8", errors="replace")
        edges, scan_capped = _scan_js_imports(text, max_edges=_MAX_JS_IMPORTS_SCAN)
        kind_counts = {name: 0 for name in sorted(_JS_IMPORT_KINDS)}
        unique: dict[str, None] = {}
        for edge in edges:
            kind_counts[str(edge["kind"])] += 1
            unique.setdefault(str(edge["specifier"]), None)
        distinct = len(unique)
        specifiers = sorted(unique)[:_MAX_JS_SPECIFIERS_SUMMARY]
        needle = contains.lower()
        selected = [
            edge
            for edge in edges
            if (not kind or edge["kind"] == kind)
            and (not needle or needle in str(edge["specifier"]).lower())
        ]
        total = len(selected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_JS_IMPORTS_PAGE))
        window = selected[start : start + cap]
        result: JsonObject = {
            "path": str(resolved),
            "imports": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "specifiers": specifiers,
            "distinct": distinct,
            "kind_counts": kind_counts,
            "scan_capped": scan_capped,
        }
        if kind:
            result["kind"] = kind
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


def _render_wasm_sig(params: list[str], results: list[str]) -> str:
    """Render a function type as ``(i32, i32) -> i32`` (``-> ()`` for void)."""
    if not results:
        rendered = "()"
    elif len(results) == 1:
        rendered = results[0]
    else:
        rendered = "(" + ", ".join(results) + ")"
    return f"({', '.join(params)}) -> {rendered}"


def _read_wasm_functype_parts(
    data: bytes, pos: int, end: int
) -> tuple[list[str], list[str], int]:
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
    return params, results, pos


def _read_wasm_functype(data: bytes, pos: int, end: int) -> tuple[str, int]:
    params, results, pos = _read_wasm_functype_parts(data, pos, end)
    return _render_wasm_sig(params, results), pos


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


# wasm.functions materialisation + page caps. The function table is the
# module's navigation index (r2.functions / apk.methods for wasm), so it
# paginates rather than hard-truncates; the collect cap only bounds a crafted
# vec count from building an unbounded list.
_MAX_WASM_FUNCTIONS_COLLECT = 50_000
_MAX_WASM_FUNCTIONS_PAGE = 2000


def _parse_wasm_functions(data: bytes, *, module: str) -> JsonObject:
    """Build the module's whole function table straight from the bytes.

    wasm.summary lists only what a module imports and exports; this is the full
    inventory -- every function, imported and internal alike -- keyed by its
    index in the function index space, so an internal routine that is neither
    imported nor exported (reached only through a call op or a table) still
    shows up with its signature and code size. It is the WebAssembly analogue of
    r2.functions / apk.methods: the seam from "here is a module" to "here is
    function #142, named encrypt, (i32, i32) -> i32, 340 code bytes", the entry
    point for pointing wasm.wat / wasm.decompile at one routine.

    Reuses the name section (via the same parser wasm.names uses) for readable
    names and marks which functions the module exports. Type/Function/Code
    faults are recovered locally (the table still builds from what parsed);
    Import/Export faults are a clean backend_error, matching wasm.summary.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("backend_error", "not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    n = len(data)
    type_sigs: list[tuple[list[str], list[str]]] = []
    func_imports: list[JsonObject] = []
    defined_types: list[int] = []
    code_entries: list[JsonObject] = []
    export_funcs: dict[int, list[str]] = {}
    try:
        while pos < n:
            sec_id = data[pos]
            pos += 1
            sec_size, pos = _read_uleb128(data, pos)
            sec_end = pos + sec_size
            if sec_size < 0 or sec_end > n:
                raise _WasmParseError("section overruns module")
            if sec_id == 0:
                pos = sec_end
                continue
            count, body = _read_uleb128(data, pos)
            if sec_id == 1:  # Type: the module's signature table
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(type_sigs) >= _MAX_WASM_ITEMS:
                            break
                        params, results, p = _read_wasm_functype_parts(data, p, sec_end)
                        type_sigs.append((params, results))
            elif sec_id == 2:  # Import: func imports take the low func index space
                p = body
                for _ in range(count):
                    mod_name, p = _read_wasm_name(data, p, sec_end)
                    fld_name, p = _read_wasm_name(data, p, sec_end)
                    if p >= sec_end:
                        raise _WasmParseError("import entry truncated")
                    kind = data[p]
                    p += 1
                    if kind == 0:  # func: type index
                        type_index, p = _read_uleb128(data, p)
                        if len(func_imports) < _MAX_WASM_FUNCS:
                            func_imports.append(
                                {
                                    "import_module": mod_name,
                                    "import_field": fld_name,
                                    "type_index": type_index,
                                }
                            )
                    elif kind == 1:  # table
                        p = _skip_wasm_limits(data, p + 1)
                    elif kind == 2:  # memory
                        p = _skip_wasm_limits(data, p)
                    elif kind == 3:  # global
                        p += 2
                    else:
                        raise _WasmParseError(f"unknown import kind {kind}")
            elif sec_id == 3:  # Function: one type index per defined function
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(defined_types) >= _MAX_WASM_FUNCS:
                            break
                        type_index, p = _read_uleb128(data, p)
                        defined_types.append(type_index)
            elif sec_id == 7:  # Export
                p = body
                for _ in range(count):
                    exp_name, p = _read_wasm_name(data, p, sec_end)
                    if p >= sec_end:
                        raise _WasmParseError("export entry truncated")
                    kind = data[p]
                    p += 1
                    idx, p = _read_uleb128(data, p)
                    if kind == 0:  # func export
                        export_funcs.setdefault(idx, []).append(exp_name)
            elif sec_id == 10:  # Code: one body per defined function
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(code_entries) >= _MAX_WASM_FUNCS:
                            break
                        body_size, p = _read_uleb128(data, p)
                        body_end = p + body_size
                        if body_size < 0 or body_end > sec_end:
                            raise _WasmParseError("code body overruns section")
                        groups, q = _read_uleb128(data, p)
                        nlocals = 0
                        for _ in range(groups):
                            if q >= body_end:
                                raise _WasmParseError("local decl overruns body")
                            gcount, q = _read_uleb128(data, q)
                            q += 1  # the group's value-type byte
                            nlocals += gcount
                        code_entries.append({"size": body_size, "locals": nlocals})
                        p = body_end
            pos = sec_end
    except _WasmParseError as exc:
        raise JsReError("backend_error", f"malformed WebAssembly module: {exc}") from exc
    except IndexError as exc:  # a read ran off the end despite the guards
        raise JsReError(
            "backend_error", "malformed WebAssembly module: unexpected end of data"
        ) from exc

    # Readable names from the name section (reuse wasm.names' tested parser), so
    # an internal func[142] carries its compiler-emitted name where present.
    name_map: dict[int, str] = {}
    has_name_section = False
    with suppress(JsReError):
        names = _parse_wasm_names(data, module=module)
        has_name_section = bool(names.get("has_name_section"))
        for named in names.get("functions", []):
            if isinstance(named, dict) and isinstance(named.get("index"), int):
                text = str(named.get("name") or "")
                if text:
                    name_map[named["index"]] = text

    def _detail(type_index: int) -> tuple[str | None, list[str], list[str]]:
        if 0 <= type_index < len(type_sigs):
            params, results = type_sigs[type_index]
            return _render_wasm_sig(params, results), list(params), list(results)
        return None, [], []

    functions: list[JsonObject] = []
    scan_capped = False
    num_imports = len(func_imports)

    def _add(entry: JsonObject, index: int, type_index: int) -> bool:
        if len(functions) >= _MAX_WASM_FUNCTIONS_COLLECT:
            return False
        sig, params, results = _detail(type_index)
        exports_here = sorted(export_funcs.get(index, []))
        if sig is not None:
            entry["signature"] = sig
            entry["params"] = params
            entry["results"] = results
        entry["exported"] = bool(exports_here)
        if exports_here:
            entry["export_names"] = exports_here
        functions.append(entry)
        return True

    for i, imp in enumerate(func_imports):
        type_index = int(imp["type_index"])
        exports_here = export_funcs.get(i, [])
        name = name_map.get(i) or imp["import_field"] or (
            sorted(exports_here)[0] if exports_here else None
        )
        entry: JsonObject = {
            "index": i,
            "name": name or None,
            "kind": "import",
            "type_index": type_index,
            "import_module": imp["import_module"],
            "import_field": imp["import_field"],
        }
        if not _add(entry, i, type_index):
            scan_capped = True
            break
    else:
        for j, type_index in enumerate(defined_types):
            index = num_imports + j
            exports_here = export_funcs.get(index, [])
            name = name_map.get(index) or (
                sorted(exports_here)[0] if exports_here else None
            )
            local_entry: JsonObject = {
                "index": index,
                "name": name or None,
                "kind": "local",
                "type_index": int(type_index),
            }
            if j < len(code_entries):
                local_entry["size"] = code_entries[j]["size"]
                local_entry["locals"] = code_entries[j]["locals"]
            if not _add(local_entry, index, int(type_index)):
                scan_capped = True
                break

    return {
        "module": module,
        "version": version,
        "functions": functions,
        "import_function_count": num_imports,
        "defined_function_count": len(defined_types),
        "has_name_section": has_name_section,
        "scan_capped": scan_capped,
    }


# --- wasm.disasm_function: a bounded, honest single-function disassembler ----
#
# The listing is only ever as correct as its immediate-decoding table: skip one
# opcode's immediates wrong and every op after it is garbage. So the decoder
# knows the immediate *shape* of every opcode it emits and STOPS cleanly at the
# first opcode whose shape it does not know (disclosed via decoded_all /
# stopped_at), rather than guessing and desynchronising. That covers the MVP
# instruction set, sign-extension, the 0xFC prefix (saturating trunc + bulk
# memory / table) and reference types; SIMD (0xFD) and threads (0xFE) stop the
# walk for now (their ops carry it far enough to read the structure first).
_WOP_NONE = "none"          # no immediates (arithmetic, comparisons, drop, ...)
_WOP_U32 = "u32"            # one uleb index (call, local.get, br, ...)
_WOP_BLOCKTYPE = "blocktype"  # block / loop / if
_WOP_MEMARG = "memarg"      # align + offset (every load / store)
_WOP_I32 = "i32"            # i32.const (sleb32)
_WOP_I64 = "i64"            # i64.const (sleb64)
_WOP_F32 = "f32"            # f32.const (4 raw bytes)
_WOP_F64 = "f64"            # f64.const (8 raw bytes)
_WOP_CALL_INDIRECT = "call_indirect"  # type index + table index
_WOP_BR_TABLE = "br_table"  # vec of labels + default
_WOP_SELECT_T = "select_t"  # typed select: vec of valtypes
_WOP_REFTYPE = "reftype"    # ref.null: one heaptype byte
_WOP_RESERVED1 = "reserved1"  # memory.size / grow: one reserved uleb

# byte -> (mnemonic, shape) for every opcode with a non-NONE shape or a name we
# want to read; the whole numeric range 0x45..0xC4 is NONE and named below.
_WASM_OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("unreachable", _WOP_NONE),
    0x01: ("nop", _WOP_NONE),
    0x02: ("block", _WOP_BLOCKTYPE),
    0x03: ("loop", _WOP_BLOCKTYPE),
    0x04: ("if", _WOP_BLOCKTYPE),
    0x05: ("else", _WOP_NONE),
    0x0B: ("end", _WOP_NONE),
    0x0C: ("br", _WOP_U32),
    0x0D: ("br_if", _WOP_U32),
    0x0E: ("br_table", _WOP_BR_TABLE),
    0x0F: ("return", _WOP_NONE),
    0x10: ("call", _WOP_U32),
    0x11: ("call_indirect", _WOP_CALL_INDIRECT),
    0x1A: ("drop", _WOP_NONE),
    0x1B: ("select", _WOP_NONE),
    0x1C: ("select", _WOP_SELECT_T),
    0x20: ("local.get", _WOP_U32),
    0x21: ("local.set", _WOP_U32),
    0x22: ("local.tee", _WOP_U32),
    0x23: ("global.get", _WOP_U32),
    0x24: ("global.set", _WOP_U32),
    0x25: ("table.get", _WOP_U32),
    0x26: ("table.set", _WOP_U32),
    0x3F: ("memory.size", _WOP_RESERVED1),
    0x40: ("memory.grow", _WOP_RESERVED1),
    0x41: ("i32.const", _WOP_I32),
    0x42: ("i64.const", _WOP_I64),
    0x43: ("f32.const", _WOP_F32),
    0x44: ("f64.const", _WOP_F64),
    0xD0: ("ref.null", _WOP_REFTYPE),
    0xD1: ("ref.is_null", _WOP_NONE),
    0xD2: ("ref.func", _WOP_U32),
}
# Memory loads/stores 0x28..0x3E are all memarg; name them in order.
_WASM_MEMORY_OPS = [
    "i32.load", "i64.load", "f32.load", "f64.load",
    "i32.load8_s", "i32.load8_u", "i32.load16_s", "i32.load16_u",
    "i64.load8_s", "i64.load8_u", "i64.load16_s", "i64.load16_u",
    "i64.load32_s", "i64.load32_u",
    "i32.store", "i64.store", "f32.store", "f64.store",
    "i32.store8", "i32.store16", "i64.store8", "i64.store16", "i64.store32",
]
for _i, _nm in enumerate(_WASM_MEMORY_OPS):
    _WASM_OPCODES[0x28 + _i] = (_nm, _WOP_MEMARG)
# The numeric range 0x45..0xC4 has no immediates; name each for a readable dump.
_WASM_NUMERIC_OPS = [
    "i32.eqz", "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u",
    "i32.le_s", "i32.le_u", "i32.ge_s", "i32.ge_u",
    "i64.eqz", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u", "i64.gt_s", "i64.gt_u",
    "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u",
    "f32.eq", "f32.ne", "f32.lt", "f32.gt", "f32.le", "f32.ge",
    "f64.eq", "f64.ne", "f64.lt", "f64.gt", "f64.le", "f64.ge",
    "i32.clz", "i32.ctz", "i32.popcnt", "i32.add", "i32.sub", "i32.mul",
    "i32.div_s", "i32.div_u", "i32.rem_s", "i32.rem_u", "i32.and", "i32.or",
    "i32.xor", "i32.shl", "i32.shr_s", "i32.shr_u", "i32.rotl", "i32.rotr",
    "i64.clz", "i64.ctz", "i64.popcnt", "i64.add", "i64.sub", "i64.mul",
    "i64.div_s", "i64.div_u", "i64.rem_s", "i64.rem_u", "i64.and", "i64.or",
    "i64.xor", "i64.shl", "i64.shr_s", "i64.shr_u", "i64.rotl", "i64.rotr",
    "f32.abs", "f32.neg", "f32.ceil", "f32.floor", "f32.trunc", "f32.nearest",
    "f32.sqrt", "f32.add", "f32.sub", "f32.mul", "f32.div", "f32.min", "f32.max",
    "f32.copysign",
    "f64.abs", "f64.neg", "f64.ceil", "f64.floor", "f64.trunc", "f64.nearest",
    "f64.sqrt", "f64.add", "f64.sub", "f64.mul", "f64.div", "f64.min", "f64.max",
    "f64.copysign",
    "i32.wrap_i64", "i32.trunc_f32_s", "i32.trunc_f32_u", "i32.trunc_f64_s",
    "i32.trunc_f64_u", "i64.extend_i32_s", "i64.extend_i32_u", "i64.trunc_f32_s",
    "i64.trunc_f32_u", "i64.trunc_f64_s", "i64.trunc_f64_u", "f32.convert_i32_s",
    "f32.convert_i32_u", "f32.convert_i64_s", "f32.convert_i64_u", "f32.demote_f64",
    "f64.convert_i32_s", "f64.convert_i32_u", "f64.convert_i64_s",
    "f64.convert_i64_u", "f64.promote_f32", "i32.reinterpret_f32",
    "i64.reinterpret_f64", "f32.reinterpret_i32", "f64.reinterpret_i64",
    "i32.extend8_s", "i32.extend16_s", "i64.extend8_s", "i64.extend16_s",
    "i64.extend32_s",
]
for _i, _nm in enumerate(_WASM_NUMERIC_OPS):
    _WASM_OPCODES.setdefault(0x45 + _i, (_nm, _WOP_NONE))
# The 0xFC prefix family: sub-opcode -> (mnemonic, index-operand count).
_WASM_FC_OPS: dict[int, tuple[str, int]] = {
    0: ("i32.trunc_sat_f32_s", 0), 1: ("i32.trunc_sat_f32_u", 0),
    2: ("i32.trunc_sat_f64_s", 0), 3: ("i32.trunc_sat_f64_u", 0),
    4: ("i64.trunc_sat_f32_s", 0), 5: ("i64.trunc_sat_f32_u", 0),
    6: ("i64.trunc_sat_f64_s", 0), 7: ("i64.trunc_sat_f64_u", 0),
    8: ("memory.init", 2), 9: ("data.drop", 1), 10: ("memory.copy", 2),
    11: ("memory.fill", 1), 12: ("table.init", 2), 13: ("elem.drop", 1),
    14: ("table.copy", 2), 15: ("table.grow", 1), 16: ("table.size", 1),
    17: ("table.fill", 1),
}
_WASM_U32_KEY = {
    0x0C: "label", 0x0D: "label", 0x10: "function_index", 0xD2: "function_index",
    0x20: "local_index", 0x21: "local_index", 0x22: "local_index",
    0x23: "global_index", 0x24: "global_index",
    0x25: "table_index", 0x26: "table_index",
}
# Bounds so a crafted body cannot build an unbounded reply.
_MAX_WASM_OPS_COLLECT = 100_000
_MAX_WASM_OPS_PAGE = 5000
_MAX_WASM_BRTABLE = 4096


def _read_wasm_blocktype(data: bytes, pos: int, end: int) -> tuple[str, int]:
    if pos >= end:
        raise _WasmParseError("blocktype truncated")
    byte = data[pos]
    if byte == 0x40:
        return "void", pos + 1
    if byte in _WASM_VALTYPES:
        # A single valtype (i32..v128, funcref, externref). Type-index encodings
        # are non-negative slebs whose first byte is < 0x40, so they never
        # collide with these bytes (all >= 0x6F, i.e. negative as sleb).
        return _WASM_VALTYPES[byte], pos + 1
    val, pos = _read_sleb128(data, pos)
    return f"type[{val}]", pos


def _read_wasm_immediates(
    data: bytes, pos: int, end: int, shape: str, op_byte: int
) -> tuple[JsonObject | None, str, int]:
    """Consume one opcode's immediates, returning (structured, rendered, pos)."""
    if shape == _WOP_NONE:
        return None, "", pos
    if shape == _WOP_U32:
        value, pos = _read_uleb128(data, pos)
        key = _WASM_U32_KEY.get(op_byte, "index")
        return {key: value}, str(value), pos
    if shape == _WOP_RESERVED1:
        value, pos = _read_uleb128(data, pos)
        return {"memory": value}, str(value), pos
    if shape == _WOP_MEMARG:
        align, pos = _read_uleb128(data, pos)
        offset, pos = _read_uleb128(data, pos)
        return {"align": align, "offset": offset}, f"align={align} offset={offset}", pos
    if shape == _WOP_I32:
        value, pos = _read_sleb128(data, pos)
        return {"value": value}, str(value), pos
    if shape == _WOP_I64:
        value, pos = _read_sleb128(data, pos)
        return {"value": value}, str(value), pos
    if shape == _WOP_F32:
        if pos + 4 > end:
            raise _WasmParseError("f32 immediate truncated")
        value = struct.unpack("<f", data[pos : pos + 4])[0]
        return {"value": value}, repr(value), pos + 4
    if shape == _WOP_F64:
        if pos + 8 > end:
            raise _WasmParseError("f64 immediate truncated")
        value = struct.unpack("<d", data[pos : pos + 8])[0]
        return {"value": value}, repr(value), pos + 8
    if shape == _WOP_BLOCKTYPE:
        rendered, pos = _read_wasm_blocktype(data, pos, end)
        return {"blocktype": rendered}, rendered, pos
    if shape == _WOP_CALL_INDIRECT:
        type_index, pos = _read_uleb128(data, pos)
        table_index, pos = _read_uleb128(data, pos)
        imm = {"type_index": type_index, "table_index": table_index}
        return imm, f"type={type_index} table={table_index}", pos
    if shape == _WOP_REFTYPE:
        if pos >= end:
            raise _WasmParseError("reftype truncated")
        byte = data[pos]
        pos += 1
        rendered = _WASM_VALTYPES.get(byte, f"0x{byte:02x}")
        return {"reftype": rendered}, rendered, pos
    if shape == _WOP_SELECT_T:
        count, pos = _read_uleb128(data, pos)
        types: list[str] = []
        for _ in range(count):
            if pos >= end:
                raise _WasmParseError("select type vec overruns body")
            types.append(_WASM_VALTYPES.get(data[pos], f"0x{data[pos]:02x}"))
            pos += 1
        return {"types": types}, " ".join(types), pos
    if shape == _WOP_BR_TABLE:
        count, pos = _read_uleb128(data, pos)
        targets: list[int] = []
        for _ in range(count):
            label, pos = _read_uleb128(data, pos)
            if len(targets) < _MAX_WASM_BRTABLE:
                targets.append(label)
        default, pos = _read_uleb128(data, pos)
        imm2: JsonObject = {"targets": targets, "default": default}
        if count > _MAX_WASM_BRTABLE:
            imm2["targets_truncated"] = True
            imm2["targets_total"] = count
        return imm2, f"[{len(targets)} targets] default={default}", pos
    raise _WasmParseError(f"unhandled immediate shape {shape}")


def _decode_wasm_body(
    data: bytes, pos: int, end: int, *, max_ops: int
) -> tuple[list[JsonObject], bool, JsonObject]:
    """Decode a function body's instruction stream into a bounded op list.

    Returns (ops, decoded_all, meta). ``decoded_all`` is False when the walk hit
    an opcode whose immediate shape is unknown (SIMD/threads/reserved); meta then
    carries stopped_at_offset / stopped_opcode. meta.scan_capped is set when the
    op cap clipped the listing. Correctness is preserved either way: every op
    emitted was decoded with a known shape, and the walk never guesses.
    """
    ops: list[JsonObject] = []
    depth = 0
    decoded_all = True
    meta: JsonObject = {"scan_capped": False}
    while pos < end:
        if len(ops) >= max_ops:
            meta["scan_capped"] = True
            break
        op_off = pos
        byte = data[pos]
        pos += 1
        if byte == 0xFC:
            sub, after = _read_uleb128(data, pos)
            info = _WASM_FC_OPS.get(sub)
            if info is None:
                decoded_all = False
                meta["stopped_at_offset"] = op_off
                meta["stopped_opcode"] = f"0xfc {sub}"
                break
            name, nindex = info
            operands: list[int] = []
            p = after
            for _ in range(nindex):
                value, p = _read_uleb128(data, p)
                operands.append(value)
            pos = p
            entry: JsonObject = {
                "offset": op_off,
                "opcode": f"0xfc {sub}",
                "name": name,
                "depth": depth,
                "bytes": data[op_off:pos].hex(),
            }
            operand_text = " ".join(str(v) for v in operands)
            entry["text"] = f"{name} {operand_text}".strip()
            if operands:
                entry["immediates"] = {"operands": operands}
            ops.append(entry)
            continue
        if byte in (0xFD, 0xFE):
            decoded_all = False
            meta["stopped_at_offset"] = op_off
            meta["stopped_opcode"] = f"0x{byte:02x}"
            break
        looked = _WASM_OPCODES.get(byte)
        if looked is None:
            decoded_all = False
            meta["stopped_at_offset"] = op_off
            meta["stopped_opcode"] = f"0x{byte:02x}"
            break
        name, shape = looked
        try:
            imm, operand_text, pos = _read_wasm_immediates(data, pos, end, shape, byte)
        except _WasmParseError:
            decoded_all = False
            meta["stopped_at_offset"] = op_off
            meta["stopped_opcode"] = f"0x{byte:02x}"
            break
        this_depth = depth
        if byte == 0x0B:  # end: closes a block, or the function itself at depth 0
            if depth == 0:
                ops.append(
                    {
                        "offset": op_off,
                        "opcode": f"0x{byte:02x}",
                        "name": name,
                        "depth": 0,
                        "bytes": data[op_off:pos].hex(),
                        "text": name,
                    }
                )
                break
            this_depth = depth - 1
            depth -= 1
        entry = {
            "offset": op_off,
            "opcode": f"0x{byte:02x}",
            "name": name,
            "depth": this_depth,
            "bytes": data[op_off:pos].hex(),
        }
        entry["text"] = f"{name} {operand_text}".strip()
        if imm is not None:
            entry["immediates"] = imm
        ops.append(entry)
        if byte in (0x02, 0x03, 0x04):  # block / loop / if open a new depth
            depth += 1
    return ops, decoded_all, meta


def _disasm_wasm_function(data: bytes, *, module: str, index: int) -> JsonObject:
    """Locate one function by index and disassemble its body (imports have none).

    Walks the section table once to place the function in the combined index
    space (imports first, then defined), resolve its signature and readable
    name, and -- for a defined function -- find its code body, read its local
    declarations and decode its instruction stream. An imported function has no
    body, reported as has_code false rather than an error, the wasm parallel to
    r2.disasm_function answering an address outside any function with empty ops.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("backend_error", "not a WebAssembly module (bad magic)")
    if index < 0:
        raise JsReError("invalid_params", "function index must be non-negative")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    n = len(data)
    type_sigs: list[tuple[list[str], list[str]]] = []
    func_import_types: list[int] = []
    defined_types: list[int] = []
    code_ranges: list[tuple[int, int]] = []  # (body_off, body_end) per defined func
    try:
        while pos < n:
            sec_id = data[pos]
            pos += 1
            sec_size, pos = _read_uleb128(data, pos)
            sec_end = pos + sec_size
            if sec_size < 0 or sec_end > n:
                raise _WasmParseError("section overruns module")
            if sec_id == 0:
                pos = sec_end
                continue
            count, body = _read_uleb128(data, pos)
            if sec_id == 1:  # Type
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(type_sigs) >= _MAX_WASM_ITEMS:
                            break
                        params, results, p = _read_wasm_functype_parts(data, p, sec_end)
                        type_sigs.append((params, results))
            elif sec_id == 2:  # Import
                p = body
                for _ in range(count):
                    _mod, p = _read_wasm_name(data, p, sec_end)
                    _fld, p = _read_wasm_name(data, p, sec_end)
                    if p >= sec_end:
                        raise _WasmParseError("import entry truncated")
                    kind = data[p]
                    p += 1
                    if kind == 0:
                        type_index, p = _read_uleb128(data, p)
                        if len(func_import_types) < _MAX_WASM_FUNCS:
                            func_import_types.append(type_index)
                    elif kind == 1:
                        p = _skip_wasm_limits(data, p + 1)
                    elif kind == 2:
                        p = _skip_wasm_limits(data, p)
                    elif kind == 3:
                        p += 2
                    else:
                        raise _WasmParseError(f"unknown import kind {kind}")
            elif sec_id == 3:  # Function
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(defined_types) >= _MAX_WASM_FUNCS:
                            break
                        type_index, p = _read_uleb128(data, p)
                        defined_types.append(type_index)
            elif sec_id == 10:  # Code
                p = body
                with suppress(_WasmParseError):
                    for _ in range(count):
                        if len(code_ranges) >= _MAX_WASM_FUNCS:
                            break
                        body_size, p = _read_uleb128(data, p)
                        body_end = p + body_size
                        if body_size < 0 or body_end > sec_end:
                            raise _WasmParseError("code body overruns section")
                        code_ranges.append((p, body_end))
                        p = body_end
            pos = sec_end
    except _WasmParseError as exc:
        raise JsReError("backend_error", f"malformed WebAssembly module: {exc}") from exc
    except IndexError as exc:
        raise JsReError(
            "backend_error", "malformed WebAssembly module: unexpected end of data"
        ) from exc

    num_imports = len(func_import_types)
    total = num_imports + len(defined_types)
    if index >= total:
        raise JsReError(
            "invalid_params",
            f"function index {index} out of range (module has {total} functions)",
        )

    name_map: dict[int, str] = {}
    with suppress(JsReError):
        for named in _parse_wasm_names(data, module=module).get("functions", []):
            if isinstance(named, dict) and isinstance(named.get("index"), int):
                text = str(named.get("name") or "")
                if text:
                    name_map[named["index"]] = text

    if index < num_imports:
        type_index = func_import_types[index]
        func_kind = "import"
    else:
        type_index = defined_types[index - num_imports]
        func_kind = "local"
    result: JsonObject = {
        "module": module,
        "version": version,
        "index": index,
        "kind": func_kind,
        "name": name_map.get(index),
        "type_index": type_index,
        "has_code": func_kind == "local",
    }
    if 0 <= type_index < len(type_sigs):
        params, results = type_sigs[type_index]
        result["signature"] = _render_wasm_sig(params, results)
        result["params"] = list(params)
        result["results"] = list(results)
    if func_kind == "import":
        result["ops"] = []
        result["decoded_all"] = True
        return result

    defined_index = index - num_imports
    if defined_index >= len(code_ranges):
        raise JsReError(
            "backend_error", "function has no code body (malformed Code section)"
        )
    body_off, body_end = code_ranges[defined_index]
    pos = body_off
    local_types: list[str] = []
    local_count = 0
    try:
        groups, pos = _read_uleb128(data, pos)
        for _ in range(groups):
            if pos >= body_end:
                raise _WasmParseError("local decl overruns body")
            gcount, pos = _read_uleb128(data, pos)
            if pos >= body_end:
                raise _WasmParseError("local decl overruns body")
            valtype = _WASM_VALTYPES.get(data[pos], f"0x{data[pos]:02x}")
            pos += 1
            local_count += gcount
            if len(local_types) < _MAX_WASM_ITEMS:
                local_types.extend([valtype] * min(gcount, _MAX_WASM_ITEMS))
    except _WasmParseError as exc:
        raise JsReError("backend_error", f"malformed WebAssembly module: {exc}") from exc

    ops, decoded_all, meta = _decode_wasm_body(
        data, pos, body_end, max_ops=_MAX_WASM_OPS_COLLECT
    )
    result["body_size"] = body_end - body_off
    result["local_count"] = local_count
    result["local_types"] = local_types[:_MAX_WASM_ITEMS]
    result["ops"] = ops
    result["decoded_all"] = decoded_all
    if not decoded_all:
        result["stopped_at_offset"] = meta.get("stopped_at_offset")
        result["stopped_opcode"] = meta.get("stopped_opcode")
    if meta.get("scan_capped"):
        result["scan_capped"] = True
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

# wasm.data bounds: one read window is capped at the same 64 KiB ceiling r2.read
# uses (each byte is two hex chars, so this stays well inside the reply budget);
# the segment index is capped so a module with a pathological number of segments
# cannot flood the map.
_MAX_WASM_DATA_SEG_BYTES = 64 * 1024
_MAX_WASM_DATA_SEGMENTS = 4096


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


def _parse_wasm_data(data: bytes, *, module: str) -> JsonObject:
    """Walk the Data section into per-segment placement metadata and raw bytes.

    wasm.strings surfaces only the printable runs in these same segments; this
    keeps every segment's raw bytes, so an embedded key, certificate, protobuf
    or compressed blob -- content that is not printable and so is invisible to a
    strings pass -- is still recoverable. Each segment reports its mode (active,
    placed in linear memory, or passive) and, for an active segment, the memory
    offset its ``i32.const`` placement resolves to (None when that base is an
    imported ``global.get``). The raw ``blob`` bytes ride along for the caller to
    window; they are stripped before the public reply. Reads the bytes directly
    (no wabt); a malformed module faults cleanly rather than misreading bytes.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("backend_error", "not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    n = len(data)
    segments: list[JsonObject] = []
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
                mode: str
                if flags == 0:  # active, memory 0, offset const-expr
                    mode = "active"
                    base, p = _read_wasm_const_offset(data, p, sec_end)
                elif flags == 1:  # passive: no placement
                    mode = "passive"
                    base = None
                elif flags == 2:  # active with explicit memory index
                    mode = "active"
                    _, p = _read_uleb128(data, p)  # memidx
                    base, p = _read_wasm_const_offset(data, p, sec_end)
                else:
                    raise _WasmParseError(f"unknown data segment flags {flags}")
                seg_len, p = _read_uleb128(data, p)
                if seg_len < 0 or p + seg_len > sec_end:
                    raise _WasmParseError("data segment bytes overrun section")
                segments.append(
                    {
                        "index": len(segments),
                        "mode": mode,
                        "memory_offset": base,
                        "size": seg_len,
                        "blob": data[p : p + seg_len],
                    }
                )
                p += seg_len
            pos = sec_end
    except _WasmParseError as exc:
        raise JsReError("backend_error", f"malformed WebAssembly module: {exc}") from exc
    except IndexError as exc:  # a read ran off the end despite the guards
        raise JsReError(
            "backend_error", "malformed WebAssembly module: unexpected end of data"
        ) from exc
    return {"module": module, "version": version, "segments": segments}


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

    def functions(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Build the module's whole function table (r2.functions for wasm).

        Where wasm.summary lists only imports/exports, this is the full function
        inventory -- imported and internal alike -- keyed by index, each with a
        resolved signature and, for defined functions, its code size and local
        count. It is the navigation entry point: pick a function here, then
        point wasm.wat / wasm.decompile at it. Reads the bytes directly (no
        wabt); a malformed module faults cleanly and a missing file is
        not_found. Paginated by offset/limit.
        """
        _ = timeout
        resolved = _require_existing_file(path, missing="wasm file not found")
        parsed = _parse_wasm_functions(resolved.read_bytes(), module=resolved.name)
        collected: list[JsonObject] = parsed["functions"]
        total = len(collected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_WASM_FUNCTIONS_PAGE))
        window = collected[start : start + cap]
        parsed["functions"] = window
        parsed["count"] = len(window)
        parsed["total"] = total
        parsed["offset"] = start
        parsed["has_more"] = start + len(window) < total
        return parsed

    def disasm_function(
        self,
        path: Path,
        *,
        index: int,
        offset: int = 0,
        limit: int = 200,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Disassemble one function's body (the wasm twin of r2.disasm_function).

        Where wasm.wat / wasm.decompile render the whole module (spilling to an
        artifact for anything sizeable), this decodes a single function picked by
        its index from wasm.functions, so an agent can read one routine's
        instruction stream without materialising the module. Pure-Python: it
        knows the immediate shape of every opcode it emits and stops cleanly at
        the first it does not (SIMD/threads), disclosed via decoded_all, rather
        than desynchronising. An imported function has no body (has_code false).
        Paginated by offset/limit; needs no wabt.
        """
        _ = timeout
        resolved = _require_existing_file(path, missing="wasm file not found")
        parsed = _disasm_wasm_function(
            resolved.read_bytes(), module=resolved.name, index=index
        )
        collected: list[JsonObject] = parsed["ops"]
        total = len(collected)
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_WASM_OPS_PAGE))
        window = collected[start : start + cap]
        parsed["ops"] = window
        parsed["count"] = len(window)
        parsed["total"] = total
        parsed["offset"] = start
        parsed["has_more"] = start + len(window) < total
        return parsed

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

    def data(
        self,
        path: Path,
        *,
        segment: int = 0,
        offset: int = 0,
        limit: int = _MAX_WASM_DATA_SEG_BYTES,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Read the raw bytes of a Data-section segment (the wasm twin of r2.read).

        wasm.strings is the wasm twin of r2.strings: it surfaces only the
        printable runs in the data segments. This is the other half -- the raw
        reader -- so the bytes a strings pass cannot show (an embedded key,
        certificate, protobuf descriptor or compressed payload) are still
        recoverable. Every call returns segments, the full lightweight map of the
        module's data segments (each {index, mode, memory_offset, size}, no
        bytes) so the caller can see what exists and pick one, plus the raw bytes
        of the selected segment as a hex window. Reads the bytes directly (no
        wabt); a malformed module faults cleanly and a missing file is not_found.
        """
        _ = timeout
        resolved = _require_existing_file(path, missing="wasm file not found")
        parsed = _parse_wasm_data(resolved.read_bytes(), module=resolved.name)
        segs: list[JsonObject] = parsed["segments"]
        total_segments = len(segs)
        index = [
            {
                "index": s["index"],
                "mode": s["mode"],
                "memory_offset": s["memory_offset"],
                "size": s["size"],
            }
            for s in segs[:_MAX_WASM_DATA_SEGMENTS]
        ]
        result: JsonObject = {
            "module": parsed["module"],
            "version": parsed["version"],
            "segments": index,
            "data_segments": total_segments,
        }
        if total_segments > _MAX_WASM_DATA_SEGMENTS:
            # A module with more segments than the map cap has its index trimmed;
            # disclose it so "these are all the segments" is never a wrong read.
            result["segments_truncated"] = True
            result["segments_total"] = total_segments
            result["segments_limit"] = _MAX_WASM_DATA_SEGMENTS
        if total_segments == 0:
            # No Data section is a clean empty map, not an error (like r2.strings
            # on a binary with no strings); there is no segment to window.
            result["count"] = 0
            return result
        sel = int(segment)
        if sel < 0 or sel >= total_segments:
            raise JsReError(
                "invalid_params",
                f"segment {sel} out of range (module has {total_segments})",
                segment=sel,
                data_segments=total_segments,
            )
        chosen = segs[sel]
        blob: bytes = chosen["blob"]
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_WASM_DATA_SEG_BYTES))
        window = blob[start : start + cap]
        result["segment"] = sel
        result["mode"] = chosen["mode"]
        result["memory_offset"] = chosen["memory_offset"]
        result["size"] = chosen["size"]
        result["encoding"] = "hex"
        result["data"] = window.hex()
        result["byte_offset"] = start
        result["count"] = len(window)
        result["has_more"] = start + len(window) < chosen["size"]
        return result

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
