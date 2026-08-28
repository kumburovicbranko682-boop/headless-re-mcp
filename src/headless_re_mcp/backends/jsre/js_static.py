"""Pure-Python static analysis for JavaScript source (no webcrack/Node needed).

Where js.deobfuscate / js.beautify shell out to webcrack (and go
capability_unavailable when Node is absent), these read the file text
themselves, so they answer on any host. Four reads:

- ``extract_js_strings`` walks the source with a small state machine that
  understands line/block comments, single/double/template string literals and
  -- so a quote inside ``/["']/`` is not mistaken for a string -- regular
  expression literals. It returns the decoded literal inventory.
- ``extract_js_indicators`` scans the raw text for absolute URLs and bare IPv4
  literals, deduped and rolled up per host, the network IOCs a triage wants
  first.
- ``extract_js_imports`` pulls the module graph: ESM import/export-from,
  CommonJS require(), dynamic import() and importScripts(), with each specifier
  classified relative/bare/url and bare packages rolled up.
- ``extract_js_api_usage`` scans a comment/string/regex-stripped code skeleton
  for sensitive API sinks (eval, DOM injection, network, storage, encoding,
  crypto, ...), grouped by threat category -- the "what can this script do"
  view, the JS counterpart to apk.api_usage.

The last two share ``_noise_spans``, which marks the byte ranges that are
comments, string literals or regex literals so a match inside one is not
counted as code. All of it is bounded on every axis so a hostile bundle cannot
blow memory or time.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections import Counter, OrderedDict
from typing import Any
from urllib.parse import urlsplit

JsonObject = dict[str, Any]

# String-literal collection caps: a minified bundle carries tens of thousands
# of literals; bound the collected set, each value's length and the page.
_MAX_JS_STRINGS_COLLECT = 50_000
_MAX_JS_STRING_LEN = 8192
_MAX_JS_STRINGS_PAGE = 2000

# URL/IP caps mirror the APK indicator extractor.
_MAX_URLS_COLLECT = 5000
_MAX_URL_VALUE_LEN = 2000
_MAX_HOST_ROLLUP = 500
_MAX_IP_ROLLUP = 500
_MAX_URLS_PAGE = 2000

# js.imports caps: a bundle can re-require the same module thousands of times;
# bound the distinct specifier set, sample lines per specifier, page and the
# package roll-up.
_MAX_IMPORTS_COLLECT = 5000
_MAX_IMPORT_SAMPLE_LINES = 5
_MAX_IMPORTS_PAGE = 2000
_MAX_PACKAGE_ROLLUP = 500

# js.api_usage caps: bound the total match scan, the sample lines per API and
# the rows kept per category.
_MAX_API_MATCHES = 50_000
_MAX_API_SAMPLE_LINES = 5
_MAX_API_ROWS = 50

_URL_TRAILING = ".,;:!?'\")]}>"
_URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>\\)\]}(]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?![\w.])"
)

# Module-graph patterns. Each captures the quoted specifier in group 2. Run on
# raw text (the specifier is a string literal) and validated against the noise
# map so an import written inside a string or comment is not counted.
_IMPORT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # import defaultOrBindings from 'x'  /  import 'x' (side-effect)
    ("esm_import", re.compile(r"\bimport\b[^;'\"]*?\bfrom\s*(['\"])([^'\"]+)\1")),
    ("esm_import", re.compile(r"\bimport\s*(['\"])([^'\"]+)\1")),
    # export ... from 'x'
    ("esm_export", re.compile(r"\bexport\b[^;'\"]*?\bfrom\s*(['\"])([^'\"]+)\1")),
    # import('x') dynamic
    ("dynamic_import", re.compile(r"\bimport\s*\(\s*(['\"])([^'\"]+)\1")),
    # require('x') CommonJS
    ("require", re.compile(r"\brequire\s*\(\s*(['\"])([^'\"]+)\1")),
    # importScripts('x') worker
    ("import_scripts", re.compile(r"\bimportScripts\s*\(\s*(['\"])([^'\"]+)\1")),
)

# Sensitive-API sinks, grouped by threat category. Matched against the code
# skeleton (strings/comments/regex blanked), so a name inside a string does not
# count. Order within a category is preserved for stable output.
_API_SINKS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("code_execution", "eval", re.compile(r"\beval\s*\(")),
    ("code_execution", "new Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("code_execution", "execScript", re.compile(r"\bexecScript\s*\(")),
    ("code_execution", "setTimeout", re.compile(r"\bsetTimeout\s*\(")),
    ("code_execution", "setInterval", re.compile(r"\bsetInterval\s*\(")),
    ("dom_injection", "innerHTML", re.compile(r"\.\s*innerHTML\b")),
    ("dom_injection", "outerHTML", re.compile(r"\.\s*outerHTML\b")),
    ("dom_injection", "document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")),
    ("dom_injection", "insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    ("network", "fetch", re.compile(r"\bfetch\s*\(")),
    ("network", "XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b")),
    ("network", "WebSocket", re.compile(r"\bnew\s+WebSocket\s*\(")),
    ("network", "sendBeacon", re.compile(r"\bsendBeacon\s*\(")),
    ("network", "EventSource", re.compile(r"\bEventSource\b")),
    ("storage", "localStorage", re.compile(r"\blocalStorage\b")),
    ("storage", "sessionStorage", re.compile(r"\bsessionStorage\b")),
    ("storage", "indexedDB", re.compile(r"\bindexedDB\b")),
    ("storage", "document.cookie", re.compile(r"\bdocument\s*\.\s*cookie\b")),
    ("encoding", "atob", re.compile(r"\batob\s*\(")),
    ("encoding", "btoa", re.compile(r"\bbtoa\s*\(")),
    ("encoding", "unescape", re.compile(r"\bunescape\s*\(")),
    ("encoding", "decodeURIComponent", re.compile(r"\bdecodeURIComponent\s*\(")),
    ("encoding", "String.fromCharCode", re.compile(r"\bfromCharCode\b")),
    ("encoding", "charCodeAt", re.compile(r"\bcharCodeAt\s*\(")),
    ("crypto", "crypto.subtle", re.compile(r"\bcrypto\s*\.\s*subtle\b")),
    ("crypto", "CryptoJS", re.compile(r"\bCryptoJS\b")),
    ("messaging", "postMessage", re.compile(r"\bpostMessage\s*\(")),
    ("node_exec", "child_process", re.compile(r"\bchild_process\b")),
    ("node_exec", "exec", re.compile(r"\.\s*exec(?:Sync)?\s*\(")),
    ("node_exec", "spawn", re.compile(r"\.\s*spawn(?:Sync)?\s*\(")),
)

# A ``/`` right after one of these keywords begins a regex, not a division.
_REGEX_PRECEDING_KEYWORDS = frozenset(
    {
        "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
        "do", "else", "yield", "await", "case", "throw",
    }
)

_SIMPLE_ESCAPES = {
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
    "\n": "",
    "\r": "",
}


def _clamp_page(offset: int, limit: int, *, max_limit: int) -> tuple[int, int]:
    start = max(0, int(offset))
    cap = max(1, min(int(limit), max_limit))
    return start, cap


def _decode_js_escapes(raw: str) -> str:
    """Turn the raw literal body into its string value, best-effort.

    Handles the standard single-char escapes plus ``\\xHH``, ``\\uHHHH`` and
    ``\\u{...}``. An unrecognised escape drops the backslash and keeps the
    following character, which is what a JS engine does for a non-escape.
    """
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = raw[i + 1]
        if e == "x" and i + 3 < n:
            try:
                out.append(chr(int(raw[i + 2 : i + 4], 16)))
                i += 4
                continue
            except ValueError:
                pass
        elif e == "u":
            if i + 2 < n and raw[i + 2] == "{":
                end = raw.find("}", i + 3)
                if end != -1:
                    try:
                        out.append(chr(int(raw[i + 3 : end], 16)))
                        i = end + 1
                        continue
                    except (ValueError, OverflowError):
                        pass
            elif i + 5 < n:
                try:
                    out.append(chr(int(raw[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
        if e in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[e])
        else:
            out.append(e)
        i += 2
    return "".join(out)


def _slash_starts_regex(prev_char: str | None, prev_word: str) -> bool:
    """Decide whether a ``/`` in code begins a regex literal or is division."""
    if prev_char is None:
        return True
    if prev_char in ")]":
        return False
    if prev_char.isalnum() or prev_char in "_$":
        # Ends an identifier or number: division, unless the word is a keyword
        # after which an expression (and thus a regex) is expected.
        return prev_word in _REGEX_PRECEDING_KEYWORDS
    # Any operator, opening bracket, comma, semicolon or block close: regex.
    return True


def _scan_regex(text: str, start: int) -> int | None:
    """Return the index past a regex literal beginning at ``text[start] == '/'``.

    Honours ``\\`` escapes and ``[...]`` character classes (where ``/`` is
    literal). Returns None when no unescaped closing ``/`` appears before a
    newline, i.e. the ``/`` was not a regex after all.
    """
    i = start + 1
    n = len(text)
    in_class = False
    while i < n:
        ch = text[i]
        if ch == "\n":
            return None
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "/":
            i += 1
            while i < n and (text[i].isalpha()):
                i += 1
            return i
        i += 1
    return None


def _prev_word(text: str, end: int) -> str:
    """The identifier ending at index ``end`` (exclusive), for keyword checks."""
    j = end
    while j > 0 and (text[j - 1].isalnum() or text[j - 1] in "_$"):
        j -= 1
    return text[j:end]


def extract_js_strings(
    text: str, *, min_length: int = 4, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Tokenize the source and return its string-literal inventory (paged)."""
    literals: list[JsonObject] = []
    n = len(text)
    i = 0
    line = 1
    prev_char: str | None = None
    prev_index = -1
    scan_capped = False
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v":
            i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    if text[i] == "\n":
                        line += 1
                    i += 1
                i += 2
                continue
            word = _prev_word(text, prev_index + 1) if prev_index >= 0 else ""
            if _slash_starts_regex(prev_char, word):
                end = _scan_regex(text, i)
                if end is not None:
                    prev_char = "0"  # a regex is a value: a following / divides
                    prev_index = end - 1
                    i = end
                    continue
        if c in "'\"`":
            start_line = line
            value, line, i, terminated = _consume_string(text, i, c, line)
            prev_char = "0"
            prev_index = i - 1
            if len(literals) >= _MAX_JS_STRINGS_COLLECT:
                scan_capped = True
                continue
            decoded = _decode_js_escapes(value)
            truncated = len(decoded) > _MAX_JS_STRING_LEN
            if truncated:
                decoded = decoded[:_MAX_JS_STRING_LEN]
            if len(decoded) >= min_length:
                row: JsonObject = {
                    "value": decoded,
                    "quote": {"'": "single", '"': "double", "`": "template"}[c],
                    "line": start_line,
                    "length": len(decoded),
                }
                if truncated:
                    row["truncated"] = True
                if not terminated:
                    row["unterminated"] = True
                literals.append(row)
            continue
        prev_char = c
        prev_index = i
        i += 1

    total = len(literals)
    start, cap = _clamp_page(offset, limit, max_limit=_MAX_JS_STRINGS_PAGE)
    window = literals[start : start + cap]
    return {
        "items": window,
        "count": len(window),
        "total": total,
        "offset": start,
        "has_more": start + len(window) < total,
        "min_length": int(min_length),
        "scan_capped": scan_capped,
    }


def _consume_string(
    text: str, start: int, quote: str, line: int
) -> tuple[str, int, int, bool]:
    """Read one string/template literal body starting at the opening quote.

    Returns (raw_body, line, index_past_close, terminated). A single/double
    literal that hits an unescaped newline is treated as unterminated and
    ends there, so one stray quote cannot swallow the rest of the file.
    """
    n = len(text)
    i = start + 1
    buf: list[str] = []
    if quote == "`":
        interp_depth = 0
        while i < n:
            ch = text[i]
            if ch == "\\" and i + 1 < n:
                buf.append(text[i : i + 2])
                if text[i + 1] == "\n":
                    line += 1
                i += 2
                continue
            if ch == "\n":
                line += 1
            if interp_depth == 0:
                if ch == "`":
                    return "".join(buf), line, i + 1, True
                if ch == "$" and i + 1 < n and text[i + 1] == "{":
                    interp_depth = 1
                    buf.append("${")
                    i += 2
                    continue
                buf.append(ch)
                i += 1
                continue
            # Inside ${...}: brace-count best-effort so a nested } does not end
            # the template early. Nested strings are not re-lexed here.
            if ch == "{":
                interp_depth += 1
            elif ch == "}":
                interp_depth -= 1
            buf.append(ch)
            i += 1
        return "".join(buf), line, i, False
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            buf.append(text[i : i + 2])
            if text[i + 1] == "\n":
                line += 1
            i += 2
            continue
        if ch == quote:
            return "".join(buf), line, i + 1, True
        if ch == "\n":
            return "".join(buf), line, i, False
        buf.append(ch)
        i += 1
    return "".join(buf), line, i, False


def extract_js_indicators(
    text: str, *, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Scan raw source for URLs and IPv4 literals, deduped and host-rolled-up."""
    urls: dict[str, JsonObject] = {}
    hosts: Counter[str] = Counter()
    ips: set[str] = set()
    scan_capped = False
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING)[:_MAX_URL_VALUE_LEN]
        if not url:
            continue
        if url not in urls:
            if len(urls) >= _MAX_URLS_COLLECT:
                scan_capped = True
                continue
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            urls[url] = {"url": url, "scheme": parts.scheme.lower(), "host": host}
            if host:
                hosts[host] += 1
    for match in _IPV4_RE.finditer(text):
        if len(ips) < _MAX_IP_ROLLUP:
            ips.add(match.group(0))
        else:
            scan_capped = True
            break
    url_list = sorted(urls.values(), key=lambda row: str(row["url"]))
    start, cap = _clamp_page(offset, limit, max_limit=_MAX_URLS_PAGE)
    window = url_list[start : start + cap]
    host_rollup = [
        {"host": host, "count": count}
        for host, count in hosts.most_common(_MAX_HOST_ROLLUP)
    ]
    ip_list = sorted(ips)
    return {
        "urls": window,
        "count": len(window),
        "total": len(url_list),
        "offset": start,
        "has_more": start + len(window) < len(url_list),
        "hosts": host_rollup,
        "host_count": len(host_rollup),
        "hosts_truncated": len(hosts) > len(host_rollup),
        "ips": ip_list,
        "ip_count": len(ip_list),
        "scan_capped": scan_capped,
    }


def _noise_spans(text: str) -> list[tuple[int, int]]:
    """Byte ranges that are comments, string literals or regex literals.

    Used to reject a keyword or API match that falls inside a string or comment
    -- the same comment/regex-aware scan as extract_js_strings, but recording
    spans instead of decoding values, and without materialising a full skeleton.
    """
    spans: list[tuple[int, int]] = []
    n = len(text)
    i = 0
    prev_char: str | None = None
    prev_index = -1
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                start = i
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                spans.append((start, i))
                continue
            if nxt == "*":
                start = i
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
                spans.append((start, i))
                continue
            word = _prev_word(text, prev_index + 1) if prev_index >= 0 else ""
            if _slash_starts_regex(prev_char, word):
                end = _scan_regex(text, i)
                if end is not None:
                    spans.append((i, end))
                    prev_char = "0"
                    prev_index = end - 1
                    i = end
                    continue
        if c in "'\"`":
            _, _, end, _ = _consume_string(text, i, c, 1)
            spans.append((i, end))
            prev_char = "0"
            prev_index = end - 1
            i = end
            continue
        if c not in " \t\r\n\f\v":
            prev_char = c
            prev_index = i
        i += 1
    return spans


def _in_noise(starts: list[int], spans: list[tuple[int, int]], index: int) -> bool:
    """Whether ``index`` lies inside one of the sorted, non-overlapping spans."""
    if not spans:
        return False
    pos = bisect_right(starts, index) - 1
    return pos >= 0 and spans[pos][0] <= index < spans[pos][1]


def _classify_specifier(spec: str) -> tuple[str, str | None]:
    """Return (category, package). category is relative/url/bare."""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", spec) or spec.startswith("//"):
        return "url", None
    if spec.startswith((".", "/")):
        return "relative", None
    body = spec.split("?", 1)[0]
    parts = [p for p in body.split("/") if p]
    if not parts:
        return "bare", None
    if body.startswith("@") and len(parts) >= 2:
        return "bare", f"{parts[0]}/{parts[1]}"
    return "bare", parts[0]


def extract_js_imports(
    text: str, *, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Extract the module graph: ESM/CJS/dynamic import and importScripts."""
    spans = _noise_spans(text)
    starts = [s for s, _ in spans]
    # key (specifier, kind) -> {specifier, kind, category, package, count, lines}
    found: OrderedDict[tuple[str, str], JsonObject] = OrderedDict()
    packages: Counter[str] = Counter()
    scan_capped = False
    seen_at: set[tuple[int, str]] = set()
    for kind, pattern in _IMPORT_PATTERNS:
        for match in pattern.finditer(text):
            if _in_noise(starts, spans, match.start()):
                continue
            spec = match.group(2)
            if not spec:
                continue
            # A from-style and side-effect pattern can both fire at the same
            # spot; dedupe by (specifier position, kind).
            anchor = (match.start(2), kind)
            if anchor in seen_at:
                continue
            seen_at.add(anchor)
            key = (spec, kind)
            line = text.count("\n", 0, match.start()) + 1
            row = found.get(key)
            if row is None:
                if len(found) >= _MAX_IMPORTS_COLLECT:
                    scan_capped = True
                    continue
                category, package = _classify_specifier(spec)
                row = {
                    "specifier": spec,
                    "kind": kind,
                    "category": category,
                    "package": package,
                    "count": 0,
                    "lines": [],
                }
                found[key] = row
                if package:
                    packages[package] += 1
            row["count"] = int(row["count"]) + 1
            lines_list: list[int] = row["lines"]
            if len(lines_list) < _MAX_IMPORT_SAMPLE_LINES:
                lines_list.append(line)

    rows = sorted(found.values(), key=lambda r: (str(r["specifier"]), str(r["kind"])))
    kinds: Counter[str] = Counter()
    for row in rows:
        kinds[str(row["kind"])] += int(row["count"])
    start, cap = _clamp_page(offset, limit, max_limit=_MAX_IMPORTS_PAGE)
    window = rows[start : start + cap]
    package_rollup = [
        {"package": name, "count": count}
        for name, count in packages.most_common(_MAX_PACKAGE_ROLLUP)
    ]
    return {
        "imports": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "kinds": dict(kinds),
        "packages": package_rollup,
        "package_count": len(package_rollup),
        "packages_truncated": len(packages) > len(package_rollup),
        "scan_capped": scan_capped,
    }


def extract_js_api_usage(text: str) -> JsonObject:
    """Scan the code skeleton for sensitive API sinks, grouped by category."""
    spans = _noise_spans(text)
    starts = [s for s, _ in spans]
    # category -> {hits, apis: {api -> {count, lines}}}
    cats: OrderedDict[str, dict[str, Any]] = OrderedDict()
    total_hits = 0
    matched = 0
    scan_capped = False
    for category, api, pattern in _API_SINKS:
        if scan_capped:
            break
        for match in pattern.finditer(text):
            if _in_noise(starts, spans, match.start()):
                continue
            matched += 1
            if matched > _MAX_API_MATCHES:
                scan_capped = True
                break
            total_hits += 1
            bucket = cats.setdefault(category, {"hits": 0, "apis": OrderedDict()})
            bucket["hits"] += 1
            apis: OrderedDict[str, dict[str, Any]] = bucket["apis"]
            row = apis.setdefault(api, {"count": 0, "lines": []})
            row["count"] += 1
            if len(row["lines"]) < _MAX_API_SAMPLE_LINES:
                row["lines"].append(text.count("\n", 0, match.start()) + 1)

    categories: list[JsonObject] = []
    for category, bucket in sorted(cats.items(), key=lambda kv: (-kv[1]["hits"], kv[0])):
        ranked = sorted(
            bucket["apis"].items(), key=lambda kv: (-kv[1]["count"], kv[0])
        )
        rows = [
            {"api": name, "count": info["count"], "lines": info["lines"]}
            for name, info in ranked[:_MAX_API_ROWS]
        ]
        categories.append(
            {
                "category": category,
                "hits": bucket["hits"],
                "apis": rows,
                "api_count": len(rows),
                "apis_truncated": len(ranked) > len(rows),
            }
        )
    return {
        "categories": categories,
        "category_count": len(categories),
        "total_hits": total_hits,
        "scan_capped": scan_capped,
    }
