"""Pure-Python static analysis for JavaScript source (no webcrack/Node needed).

Where js.deobfuscate / js.beautify shell out to webcrack (and go
capability_unavailable when Node is absent), these read the file text
themselves, so they answer on any host. Seven reads:

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
- ``extract_js_secrets`` classifies string-literal values against a
  high-precision table of provider credentials (AWS/GCP/GitHub/Slack/Stripe
  keys, JWTs, private keys, ...), deduping and redacting each match.
- ``extract_js_blobs`` pulls embedded base64/hex payloads out of the literals,
  decodes them, and classifies what came out (script/json/url/text or a binary
  by magic), with the URLs/IPs inside and one gzip/zlib inflate -- the "what is
  hidden in that long string" view for packed/obfuscated code.
- ``extract_js_endpoints`` reads the network *call sites* (fetch, axios,
  XMLHttpRequest.open, jQuery $.get/$.ajax, sendBeacon, new WebSocket) and pulls
  each request's target and method, catching the relative API paths a bare-URL
  scan misses -- the "what does this script talk to" view.

extract_js_api_usage and extract_js_imports share ``_noise_spans``, which marks
the byte ranges that are comments, string literals or regex literals so a match
inside one is not counted as code; extract_js_strings and extract_js_secrets
share the ``_scan_string_literals`` tokenizer. All of it is bounded on every
axis so a hostile bundle cannot blow memory or time.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import re
import zlib
from bisect import bisect_right
from collections import Counter, OrderedDict
from typing import Any
from urllib.parse import urlsplit

from headless_re_mcp.backends.common.secrets import classify_secrets

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

# js.blobs caps: bound the candidate runs scanned, distinct blobs collected,
# sample lines per blob, the decode size, the preview and the page.
_MAX_BLOB_RUNS = 50_000
_MAX_BLOBS_COLLECT = 2000
_MAX_BLOB_SAMPLE_LINES = 5
_MAX_BLOBS_PAGE = 500
_MAX_BLOB_DECODE_BYTES = 2 * 1024 * 1024
_MAX_BLOB_PREVIEW = 240
_MAX_BLOB_INDICATORS = 20
# A decoded payload of mostly printable bytes is treated as text (script/json/
# url/text); below this it is opaque binary and only reported if it has a magic.
_BLOB_PRINTABLE_RATIO = 0.85
# A candidate encoded run: base64 (std or url alphabet) with optional padding, or
# a pure-hex run. Runs shorter than this decode to too little to be a payload.
_BLOB_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
_HEX_ONLY_RE = re.compile(r"[0-9a-fA-F]+")
_SCRIPT_HINT_RE = re.compile(
    r"(?:\bfunction\b|=>|\beval\b|\bvar\b|\bconst\b|\blet\b|document\s*\.|"
    r"window\s*\.|\brequire\s*\(|\bimport\b|\bnew\s+Function\b)"
)
# Leading-byte signatures for common embedded payload types.
_BLOB_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\x1f\x8b", "gzip"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"%PDF", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\xca\xfe\xba\xbe", "java_class"),
    (b"dex\n", "dex"),
    (b"\x25\x21PS", "postscript"),
)
# Sort priority: executable/compressed/archive payloads first, then structured
# text, then plain text and opaque binary last.
_BLOB_KIND_RANK = {
    "script": 0,
    "pe": 1,
    "elf": 1,
    "dex": 1,
    "java_class": 1,
    "gzip": 2,
    "zlib": 2,
    "zip": 2,
    "json": 3,
    "url": 3,
    "pdf": 4,
    "png": 5,
    "jpeg": 5,
    "gif": 5,
    "postscript": 5,
    "text": 6,
    "binary": 7,
}

# js.endpoints caps: bound the string literals recorded into the call skeleton,
# the distinct endpoints collected, each URL's length, the sample lines per
# endpoint, the host roll-up and the page.
_MAX_ENDPOINT_LITERALS = 100_000
_MAX_ENDPOINTS_COLLECT = 5000
_MAX_ENDPOINT_URL_LEN = 2000
_MAX_ENDPOINT_SAMPLE_LINES = 5
_MAX_ENDPOINTS_PAGE = 2000
_MAX_ENDPOINT_HOST_ROLLUP = 500
# How far past a fetch()/config call's URL to look for a method: option.
_ENDPOINT_OPTS_WINDOW = 500
_MAX_METHOD_TOKEN_LEN = 12
_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)
# A string literal in the call skeleton is stored out-of-band and referenced by
# a NUL-bracketed index, so a URL that itself contains "fetch(" cannot be read
# as a call site. This matches one such placeholder.
_PH = r"\x00(\d+)\x00"
_M_FETCH = re.compile(r"\bfetch\s*\(\s*" + _PH)
_M_AXIOS_METHOD = re.compile(
    r"\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*" + _PH
)
_M_AXIOS_URL = re.compile(r"\baxios\s*\(\s*" + _PH)
_M_XHR_OPEN = re.compile(r"\.\s*open\s*\(\s*" + _PH + r"\s*,\s*" + _PH)
_M_JQUERY = re.compile(r"(?:\$|jQuery)\s*\.\s*(get|post|getJSON)\s*\(\s*" + _PH)
_M_BEACON = re.compile(r"\.\s*sendBeacon\s*\(\s*" + _PH)
_M_WS_CTOR = re.compile(r"\bnew\s+(WebSocket|EventSource)\s*\(\s*" + _PH)
_M_CONFIG_URL = re.compile(
    r"(?<![\w$])(?:axios(?:\s*\.\s*request)?|(?:\$|jQuery)\s*\.\s*ajax)\s*\(\s*\{"
    r"[^{}]{0,400}?\burl\s*:\s*" + _PH
)
_M_CONFIG_METHOD = re.compile(r"\b(?:method|type)\s*:\s*" + _PH)
_M_FETCH_METHOD = re.compile(r"\bmethod\s*:\s*" + _PH)
_ENDPOINT_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

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

# Shortest literal worth classifying for secrets: every credential pattern in
# backends.common.secrets is longer than this, so shorter literals can be skipped.
_MIN_SECRET_LITERAL_LEN = 8

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


def _scan_string_literals(
    text: str, *, min_length: int
) -> tuple[list[JsonObject], bool]:
    """Tokenize the source and return (literals, scan_capped).

    The comment/regex-aware scan shared by extract_js_strings (which pages the
    result) and extract_js_secrets (which classifies each value).
    """
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
    return literals, scan_capped


def extract_js_strings(
    text: str, *, min_length: int = 4, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Tokenize the source and return its string-literal inventory (paged)."""
    literals, scan_capped = _scan_string_literals(text, min_length=min_length)
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


def extract_js_secrets(
    text: str, *, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Classify string literals against known credential patterns (pure Python).

    Scans the decoded value of every string literal (not raw code, so a name in
    a comment does not count) against the shared credential table, deduping
    identical secrets and redacting them in the output. The classification is
    the shared ``classify_secrets``; this only supplies the JS-tokenized values.
    """
    literals, scan_capped = _scan_string_literals(
        text, min_length=_MIN_SECRET_LITERAL_LEN
    )
    items = ((str(lit["value"]), int(lit["line"])) for lit in literals)
    return classify_secrets(
        items, offset=offset, limit=limit, scan_capped=scan_capped
    )


def _decode_blob_run(run: str) -> tuple[str, bytes] | None:
    """Decode one candidate run to (encoding, bytes), or None if it is not one.

    A pure-hex even-length run is hex; otherwise the run is base64 (standard, or
    the url-safe alphabet when it carries - or _ but no + or /). Anything that
    fails to decode -- bad padding, wrong length -- is simply not a blob.
    """
    core = run.rstrip("=")
    if _HEX_ONLY_RE.fullmatch(core) and len(core) % 2 == 0:
        try:
            return "hex", bytes.fromhex(core)
        except ValueError:
            return None
    url_safe = ("-" in core or "_" in core) and "+" not in core and "/" not in core
    std = core.translate(str.maketrans("-_", "+/")) if url_safe else core
    padded = std + "=" * (-len(std) % 4)
    try:
        data = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) < 8:
        return None
    return ("base64url" if url_safe else "base64"), data


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def _blob_text_indicators(text: str) -> JsonObject:
    """URLs and bare IPv4 literals found inside a decoded payload, bounded."""
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING)[:_MAX_URL_VALUE_LEN]
        if url and url not in urls:
            urls.append(url)
        if len(urls) >= _MAX_BLOB_INDICATORS:
            break
    ips: list[str] = []
    for match in _IPV4_RE.finditer(text):
        ip = match.group(0)
        if ip not in ips:
            ips.append(ip)
        if len(ips) >= _MAX_BLOB_INDICATORS:
            break
    out: JsonObject = {}
    if urls:
        out["urls"] = urls
    if ips:
        out["ips"] = ips
    return out


def _classify_payload(data: bytes) -> tuple[str, str | None, JsonObject]:
    """Classify decoded bytes into (kind, text_preview_or_None, indicators).

    Magic-byte types (pe/elf/gzip/zip/...) win first. Otherwise a mostly-printable
    payload is text, refined to script/json/url; a low-printable payload with no
    magic is opaque binary.
    """
    for magic, kind in _BLOB_MAGICS:
        if data.startswith(magic):
            return kind, None, {}
    # zlib has no fixed magic: first byte 0x78 (common) and the two-byte header a
    # multiple of 31 is the standard check.
    if len(data) >= 2 and data[0] == 0x78 and (data[0] * 256 + data[1]) % 31 == 0:
        return "zlib", None, {}
    if _printable_ratio(data) >= _BLOB_PRINTABLE_RATIO:
        text = data.decode("utf-8", errors="replace")
        stripped = text.lstrip()
        kind = "text"
        if _SCRIPT_HINT_RE.search(text):
            kind = "script"
        elif stripped[:1] in "{[":
            try:
                json.loads(text)
                kind = "json"
            except (ValueError, RecursionError):
                kind = "text"
        elif stripped[:4].lower() == "http" and _URL_RE.match(stripped):
            kind = "url"
        return kind, text[:_MAX_BLOB_PREVIEW], _blob_text_indicators(text)
    return "binary", None, {}


def _decompress_blob(kind: str, data: bytes) -> bytes | None:
    """Best-effort one-level gzip/zlib inflate, bounded, or None on failure."""
    try:
        if kind == "gzip":
            return gzip.decompress(data)[:_MAX_BLOB_DECODE_BYTES]
        if kind == "zlib":
            return zlib.decompress(data)[:_MAX_BLOB_DECODE_BYTES]
    except (OSError, zlib.error, EOFError):
        return None
    return None


def _hex_preview(data: bytes) -> str:
    return data[: _MAX_BLOB_PREVIEW // 2].hex()


def _build_blob_finding(encoding: str, run: str, data: bytes) -> JsonObject:
    kind, preview, indicators = _classify_payload(data)
    finding: JsonObject = {
        "encoding": encoding,
        "kind": kind,
        "encoded_length": len(run),
        "decoded_length": len(data),
        "count": 0,
        "lines": [],
    }
    if preview is not None:
        finding["preview"] = preview
        if len(preview) < len(data):
            finding["preview_truncated"] = True
    else:
        finding["preview"] = _hex_preview(data)
        finding["preview_is_hex"] = True
    if indicators:
        finding["indicators"] = indicators
    if kind in ("gzip", "zlib"):
        inner = _decompress_blob(kind, data)
        if inner is not None:
            inner_kind, inner_preview, inner_ind = _classify_payload(inner)
            nested: JsonObject = {
                "kind": inner_kind,
                "decoded_length": len(inner),
            }
            if inner_preview is not None:
                nested["preview"] = inner_preview
            else:
                nested["preview"] = _hex_preview(inner)
                nested["preview_is_hex"] = True
            if inner_ind:
                nested["indicators"] = inner_ind
            finding["nested"] = nested
    return finding


def extract_js_blobs(
    text: str, *, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Extract, decode and classify embedded base64/hex payloads (pure Python).

    Obfuscated scripts hide their real payload in a long encoded string that a
    ``atob``/``fromCharCode`` chain unpacks at runtime; this pulls those strings
    out of the literal inventory, decodes them, and tells you what came out --
    another script, JSON, a URL, or a binary (PE/ELF/gzip/zip/...) by magic --
    plus any URLs/IPs inside the decoded text and one level of gzip/zlib inflate.
    Opaque binary with no recognizable magic is not reported (it is the noise of
    minified bundles) but is counted in opaque_skipped.
    """
    literals, scan_capped = _scan_string_literals(text, min_length=32)
    found: OrderedDict[str, JsonObject] = OrderedDict()
    kinds: Counter[str] = Counter()
    runs_scanned = 0
    opaque_skipped = 0
    for lit in literals:
        value = str(lit["value"])
        line = int(lit["line"])
        for match in _BLOB_RUN_RE.finditer(value):
            runs_scanned += 1
            if runs_scanned > _MAX_BLOB_RUNS:
                scan_capped = True
                break
            run = match.group(0)
            decoded = _decode_blob_run(run)
            if decoded is None:
                continue
            encoding, data = decoded
            existing = found.get(run)
            if existing is not None:
                existing["count"] = int(existing["count"]) + 1
                lines_list: list[int] = existing["lines"]
                if line not in lines_list and len(lines_list) < _MAX_BLOB_SAMPLE_LINES:
                    lines_list.append(line)
                continue
            kind_probe, _, _ = _classify_payload(data)
            if kind_probe == "binary":
                opaque_skipped += 1
                continue
            if len(found) >= _MAX_BLOBS_COLLECT:
                scan_capped = True
                continue
            finding = _build_blob_finding(encoding, run, data)
            finding["count"] = 1
            finding["lines"] = [line]
            found[run] = finding
            kinds[str(finding["kind"])] += 1
        if scan_capped:
            break

    rows = sorted(
        found.values(),
        key=lambda f: (
            _BLOB_KIND_RANK.get(str(f["kind"]), 8),
            -int(f["decoded_length"]),
            int(f["lines"][0]) if f["lines"] else 0,
        ),
    )
    start, cap = _clamp_page(offset, limit, max_limit=_MAX_BLOBS_PAGE)
    window = rows[start : start + cap]
    return {
        "blobs": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "kinds": dict(kinds),
        "opaque_skipped": opaque_skipped,
        "scan_capped": scan_capped,
    }


def _normalize_template(value: str) -> tuple[str, bool]:
    """Collapse a template literal's ``${...}`` interpolations to a marker.

    Returns (normalized, has_expression). ``/api/${id}/x`` becomes
    ``/api/${...}/x`` with has_expression True, so a caller sees the fixed
    shape of a computed URL without the interpolation body.
    """
    out: list[str] = []
    has_expr = False
    i = 0
    n = len(value)
    while i < n:
        if value[i] == "$" and i + 1 < n and value[i + 1] == "{":
            has_expr = True
            depth = 1
            i += 2
            while i < n and depth > 0:
                if value[i] == "{":
                    depth += 1
                elif value[i] == "}":
                    depth -= 1
                i += 1
            out.append("${...}")
            continue
        out.append(value[i])
        i += 1
    return "".join(out), has_expr


def _endpoint_literal_value(raw: str, quote: str) -> tuple[str, bool, bool]:
    """Decode one call-argument literal. Returns (value, is_template, has_expr)."""
    if quote == "`":
        normalized, has_expr = _normalize_template(raw)
        return _decode_js_escapes(normalized), True, has_expr
    return _decode_js_escapes(raw), False, False


def _endpoint_skeleton(text: str) -> tuple[str, list[JsonObject], bool]:
    """Rewrite source into a call skeleton with literals held out of band.

    Comments and regex literals become a space; every string/template literal
    becomes a NUL-bracketed index into the returned literals table (each row
    holding the decoded value, whether it was a template, whether it carried a
    ``${...}`` and its line). Code is copied verbatim so a regex can find a
    call site and read the placeholder that follows. Bounded: past the literal
    cap, further literals become a bare space and capped is set.
    """
    out: list[str] = []
    literals: list[JsonObject] = []
    n = len(text)
    i = 0
    line = 1
    prev_char: str | None = None
    prev_index = -1
    capped = False
    while i < n:
        c = text[i]
        if c == "\n":
            out.append("\n")
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v":
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                out.append(" ")
                continue
            if nxt == "*":
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    if text[i] == "\n":
                        line += 1
                    i += 1
                i += 2
                out.append(" ")
                continue
            word = _prev_word(text, prev_index + 1) if prev_index >= 0 else ""
            if _slash_starts_regex(prev_char, word):
                end = _scan_regex(text, i)
                if end is not None:
                    prev_char = "0"
                    prev_index = end - 1
                    out.append(" ")
                    i = end
                    continue
        if c in "'\"`":
            start_line = line
            value, line, i, _terminated = _consume_string(text, i, c, line)
            prev_char = "0"
            prev_index = i - 1
            if len(literals) < _MAX_ENDPOINT_LITERALS:
                decoded, is_template, has_expr = _endpoint_literal_value(value, c)
                out.append("\x00" + str(len(literals)) + "\x00")
                literals.append(
                    {
                        "value": decoded,
                        "is_template": is_template,
                        "has_expression": has_expr,
                        "line": start_line,
                    }
                )
            else:
                capped = True
                out.append(" ")
            continue
        prev_char = c
        prev_index = i
        # A raw NUL in source would collide with the placeholder sentinel.
        out.append(" " if c == "\x00" else c)
        i += 1
    return "".join(out), literals, capped


def _norm_method(literals: list[JsonObject], group: str | None) -> str | None:
    """Resolve a captured method literal index to an uppercase HTTP verb."""
    if group is None:
        return None
    lit = literals[int(group)]
    value = str(lit["value"]).strip()
    if not value or len(value) > _MAX_METHOD_TOKEN_LEN or not value.isalpha():
        return None
    upper = value.upper()
    return upper if upper in _HTTP_METHODS else None


def _endpoint_from(
    literals: list[JsonObject], url_group: str, *, kind: str, method: str | None
) -> JsonObject:
    lit = literals[int(url_group)]
    value = str(lit["value"])
    truncated = len(value) > _MAX_ENDPOINT_URL_LEN
    if truncated:
        value = value[:_MAX_ENDPOINT_URL_LEN]
    absolute = bool(_ENDPOINT_SCHEME_RE.match(value))
    host: str | None = None
    if absolute:
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
    row: JsonObject = {
        "url": value,
        "method": method,
        "kind": kind,
        "dynamic": bool(lit["has_expression"]),
        "absolute": absolute,
        "host": host,
        "line": int(lit["line"]),
    }
    if truncated:
        row["url_truncated"] = True
    return row


def _fetch_option_method(skeleton: str, literals: list[JsonObject], at: int) -> str | None:
    """Look just past a fetch()/config URL for a ``method:`` string option."""
    window = skeleton[at : at + _ENDPOINT_OPTS_WINDOW]
    found = _M_FETCH_METHOD.search(window)
    if found is None:
        return None
    return _norm_method(literals, found.group(1))


def _config_method(skeleton: str, literals: list[JsonObject], start: int) -> str | None:
    """Find a method:/type: option inside an axios/ajax config object."""
    window = skeleton[start : start + _ENDPOINT_OPTS_WINDOW]
    found = _M_CONFIG_METHOD.search(window)
    if found is None:
        return None
    return _norm_method(literals, found.group(1))


def extract_js_endpoints(
    text: str, *, offset: int = 0, limit: int = 200
) -> JsonObject:
    """Map the HTTP/WS request targets a script calls, by call site.

    Where extract_js_indicators lifts absolute URLs out of any literal, this
    reads the network *call sites* -- fetch(), axios.get/post/..., an
    XMLHttpRequest .open(method, url), jQuery $.get/$.post/$.ajax({url}),
    navigator.sendBeacon() and new WebSocket()/EventSource() -- and pulls the
    request target from each, which is usually the relative API path
    (``/api/v1/...``) that a bare-URL scan misses. The method comes from the
    call (axios.post, $.post), the XHR verb argument, or a method:/type: option.
    """
    skeleton, literals, scan_capped = _endpoint_skeleton(text)
    found: OrderedDict[tuple[str | None, str, str], JsonObject] = OrderedDict()
    endpoints_capped = False

    def _record(row: JsonObject) -> None:
        nonlocal endpoints_capped
        key = (row["method"], row["url"], row["kind"])
        existing = found.get(key)
        if existing is not None:
            existing["count"] = int(existing["count"]) + 1
            lines: list[int] = existing["lines"]
            if row["line"] not in lines and len(lines) < _MAX_ENDPOINT_SAMPLE_LINES:
                lines.append(row["line"])
            return
        if len(found) >= _MAX_ENDPOINTS_COLLECT:
            endpoints_capped = True
            return
        line = row.pop("line")
        row["lines"] = [line]
        row["count"] = 1
        found[key] = row

    for match in _M_FETCH.finditer(skeleton):
        method = _fetch_option_method(skeleton, literals, match.end()) or "GET"
        _record(_endpoint_from(literals, match.group(1), kind="fetch", method=method))
    for match in _M_AXIOS_METHOD.finditer(skeleton):
        method = match.group(1).upper()
        _record(_endpoint_from(literals, match.group(2), kind="axios", method=method))
    for match in _M_AXIOS_URL.finditer(skeleton):
        _record(_endpoint_from(literals, match.group(1), kind="axios", method="GET"))
    for match in _M_XHR_OPEN.finditer(skeleton):
        verb = _norm_method(literals, match.group(1))
        if verb is None:
            # A .open(str, str) whose first arg is not an HTTP verb is some
            # other open() (IndexedDB, a dialog), not an XHR.
            continue
        _record(_endpoint_from(literals, match.group(2), kind="xhr", method=verb))
    for match in _M_JQUERY.finditer(skeleton):
        method = "POST" if match.group(1) == "post" else "GET"
        _record(_endpoint_from(literals, match.group(2), kind="jquery", method=method))
    for match in _M_BEACON.finditer(skeleton):
        _record(_endpoint_from(literals, match.group(1), kind="beacon", method="POST"))
    for match in _M_WS_CTOR.finditer(skeleton):
        kind = "websocket" if match.group(1) == "WebSocket" else "eventsource"
        _record(_endpoint_from(literals, match.group(2), kind=kind, method=None))
    for match in _M_CONFIG_URL.finditer(skeleton):
        method = _config_method(skeleton, literals, match.start()) or "GET"
        _record(_endpoint_from(literals, match.group(1), kind="axios", method=method))

    rows = sorted(found.values(), key=lambda r: (-int(r["count"]), str(r["url"])))
    kinds: Counter[str] = Counter(str(r["kind"]) for r in rows)
    methods: Counter[str] = Counter(
        str(r["method"]) for r in rows if r["method"] is not None
    )
    host_counts: Counter[str] = Counter(
        str(r["host"]) for r in rows if r.get("host")
    )
    hosts = [
        {"host": host, "count": count}
        for host, count in host_counts.most_common(_MAX_ENDPOINT_HOST_ROLLUP)
    ]
    start, cap = _clamp_page(offset, limit, max_limit=_MAX_ENDPOINTS_PAGE)
    window = rows[start : start + cap]
    return {
        "items": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "kinds": dict(kinds),
        "methods": dict(methods),
        "hosts": hosts,
        "host_count": len(host_counts),
        "scan_capped": scan_capped,
        "endpoints_capped": endpoints_capped,
    }
