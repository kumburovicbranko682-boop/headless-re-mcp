"""Dependency-free extraction of string literals from JavaScript source.

js.deobfuscate / js.beautify / js.unpack_bundle all shell out to webcrack (and
so the whole js line is capability_unavailable when Node/webcrack is not
configured). This reads the source directly -- no webcrack, no subprocess, pure
Python -- and pulls out the one thing a triage pass wants first: the string
literals, where a bundle's URLs, api endpoints, error messages and embedded
keys live.

It is a small single-pass lexer rather than a regex sweep, because a regex that
just matches quotes would trip over quotes inside comments and regex literals
and swallow the rest of the file. The lexer tracks line/block comments, regex
literals (via the standard previous-significant-token heuristic), the three
string forms ('...', "...", and template `...`), and escape sequences -- and it
*decodes* \\x / \\u / \\0 escapes, which is exactly what unmasks a URL an
obfuscator hid as "\\x68\\x74\\x74\\x70". It is best-effort (the regex/division
heuristic is not a full parser), always advances, and never over-reads: an
unterminated literal ends at EOF with what was read, the collected count is
bounded, and each returned string is length-clipped.
"""

from __future__ import annotations

import re
from typing import Any

JsonObject = dict[str, Any]

# String literals collected before the scan stops. A minified bundle holds tens
# of thousands; bound what is materialised (scan_capped when hit) so a hostile
# or generated file cannot grow the answer without bound.
_MAX_STRINGS_COLLECT = 100000
# One literal's on-source length can be a whole embedded JSON/base64 blob; clip
# the returned text (size still reports the full length) so one string cannot
# bloat the page.
_MAX_STRING_TEXT = 8192
# A caller-supplied minimum length is clamped to this so a value of 0 does not
# turn every empty literal into a row.
_MIN_LEN_MAX = 1024

_DELIM_RE = re.compile(r"['\"`/]")

# Keywords after which a `/` begins a regex literal, not a division. The prev
# significant char is then an identifier char, so the word disambiguates.
_REGEX_KEYWORDS = frozenset(
    {
        "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
        "do", "else", "yield", "await", "case", "throw",
    }
)
# Punctuation after which a `/` begins a regex literal.
_REGEX_PUNCT = frozenset("=(,:[!&|?{;~^%*-+<>")

_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
    "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`", "/": "/",
}


def _prev_word(source: str, end: int) -> str:
    """The identifier ending at ``end`` (exclusive), for regex disambiguation."""
    start = end
    while start > 0:
        ch = source[start - 1]
        if ch.isalnum() or ch in "_$":
            start -= 1
        else:
            break
    return source[start:end]


def _regex_allowed(prev_sig: str, prev_word: str) -> bool:
    """Whether a `/` at this position starts a regex literal (vs. division).

    The standard heuristic: a regex can begin wherever an expression can, i.e.
    at the start of input, after an operator or an opening bracket, or after a
    keyword that expects an expression. After a value (identifier, number,
    closing bracket, or a string) a `/` is division.
    """
    if prev_sig == "":
        return True
    if prev_sig in _REGEX_PUNCT:
        return True
    if prev_sig.isalnum() or prev_sig in "_$":
        return prev_word in _REGEX_KEYWORDS
    return False


def _decode_escape(source: str, i: int, n: int) -> tuple[str, int]:
    """Decode one escape at ``source[i] == '\\'``; return (char, chars_consumed).

    ``\\xHH`` and ``\\uHHHH`` / ``\\u{...}`` are decoded to their character --
    the move that unmasks a hex/unicode-escaped URL -- and the common
    single-char escapes are mapped. A line-continuation (``\\`` then newline)
    contributes nothing. A malformed or unknown escape falls back to the literal
    following character, so decoding never raises or stalls.
    """
    if i + 1 >= n:
        return "", 1
    nxt = source[i + 1]
    if nxt == "x" and i + 3 < n:
        hexs = source[i + 2 : i + 4]
        if len(hexs) == 2 and all(c in "0123456789abcdefABCDEF" for c in hexs):
            return chr(int(hexs, 16)), 4
        return "x", 2
    if nxt == "u":
        if i + 2 < n and source[i + 2] == "{":
            close = source.find("}", i + 3)
            if 0 <= close <= i + 3 + 8:
                body = source[i + 3 : close]
                if body and all(c in "0123456789abcdefABCDEF" for c in body):
                    try:
                        return chr(int(body, 16)), (close - i) + 1
                    except (ValueError, OverflowError):
                        return "u", 2
            return "u", 2
        hexs = source[i + 2 : i + 6]
        if len(hexs) == 4 and all(c in "0123456789abcdefABCDEF" for c in hexs):
            return chr(int(hexs, 16)), 6
        return "u", 2
    if nxt == "\n":
        return "", 2
    if nxt == "\r":
        # A CRLF line continuation consumes both.
        return "", (3 if i + 2 < n and source[i + 2] == "\n" else 2)
    return _SIMPLE_ESCAPES.get(nxt, nxt), 2


def _read_quoted(source: str, start: int, quote: str, n: int) -> tuple[str, int]:
    """Read a '...'/"..." literal from its opening quote; return (text, end).

    ``text`` is the *decoded* content; ``end`` is the index just past the
    closing quote (or at the terminating newline / EOF for an unterminated
    literal -- both are handled as an end rather than an over-read).
    """
    i = start + 1
    parts: list[str] = []
    while i < n:
        ch = source[i]
        if ch == "\\":
            decoded, consumed = _decode_escape(source, i, n)
            parts.append(decoded)
            i += consumed
            continue
        if ch == quote:
            return "".join(parts), i + 1
        if ch == "\n" or ch == "\r":
            # A raw newline cannot appear in a '/" literal; treat as unterminated.
            return "".join(parts), i
        parts.append(ch)
        i += 1
    return "".join(parts), i


def _skip_string(source: str, start: int, quote: str, n: int) -> int:
    """Skip a '...'/"..." literal (used inside template interpolations)."""
    _, end = _read_quoted(source, start, quote, n)
    return end


def _skip_interpolation(source: str, i: int, n: int) -> int:
    """Skip a template ``${ ... }`` expression, returning the index past ``}``.

    Braces are balanced while respecting nested strings and templates, so a
    ``}`` inside a string within the expression does not end the skip early.
    """
    depth = 1
    while i < n and depth > 0:
        ch = source[i]
        if ch == "{":
            depth += 1
            i += 1
        elif ch == "}":
            depth -= 1
            i += 1
        elif ch in "'\"":
            i = _skip_string(source, i, ch, n)
        elif ch == "`":
            i = _skip_template(source, i, n, None)
        elif ch == "\\":
            i += 2
        else:
            i += 1
    return i


def _skip_template(source: str, start: int, n: int, emit: Any) -> int:
    """Read a template `...` literal from its opening backtick; return end index.

    Static text chunks (the spans outside ``${...}``) are decoded and, when
    ``emit`` is given, reported one chunk at a time with their own offsets, so a
    ``https://a/${x}/b`` template yields "https://a/" and "/b" rather than one
    misleading concatenation. ``${...}`` expressions are skipped (their own
    string literals are not separately extracted). When ``emit`` is None this is
    a pure skip (used to step over a template nested in an interpolation).
    """
    i = start + 1
    parts: list[str] = []
    chunk_start = i
    while i < n:
        ch = source[i]
        if ch == "\\":
            decoded, consumed = _decode_escape(source, i, n)
            parts.append(decoded)
            i += consumed
            continue
        if ch == "`":
            if emit is not None and not emit("".join(parts), chunk_start, "template"):
                return -1
            return i + 1
        if ch == "$" and i + 1 < n and source[i + 1] == "{":
            if emit is not None and not emit("".join(parts), chunk_start, "template"):
                return -1
            parts = []
            i = _skip_interpolation(source, i + 2, n)
            chunk_start = i
            continue
        parts.append(ch)
        i += 1
    if emit is not None:
        emit("".join(parts), chunk_start, "template")
    return i


def _skip_line_comment(source: str, i: int, n: int) -> int:
    nl = source.find("\n", i)
    return n if nl < 0 else nl + 1


def _skip_block_comment(source: str, i: int, n: int) -> int:
    close = source.find("*/", i + 2)
    return n if close < 0 else close + 2


def _skip_regex(source: str, start: int, n: int) -> int:
    """Skip a /.../ regex literal, honouring escapes and character classes."""
    i = start + 1
    in_class = False
    while i < n:
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "\n":
            return i  # unterminated regex; stop at the line end
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            return i + 1
        i += 1
    return i


def extract_strings(
    source: str, *, min_length: int = 3, name_filter: str = ""
) -> tuple[list[JsonObject], bool]:
    """Extract string literals from JavaScript source.

    Returns ``(strings, scan_capped)``. Each row is ``{offset (char index of the
    opening quote / chunk start), text (decoded), size (decoded length), kind
    (single|double|template)}`` plus text_truncated when a single literal
    exceeded the text clip. Literals shorter than ``min_length`` (after decode)
    are dropped -- the way ``strings`` drops noise -- and ``name_filter`` keeps
    only those whose text contains that substring (case-insensitive, since these
    are prose/URLs), so total becomes the match count. Collection stops at the
    ceiling (scan_capped True).
    """
    length = min_length if isinstance(min_length, int) and not isinstance(min_length, bool) else 3
    length = max(1, min(length, _MIN_LEN_MAX))
    needle = name_filter.lower() if isinstance(name_filter, str) else ""
    results: list[JsonObject] = []
    capped = False

    def emit(text: str, offset: int, kind: str) -> bool:
        nonlocal capped
        if len(text) < length:
            return True
        if needle and needle not in text.lower():
            return True
        if len(results) >= _MAX_STRINGS_COLLECT:
            capped = True
            return False
        if len(text) > _MAX_STRING_TEXT:
            results.append(
                {
                    "offset": offset,
                    "text": text[:_MAX_STRING_TEXT],
                    "size": len(text),
                    "kind": kind,
                    "text_truncated": True,
                }
            )
        else:
            results.append({"offset": offset, "text": text, "size": len(text), "kind": kind})
        return True

    n = len(source)
    i = 0
    prev_sig = ""
    prev_word = ""
    while i < n:
        match = _DELIM_RE.search(source, i)
        if match is None:
            break
        j = match.start()
        # Record the last significant char/word in the plain-code span [i, j).
        span = source[i:j]
        stripped = span.rstrip()
        if stripped:
            prev_sig = stripped[-1]
            prev_word = _prev_word(stripped, len(stripped))
        ch = source[j]
        if ch == "/":
            nxt = source[j + 1] if j + 1 < n else ""
            if nxt == "/":
                i = _skip_line_comment(source, j, n)
                continue
            if nxt == "*":
                i = _skip_block_comment(source, j, n)
                continue
            if _regex_allowed(prev_sig, prev_word):
                i = _skip_regex(source, j, n)
                prev_sig = "/"
                prev_word = ""
                continue
            # Division operator: an ordinary code char.
            prev_sig = "/"
            prev_word = ""
            i = j + 1
            continue
        if ch == "'" or ch == '"':
            text, end = _read_quoted(source, j, ch, n)
            kind = "single" if ch == "'" else "double"
            if not emit(text, j, kind):
                break
            # A string literal ends a value, so a following `/` is division.
            prev_sig = ch
            prev_word = ""
            i = end
            continue
        # Template literal.
        end = _skip_template(source, j, n, emit)
        if end < 0:  # cap hit inside the template
            break
        prev_sig = "`"
        prev_word = ""
        i = end
    return results, capped
