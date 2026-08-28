"""Shared, dependency-free network-endpoint detectors used across analysis lines.

"What backends does this artefact talk to" is the same top-of-funnel question
for a JS bundle (js.endpoints, over string literals) and an Android app
(apk.endpoints, over the DEX string pool). Both pull scheme'd URLs and
whole-string request paths with the *same* rules, so the URL/path patterns and
host parsing live here once rather than being copied per backend -- the sibling
of secret_scan.py.

This module owns only the per-text matching primitive -- the URL regex, the
request-path recogniser, and host/scheme parsing. Aggregation (dedup, occurrence
counting, the reference each finding carries -- a char offset for JS, the
containing DEX constant for APK -- the distinct-host summary, filtering, sorting,
paging and the collect cap) stays in each caller, because those differ per line.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

# A scheme'd URL inside a string. The character class stops at anything that
# cannot sit unencoded in a URL (whitespace, quotes, backtick, backslash, angle
# brackets, and the template/pipe/caret punctuation); the trailing punctuation a
# URL is often written next to is stripped afterwards by clean_url.
URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'`<>\\{}|^]+", re.IGNORECASE)
# A whole-string request path: starts with '/', an alnum second char (so '//'
# and '/?...' are not paths), then path/query characters.
PATH_RE = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9._~%/@:{}?=&*-]*$")
# Path segments that mark a single-segment string as a real endpoint (so '/api'
# counts but a bare '/x' does not); a path with two or more segments counts
# regardless.
API_SEGMENTS = frozenset(
    {
        "api", "v1", "v2", "v3", "v4", "graphql", "gql", "rest", "oauth", "auth",
        "token", "login", "logout", "signin", "signup", "session", "account",
        "admin", "upload", "download", "callback", "webhook", "rpc", "ws",
    }
)
URL_TRAILING = ".,;:!?)]}>\"'`"


def clean_url(url: str) -> str:
    """Trim the trailing punctuation a URL is commonly written next to."""
    end = len(url)
    while end > 0 and url[end - 1] in URL_TRAILING:
        end -= 1
    return url[:end]


def url_scheme(url: str) -> str:
    return url.split("://", 1)[0].lower()


def url_host(url: str) -> str:
    """The host of a scheme'd URL: authority minus userinfo and port, lowered."""
    after = url.split("://", 1)[1] if "://" in url else url
    authority = re.split(r"[/?#]", after, maxsplit=1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    return authority.split(":", 1)[0].lower()


def looks_like_path(text: str) -> bool:
    """Whether a whole string reads as an HTTP request path worth surfacing."""
    if not (2 <= len(text) <= 512) or not PATH_RE.match(text):
        return False
    segments = [s for s in text.split("/") if s]
    if not segments:
        return False
    if len(segments) >= 2:
        return True
    return segments[0].split("?", 1)[0].lower() in API_SEGMENTS


def iter_endpoint_matches(
    text: str, *, include_paths: bool = True
) -> Iterator[tuple[str, str, str, str]]:
    """Yield ``(value, kind, scheme, host)`` for every endpoint in ``text``.

    Scheme'd URLs (http/https/ws/wss/ftp) anywhere in the text are yielded first,
    each with its parsed scheme and host (a URL whose authority yields no host is
    skipped). Then, when include_paths is set and the *whole* stripped text reads
    as a request path ('/api/...', '/v1/users', any two-segment path), one path
    endpoint with empty scheme/host. Order (URLs then path) is stable so a caller
    aggregating with an occurrence cap sees a deterministic sequence.
    """
    for match in URL_RE.finditer(text):
        value = clean_url(match.group())
        if "://" not in value:
            continue
        host = url_host(value)
        if not host:
            continue
        yield value, "url", url_scheme(value), host
    if include_paths:
        trimmed = text.strip()
        if looks_like_path(trimmed):
            yield trimmed, "path", "", ""
