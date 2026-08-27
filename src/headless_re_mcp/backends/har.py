"""HAR 1.2 document construction shared by the proxy and web capture lines.

Both backends recorded HTTP exchanges but exported a HAR that carried only
``request.method/url`` and ``response.status`` plus a bare ``content.mimeType``
-- missing almost every field the HAR 1.2 spec (and real consumers: Chrome
DevTools' *Import HAR*, ``haralyzer``, ``har-validator``, most HAR viewers)
require, so the artifact would not load. This assembles a spec-compliant log:
each entry always carries ``startedDateTime``, ``time``, a ``request`` and
``response`` with ``cookies``/``headers``/``queryString``/``content``, ``cache``
and ``timings``. Genuinely unknown sizes and timings are reported as ``-1``,
which the spec defines as "does not apply / not available", rather than being
silently dropped -- so a field an analyst reads as zero is really zero.

The proxy line has the whole mitmproxy flow object and fills the rich fields
(headers, query string, bodies, real timings); the web line only captured
method/url/status/mimeType, so its entries are structurally complete but sparse.
Both are now valid HAR.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from headless_re_mcp import __version__

JsonObject = dict[str, Any]

HAR_VERSION = "1.2"
# HAR headers/bodies are metadata for inspection, not a mirror of the capture:
# a body preview is enough (the full body is retrievable via flow.get /
# network.get), and these caps keep one pathological exchange from bloating the
# whole log.
_MAX_HEADERS = 300
_MAX_HEADER_VALUE = 8 * 1024
_MAX_BODY_TEXT = 64 * 1024


def creator() -> JsonObject:
    return {"name": "headless-re-mcp", "version": str(__version__)}


def document(entries: list[JsonObject]) -> JsonObject:
    """Wrap finished entries in the required ``{"log": {...}}`` envelope."""
    return {"log": {"version": HAR_VERSION, "creator": creator(), "entries": entries}}


def iso8601(ts: float | None) -> str:
    """Epoch seconds -> ISO 8601 with timezone; epoch (1970) stands for unknown.

    HAR requires startedDateTime on every entry, so a flow whose timestamp was
    not captured still needs a valid value; the epoch is an unmistakable, valid
    placeholder rather than an invented "now".
    """
    try:
        seconds = float(ts) if ts is not None else 0.0
    except (TypeError, ValueError):
        seconds = 0.0
    if seconds < 0.0:
        seconds = 0.0
    return datetime.fromtimestamp(seconds, tz=UTC).isoformat()


def duration_ms(start: float | None, end: float | None) -> float:
    """Milliseconds between two epoch timestamps, or -1 when either is missing."""
    try:
        if start is None or end is None:
            return -1.0
        delta = (float(end) - float(start)) * 1000.0
    except (TypeError, ValueError):
        return -1.0
    return round(delta, 3) if delta >= 0.0 else -1.0


def timings(
    send: float,
    wait: float,
    receive: float,
    *,
    blocked: float | None = None,
    dns: float | None = None,
    connect: float | None = None,
    ssl: float | None = None,
) -> JsonObject:
    """HAR ``timings``: send/wait/receive are required; the rest are optional.

    The optional phases are included only when a caller actually knows them
    (>= 0), so a source that cannot measure them -- the proxy -- keeps a lean
    ``{send, wait, receive}`` while a richer source (CDP ResourceTiming) can add
    dns/connect/ssl. ssl is only meaningful with connect, per the spec.
    """
    out: JsonObject = {
        "send": round(send, 3),
        "wait": round(wait, 3),
        "receive": round(receive, 3),
    }
    for name, value in (("blocked", blocked), ("dns", dns), ("connect", connect), ("ssl", ssl)):
        if value is not None and value >= 0.0:
            out[name] = round(value, 3)
    return out


def total_time(*values: float) -> float:
    """Sum of the timing phases that are actually known (per the HAR spec)."""
    known = [v for v in values if v is not None and v >= 0.0]
    return round(sum(known), 3) if known else 0.0


def header_list(headers: Any) -> list[JsonObject]:
    """Normalise a header container into HAR ``[{name, value}]``.

    Accepts a mitmproxy ``Headers`` (which supports repeated names via
    ``items(multi=True)``) or a plain mapping; anything else yields an empty
    list rather than raising, so a sparse capture still produces valid HAR.
    """
    if headers is None:
        return []
    try:
        items = list(headers.items(multi=True))
    except TypeError:
        # A plain mapping's items() takes no ``multi`` keyword.
        try:
            items = list(headers.items())
        except (AttributeError, TypeError):
            return []
    except AttributeError:
        # Not a mapping/headers object at all.
        return []
    out: list[JsonObject] = []
    for name, value in items:
        if len(out) >= _MAX_HEADERS:
            break
        out.append({"name": str(name), "value": str(value)[:_MAX_HEADER_VALUE]})
    return out


def query_string(url: str) -> list[JsonObject]:
    """Parse a URL's query into HAR ``[{name, value}]`` pairs."""
    try:
        query = urlsplit(url or "").query
    except (TypeError, ValueError):
        return []
    if not query:
        return []
    return [
        {"name": name, "value": value}
        for name, value in parse_qsl(query, keep_blank_values=True)
    ]


def _text_of(body: bytes) -> tuple[str, str | None, int]:
    """Return (text, encoding_or_None, kept_bytes) for a body preview.

    UTF-8 text is inlined as-is; anything else is base64 with encoding="base64",
    which is exactly how HAR represents a binary/undecodable body.
    """
    head = body[:_MAX_BODY_TEXT]
    try:
        return head.decode("utf-8"), None, len(head)
    except UnicodeDecodeError:
        return base64.b64encode(head).decode("ascii"), "base64", len(head)


def content(body: bytes, mime: str, *, size: int | None = None) -> JsonObject:
    """A HAR ``response.content`` object with a bounded, honestly-typed preview."""
    real_size = size if size is not None else len(body)
    entry: JsonObject = {
        "size": real_size,
        "mimeType": mime or "application/octet-stream",
    }
    if body:
        text, encoding, kept = _text_of(body)
        entry["text"] = text
        if encoding is not None:
            entry["encoding"] = encoding
        if kept < len(body):
            entry["comment"] = f"body preview: {kept} of {len(body)} bytes"
    return entry


def post_data(body: bytes, mime: str) -> JsonObject | None:
    """A HAR ``request.postData`` object, or None when there is no request body."""
    if not body:
        return None
    text, encoding, kept = _text_of(body)
    entry: JsonObject = {"mimeType": mime or "application/octet-stream", "text": text}
    comment = []
    if encoding is not None:
        comment.append("text is base64-encoded binary")
    if kept < len(body):
        comment.append(f"body preview: {kept} of {len(body)} bytes")
    if comment:
        entry["comment"] = "; ".join(comment)
    return entry


def request_entry(
    *,
    method: Any,
    url: Any,
    http_version: str = "HTTP/1.1",
    headers: Any = None,
    body: bytes = b"",
    mime: str = "",
    body_size: int | None = None,
) -> JsonObject:
    entry: JsonObject = {
        "method": str(method or ""),
        "url": str(url or ""),
        "httpVersion": str(http_version or "HTTP/1.1"),
        "cookies": [],
        "headers": header_list(headers),
        "queryString": query_string(str(url or "")),
        "headersSize": -1,
        "bodySize": body_size if body_size is not None else (len(body) if body else 0),
    }
    post = post_data(body, mime)
    if post is not None:
        entry["postData"] = post
    return entry


def response_entry(
    *,
    status: Any,
    status_text: str = "",
    http_version: str = "HTTP/1.1",
    headers: Any = None,
    body: bytes = b"",
    mime: str = "",
    redirect_url: str = "",
    body_size: int | None = None,
) -> JsonObject:
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    return {
        "status": code,
        "statusText": str(status_text or ""),
        "httpVersion": str(http_version or "HTTP/1.1"),
        "cookies": [],
        "headers": header_list(headers),
        "content": content(body, mime, size=body_size),
        "redirectURL": str(redirect_url or ""),
        "headersSize": -1,
        "bodySize": body_size if body_size is not None else (len(body) if body else 0),
    }


def entry(
    *,
    started: float | None,
    time_ms: float,
    request: JsonObject,
    response: JsonObject,
    timings_obj: JsonObject | None = None,
) -> JsonObject:
    return {
        "startedDateTime": iso8601(started),
        "time": time_ms if time_ms is not None else 0.0,
        "request": request,
        "response": response,
        "cache": {},
        "timings": timings_obj if timings_obj is not None else timings(-1.0, -1.0, -1.0),
    }
