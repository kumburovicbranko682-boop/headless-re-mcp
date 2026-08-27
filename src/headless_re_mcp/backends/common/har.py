"""Build HAR 1.2 documents that standard viewers actually accept.

A HAR ``entry`` has required members well beyond method/url/status:
``startedDateTime``, ``time``, a ``request`` and ``response`` each carrying
``httpVersion``/``cookies``/``headers`` (plus ``queryString`` on the request and
``content`` on the response) and ``headersSize``/``bodySize``, a ``cache``
object, and ``timings``. The proxy and web exporters used to emit only
method/url/status/mimeType, which Chrome DevTools and other HAR tools reject as
malformed -- a file that opens nowhere is not an export. These builders fill
every required field, using the real capture timestamp when one was recorded,
the request parameters recovered from the URL for ``queryString``, the raw
request/response headers when the capture retained them, the request body as
``postData`` when the capture held it, the request/response ``cookies`` parsed
from the ``Cookie``/``Set-Cookie`` headers, the redirect target recovered from
the response ``Location`` header for ``redirectURL``, the request/response
``bodySize`` recovered from the ``Content-Length`` header, and honest "unknown"
sentinels (``-1`` sizes, empty arrays) where the capture did not retain that
detail, so the document loads while never claiming data it does not have.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

JsonObject = dict[str, Any]

# The receiver keys off `entries`, not the creator, but the field is required.
_CREATOR: JsonObject = {"name": "headless-re-mcp"}

# A captured URL is already length-bounded upstream, but cap the parsed list so
# a pathologically parameter-dense query cannot bloat a single entry.
_MAX_QUERY_PARAMS = 512
# Headers are copied verbatim from a retained flow; cap the count and each
# name/value so one header-heavy entry cannot dominate the export.
_MAX_HEADERS = 200
_MAX_HEADER_LEN = 8 * 1024
# A request body carried into the export is clipped to this, and a
# form-urlencoded body's parsed field list is capped, so one large POST cannot
# bloat a single entry. The web ring already stores a smaller inline slice; this
# is the outer ceiling that also bounds the proxy's decoded flow content.
_MAX_POST_TEXT = 256 * 1024
_MAX_POST_PARAMS = 512
# Cookies parsed out of the Cookie / Set-Cookie headers; cap the count so a
# cookie-heavy exchange cannot bloat one entry.
_MAX_COOKIES = 200


def _clip(value: object, limit: int) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return text if len(text) <= limit else text[:limit]


def header_value(headers: list[JsonObject] | None, name: str) -> str:
    """First value of a header (case-insensitive) from a HAR name/value list.

    Lets an exporter recover a single header (e.g. ``content-type``, to type a
    request body) from the same ``har_headers`` list it already built, without a
    second pass over the raw capture. Returns "" when absent.
    """
    if not headers:
        return ""
    target = name.lower()
    for item in headers:
        if isinstance(item, dict) and str(item.get("name", "")).lower() == target:
            return str(item.get("value", ""))
    return ""


def content_length(headers: list[JsonObject] | None) -> int:
    """The body byte count declared by ``Content-Length``, or ``-1`` when unknown.

    HAR's request/response ``bodySize`` is exactly this figure for the common
    case, and taking it from the sender's own header is authoritative: it is the
    true on-wire body size even when the export retained only a clipped copy of
    the body (so it never understates a truncated payload the way measuring our
    stored text would). A missing, repeated (comma-folded), or non-numeric value
    degrades to ``-1`` (the spec's "unknown") rather than a guess.
    """
    raw = header_value(headers, "content-length").strip()
    if not raw or not raw.isascii() or not raw.isdigit():
        return -1
    try:
        return int(raw)
    except ValueError:
        return -1


def request_cookies(headers: list[JsonObject] | None) -> list[JsonObject]:
    """HAR ``request.cookies`` parsed from the ``Cookie`` header(s).

    ``cookies`` is a required request member and is what an analyst reads a HAR
    to see (the session token a page sends), yet it was always emitted empty.
    The ``Cookie`` header is a ``name=value; name2=value2`` list, so it is split
    into the spec's name/value objects from the headers already retained. A
    valueless segment keeps an empty value rather than being dropped, and the
    list is capped so a cookie flood cannot bloat one entry.
    """
    out: list[JsonObject] = []
    for header in headers or []:
        if not isinstance(header, dict) or str(header.get("name", "")).lower() != "cookie":
            continue
        for segment in str(header.get("value", "")).split(";"):
            pair = segment.strip()
            if not pair:
                continue
            name, sep, value = pair.partition("=")
            name = name.strip()
            if not name:
                continue
            out.append({"name": name, "value": value.strip() if sep else ""})
            if len(out) >= _MAX_COOKIES:
                return out
    return out


def _parse_set_cookie(raw: str) -> JsonObject | None:
    """One ``Set-Cookie`` value as a HAR cookie, or None when it has no name.

    The first ``name=value`` is the cookie; the rest are attributes. Only the
    members HAR defines are surfaced -- ``path``/``domain`` and the security
    flags ``httpOnly``/``secure``, which are exactly the triage signals for a
    session cookie. ``expires`` is deliberately not emitted: Set-Cookie carries
    an HTTP-date, and HAR wants ISO 8601, so a raw copy would risk a strict
    viewer rejecting the log.
    """
    parts = raw.split(";")
    name, sep, value = parts[0].strip().partition("=")
    name = name.strip()
    if not name:
        return None
    cookie: JsonObject = {"name": name, "value": value.strip() if sep else ""}
    for attribute in parts[1:]:
        key, _, val = attribute.strip().partition("=")
        low = key.strip().lower()
        if low == "path":
            cookie["path"] = val.strip()
        elif low == "domain":
            cookie["domain"] = val.strip()
        elif low == "httponly":
            cookie["httpOnly"] = True
        elif low == "secure":
            cookie["secure"] = True
    return cookie


def response_cookies(headers: list[JsonObject] | None) -> list[JsonObject]:
    """HAR ``response.cookies`` parsed from the ``Set-Cookie`` header(s).

    Each ``Set-Cookie`` is one cookie (``har_headers`` already unfolds repeats
    into separate entries), so the list mirrors what the server set, with the
    ``HttpOnly``/``Secure`` flags an analyst checks. Bounded like the request
    side; a nameless header is skipped rather than emitted malformed.
    """
    out: list[JsonObject] = []
    for header in headers or []:
        if not isinstance(header, dict) or str(header.get("name", "")).lower() != "set-cookie":
            continue
        cookie = _parse_set_cookie(str(header.get("value", "")))
        if cookie is not None:
            out.append(cookie)
        if len(out) >= _MAX_COOKIES:
            return out
    return out


def post_data(body: str | bytes | None, mime_type: str | None) -> JsonObject | None:
    """A HAR ``request.postData`` object from a captured body, or None when empty.

    ``postData`` is the field an API/protocol analyst opens a HAR to read -- the
    JSON body, the form credentials, the signed blob a page POSTs -- yet it was
    never emitted even when the capture held the body. ``mimeType`` is a required
    member when ``postData`` is present, so an unknown content type still yields
    an empty-string mimeType rather than an invalid object. A form-urlencoded
    body is additionally split into the spec's ``params`` (name/value) list, the
    same recovery ``query_string`` does for the URL; any other body is carried
    verbatim in ``text``. Bytes are decoded leniently so a binary body still
    signals its presence rather than breaking the export.
    """
    if not body:
        return None
    if isinstance(body, bytes):
        text = body[:_MAX_POST_TEXT].decode("utf-8", errors="replace")
    else:
        text = _clip(body, _MAX_POST_TEXT)
    if not text:
        return None
    mime = mime_type or ""
    result: JsonObject = {"mimeType": mime, "text": text}
    base = mime.split(";", 1)[0].strip().lower()
    if base == "application/x-www-form-urlencoded":
        try:
            pairs = parse_qsl(text, keep_blank_values=True)
        except ValueError:
            pairs = []
        if pairs:
            result["params"] = [
                {"name": name, "value": value} for name, value in pairs[:_MAX_POST_PARAMS]
            ]
    return result


def har_headers(headers: Any) -> list[JsonObject]:
    """A mapping of headers as HAR ``{"name","value"}`` objects, bounded.

    Accepts a mitmproxy ``Headers`` (which can repeat a name, so ``items(multi=
    True)`` is preferred) or a plain dict. The count and each field are clipped
    so a hostile server's header flood cannot bloat one entry, and any oddly
    shaped mapping degrades to an empty list rather than breaking the export.
    """
    if headers is None:
        return []
    try:
        try:
            items = list(headers.items(multi=True))
        except TypeError:
            items = list(headers.items())
    except Exception:  # noqa: BLE001
        return []
    return [
        {"name": _clip(name, _MAX_HEADER_LEN), "value": _clip(value, _MAX_HEADER_LEN)}
        for name, value in items[:_MAX_HEADERS]
    ]


def query_string(url: str | None) -> list[JsonObject]:
    """The URL's query parsed into HAR ``queryString`` name/value objects.

    ``queryString`` is a required request member and it is exactly the request
    parameters a reverse-engineer opens a HAR to read, yet it was always emitted
    empty even though the whole URL -- query included -- is already in the entry.
    The data is therefore surfaced from the URL that is already retained, not
    invented: the query is split off (the fragment, which ``urlsplit`` separates,
    is excluded) and percent-decoded with blank values kept, so ``?a=1&b=&c``
    round-trips honestly. A malformed URL degrades to an empty list rather than
    breaking the whole export.
    """
    if not url:
        return []
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    if not query:
        return []
    pairs = parse_qsl(query, keep_blank_values=True)
    return [{"name": name, "value": value} for name, value in pairs[:_MAX_QUERY_PARAMS]]


def iso8601(epoch: float | None) -> str:
    """An RFC 3339 / ISO 8601 timestamp, or the epoch when none was captured.

    ``startedDateTime`` is required and must parse as a date, so a missing or
    nonsensical value degrades to ``1970-01-01T00:00:00+00:00`` rather than
    omitting the field (which makes strict parsers reject the whole log).
    """
    if not isinstance(epoch, (int, float)) or epoch <= 0:
        epoch = 0.0
    return datetime.fromtimestamp(float(epoch), tz=UTC).isoformat()


def har_entry(
    *,
    started_at: float | None,
    method: str | None,
    url: str | None,
    status: int | None,
    mime_type: str | None,
    http_version: str = "HTTP/1.1",
    request_headers: list[JsonObject] | None = None,
    response_headers: list[JsonObject] | None = None,
    request_post_data: JsonObject | None = None,
    extra: JsonObject | None = None,
) -> JsonObject:
    """One spec-complete HAR entry from what a capture retained.

    method/url/status/mimeType and an optional start time are always known;
    ``queryString`` is recovered from the URL (see ``query_string``). A capture
    that also kept the raw headers can pass ``request_headers`` / ``response_
    headers`` (build them with ``har_headers``) so the viewer's Headers tab is
    populated and the request/response ``cookies`` are parsed from the
    ``Cookie``/``Set-Cookie`` headers; a capture that kept the request body can
    pass ``request_post_data`` (build it with ``post_data``) so the Request
    payload is shown; a capture that only kept summaries omits them and those
    members stay empty.
    Every remaining required member is emitted with a valid empty/unknown value
    so the entry is well-formed. ``extra`` carries custom ``_``-prefixed fields
    (e.g. the web capture's resource type), which HAR permits.
    """
    request: JsonObject = {
        "method": method or "",
        "url": url or "",
        "httpVersion": http_version,
        "cookies": request_cookies(request_headers),
        "headers": request_headers or [],
        "queryString": query_string(url),
        "headersSize": -1,
        "bodySize": content_length(request_headers),
    }
    if request_post_data is not None:
        request["postData"] = request_post_data
    entry: JsonObject = {
        "startedDateTime": iso8601(started_at),
        # No per-phase timing was captured; 0 is valid and keeps the invariant
        # that ``time`` equals the sum of the (all-zero) timings below.
        "time": 0.0,
        "request": request,
        "response": {
            "status": int(status or 0),
            "statusText": "",
            "httpVersion": http_version,
            "cookies": response_cookies(response_headers),
            "headers": response_headers or [],
            "content": {"size": 0, "mimeType": mime_type or ""},
            # The HAR spec's redirectURL is the Location response header; both
            # capture sides already hand the headers over, so recover the
            # redirect target here rather than drop the chain (OAuth hops,
            # trackers, URL shorteners) a viewer would otherwise show as blank.
            "redirectURL": header_value(response_headers, "location"),
            "headersSize": -1,
            # The received body's on-wire byte count, recovered from the
            # response Content-Length (which, when the body is compressed, is the
            # transferred size -- exactly what bodySize means). content.size
            # stays 0 because the uncompressed length is not known without
            # decoding the body, which the export deliberately does not retain.
            "bodySize": content_length(response_headers),
        },
        "cache": {},
        "timings": {"send": 0.0, "wait": 0.0, "receive": 0.0},
    }
    if extra:
        entry.update(extra)
    return entry


def har_document(entries: list[JsonObject]) -> JsonObject:
    """Wrap entries in the required ``log`` envelope."""
    return {
        "log": {
            "version": "1.2",
            "creator": dict(_CREATOR),
            "entries": entries,
        }
    }
