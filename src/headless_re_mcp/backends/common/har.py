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
``postData`` when the capture held it, and honest "unknown" sentinels (``-1``
sizes, empty arrays) where the capture did not retain that detail, so the
document loads while never claiming data it does not have.
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
    populated; a capture that kept the request body can pass ``request_post_
    data`` (build it with ``post_data``) so the Request payload is shown; a
    capture that only kept summaries omits them and those members stay empty.
    Every remaining required member is emitted with a valid empty/unknown value
    so the entry is well-formed. ``extra`` carries custom ``_``-prefixed fields
    (e.g. the web capture's resource type), which HAR permits.
    """
    request: JsonObject = {
        "method": method or "",
        "url": url or "",
        "httpVersion": http_version,
        "cookies": [],
        "headers": request_headers or [],
        "queryString": query_string(url),
        "headersSize": -1,
        "bodySize": -1,
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
            "cookies": [],
            "headers": response_headers or [],
            "content": {"size": 0, "mimeType": mime_type or ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
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
