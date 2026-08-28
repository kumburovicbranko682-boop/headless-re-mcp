"""Spec-valid, byte-bounded HAR 1.2 assembly shared by the Web and proxy captures.

Both the CDP browser backend (``web.har.export``) and the mitmproxy backend
(``proxy.export_har``) turn their in-memory flow summaries into a HAR file. The
naive shape each grew on its own -- ``{"request": {method, url}, "response":
{status, content: {mimeType}}}`` -- is not loadable by the tools an analyst
actually opens a HAR in (Chrome DevTools "Import HAR", Firefox, har-validator):
the 1.2 spec makes ``startedDateTime``, ``time``, several request/response
members, ``cache`` and ``timings`` mandatory on every entry, and a consumer
that finds them missing rejects the whole file. Emitting them here, once, keeps
the two exporters producing an interoperable artifact instead of a bespoke blob
that only this project can read.

Serialisation is byte-bounded: entries are dropped from the *oldest* end until
the encoded file fits the capture cap, so the HAR keeps the most recent flows
that fit -- the same way both capture rings evict their oldest row when full,
and the subset an analyst reaching for a HAR after an action actually wants.
``proxy.export_har`` had no such ceiling -- it wrote whatever the ring held --
so an overnight capture of thousands of flows wrote an unbounded artifact into
the session directory that retention could not have foreseen. Both now go
through :func:`serialize_har`.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any, NamedTuple
from urllib.parse import parse_qsl, urlsplit

from headless_re_mcp import __version__

JsonObject = dict[str, Any]

HAR_VERSION = "1.2"
HAR_CREATOR_NAME = "headless-re-mcp"
# A URL with a pathological number of parameters must not inflate one entry.
# The upstream captures already bound the URL to 16 KiB, so this only guards
# the degenerate case; a real request is far below it.
_MAX_QUERY_PARAMS = 256

# HAR wants a millisecond count for each timing phase; -1 is the spec's own
# "does not apply / was not measured" sentinel. These captures record which
# flows happened, not how long each phase took, so every phase is reported
# unknown and ``time`` is 0 -- the sum of the non-negative phases, of which
# there are none, which is exactly what the spec defines ``time`` to be.
_UNKNOWN_TIMINGS = {"send": -1, "wait": -1, "receive": -1}
# The captures keep no per-request header set or payload length, so every size
# is the spec's "not available" value rather than a fabricated zero.
_UNKNOWN_SIZE = -1
_ENTRY_COMMENT = "per-flow headers, bodies and phase timings were not captured"


class SerializedHar(NamedTuple):
    text: str
    entry_count: int
    truncated: bool
    size: int


def _iso_now() -> str:
    """Export-time instant in ISO 8601 with an explicit offset (the TZD HAR wants)."""
    return datetime.now(UTC).isoformat()


def _query_string(url: str) -> list[JsonObject]:
    """Parse the URL's query into HAR ``name``/``value`` pairs, bounded.

    HAR consumers render a "Query String Parameters" pane straight from this
    list; filling it from the URL the capture already holds costs nothing and
    makes the export useful to tools that do not re-parse the URL themselves.
    """
    try:
        query = urlsplit(url).query
    except (ValueError, TypeError):
        return []
    if not query:
        return []
    pairs = parse_qsl(query, keep_blank_values=True)
    return [{"name": name, "value": value} for name, value in pairs[:_MAX_QUERY_PARAMS]]


def har_entry(
    *,
    method: str | None,
    url: str | None,
    status: int | None,
    mime_type: str | None,
    started_date_time: str | None = None,
    resource_type: str | None = None,
    response_body_size: int | None = None,
) -> JsonObject:
    """One spec-complete HAR 1.2 entry from the fields a summary actually has.

    Members the captures never recorded are filled with the spec's placeholders
    -- empty cookie/header arrays, -1 sizes, unknown timings -- because omitting
    them makes a strict consumer reject the entire log rather than the one
    absent field. ``queryString`` is parsed from the URL, and when the capture
    knows the decoded response body length (``response_body_size``) it fills
    ``content.size`` and ``response.bodySize`` instead of the -1 sentinel.
    ``resource_type`` rides along as Chrome's ``_resourceType`` extension so the
    browser capture keeps that hint.
    """
    status_code = int(status) if isinstance(status, int) else 0
    url_text = str(url or "")
    if isinstance(response_body_size, int) and response_body_size >= 0:
        content_size = response_body_size
    else:
        content_size = _UNKNOWN_SIZE
    entry: JsonObject = {
        "startedDateTime": started_date_time or _iso_now(),
        "time": 0,
        "request": {
            "method": str(method or ""),
            "url": url_text,
            "httpVersion": "",
            "cookies": [],
            "headers": [],
            "queryString": _query_string(url_text),
            "headersSize": _UNKNOWN_SIZE,
            "bodySize": _UNKNOWN_SIZE,
        },
        "response": {
            "status": status_code,
            "statusText": "",
            "httpVersion": "",
            "cookies": [],
            "headers": [],
            "content": {"size": content_size, "mimeType": str(mime_type or "")},
            "redirectURL": "",
            "headersSize": _UNKNOWN_SIZE,
            "bodySize": content_size,
        },
        "cache": {},
        "timings": dict(_UNKNOWN_TIMINGS),
        "comment": _ENTRY_COMMENT,
    }
    if resource_type:
        entry["_resourceType"] = str(resource_type)
    return entry


def build_har(entries: list[JsonObject]) -> JsonObject:
    """Wrap entries in the mandatory ``log`` envelope with a named creator."""
    return {
        "log": {
            "version": HAR_VERSION,
            "creator": {"name": HAR_CREATOR_NAME, "version": str(__version__)},
            "entries": entries,
        }
    }


# --- reading side -----------------------------------------------------------
#
# The two exporters above write HAR files; nothing could read one back. An
# analyst who captured traffic (here, in Chrome DevTools, or in mitmproxy) and
# holds a .har had no offline way to ask "which hosts did this talk to, what
# failed, where did that URL come from" without standing a live browser or
# proxy back up. summarize_har closes that round trip with the stdlib alone --
# no CDP, no wabt, no CLI -- so a .har is a first-class thing to open and query.

# Each stringy field a summarised entry carries is bounded so one pathological
# URL or mime type cannot inflate a page. Real values sit far below this.
_MAX_HAR_FIELD = 8000
# The host histogram describes the whole (filtered) log, but only the busiest
# hosts are named; the rest are folded into the reported total via a flag.
_HOST_FACET_CAP = 64


class HarParseError(ValueError):
    """A document that does not decode as a HAR 1.2 log.

    A ValueError subclass so a caller that already funnels ValueError into an
    ``invalid_request`` envelope keeps working, while a caller that wants the
    more precise ``invalid_params`` can catch this type by name.
    """


def _clip(value: object) -> str:
    text = str(value or "")
    if len(text) > _MAX_HAR_FIELD:
        return text[:_MAX_HAR_FIELD]
    return text


def _entry_host(url: str) -> str:
    """Lowercased host[:port] from a request URL, or '' when it has none."""
    try:
        netloc = urlsplit(url).netloc
    except (ValueError, TypeError):
        return ""
    return netloc.casefold()


def _coerce_status(value: object) -> int | None:
    """A HAR response status as an int, or None when it is absent/0/garbage."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    return None


def _coerce_size(value: object) -> int | None:
    """A non-negative body/content size, or None for the spec's -1 sentinel."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _summarize_entry(entry: JsonObject) -> tuple[str, JsonObject]:
    """One HAR entry reduced to the fields an analyst scans, plus its host.

    Every member is optional in the wild -- captures from other tools omit
    what they did not record -- so each is pulled defensively and a missing or
    wrong-typed member becomes an empty/None field rather than an exception.
    """
    request = entry.get("request")
    request = request if isinstance(request, dict) else {}
    response = entry.get("response")
    response = response if isinstance(response, dict) else {}
    content = response.get("content")
    content = content if isinstance(content, dict) else {}
    url = _clip(request.get("url"))
    host = _entry_host(url)
    summary: JsonObject = {
        "method": _clip(request.get("method")),
        "url": url,
        "host": host,
        "status": _coerce_status(response.get("status")),
        "mime_type": _clip(content.get("mimeType")),
        "response_size": _coerce_size(content.get("size")),
        "started": _clip(entry.get("startedDateTime")),
    }
    resource_type = entry.get("_resourceType")
    if resource_type:
        summary["resource_type"] = _clip(resource_type)
    return host, summary


def _har_entries(document: Any) -> list[Any]:
    """The ``log.entries`` list, or a HarParseError naming what was wrong.

    Accepts both the whole ``{"log": {...}}`` document and a bare ``log``
    object, because a caller that already unwrapped one level should not have
    its file rejected as malformed.
    """
    if not isinstance(document, dict):
        raise HarParseError("not a HAR document: top level is not an object")
    log = document.get("log")
    if not isinstance(log, dict):
        # A bare log object (already unwrapped) is tolerated.
        log = document if "entries" in document else None
    if not isinstance(log, dict):
        raise HarParseError("not a HAR 1.2 file: missing the log object")
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise HarParseError("not a HAR 1.2 file: log.entries is missing or not a list")
    return entries


def summarize_har(
    document: Any,
    *,
    offset: int = 0,
    limit: int = 100,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
) -> JsonObject:
    """Bounded, paginated summary of a parsed HAR 1.2 document.

    One pass over ``log.entries``: entries that pass the (optional) host,
    method and status filters are counted, folded into a host histogram, and --
    only for the requested page window -- materialised into the summarised
    shape ``_summarize_entry`` returns. Counting the whole filtered set rather
    than the page keeps ``total`` and ``hosts`` describing the file, not the
    slice, the same honesty the paginated capture listings already keep.

    Raises HarParseError when the document is not a HAR 1.2 log; the caller
    turns that into the transport's invalid-input envelope.
    """
    entries = _har_entries(document)
    log = document.get("log") if isinstance(document.get("log"), dict) else document
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}

    start = max(0, int(offset))
    window = max(1, min(int(limit), _HOST_FACET_CAP * 16))
    want_host = host.casefold() if isinstance(host, str) and host.strip() else None
    want_method = method.casefold() if isinstance(method, str) and method.strip() else None
    want_status = _coerce_status(status) if status is not None else None

    hosts: Counter[str] = Counter()
    page: list[JsonObject] = []
    entries_total = 0
    matched = 0
    for raw in entries:
        entries_total += 1
        if not isinstance(raw, dict):
            continue
        entry_host, summary = _summarize_entry(raw)
        if want_host is not None and entry_host != want_host:
            continue
        if want_method is not None and summary["method"].casefold() != want_method:
            continue
        if want_status is not None and summary["status"] != want_status:
            continue
        hosts[entry_host] += 1
        if start <= matched < start + window:
            page.append(summary)
        matched += 1

    top = hosts.most_common(_HOST_FACET_CAP)
    return {
        "version": _clip(log.get("version")) if isinstance(log, dict) else "",
        "creator": {
            "name": _clip(creator.get("name")),
            "version": _clip(creator.get("version")),
        },
        "entries": page,
        "count": len(page),
        "total": matched,
        "entries_total": entries_total,
        "offset": start,
        "limit": window,
        "has_more": start + len(page) < matched,
        "hosts": {name: count for name, count in top},
        "hosts_truncated": len(hosts) > len(top),
        "distinct_hosts": len(hosts),
        "filters": {
            "host": want_host,
            "method": want_method,
            "status": want_status,
        },
    }


def serialize_har(entries: list[JsonObject], *, max_bytes: int) -> SerializedHar:
    """Encode a HAR log, dropping the oldest entries until it fits ``max_bytes``.

    Callers pass entries oldest-first, so eviction from the front keeps the most
    recent flows -- consistent with both capture rings, which evict their oldest
    row when full, and with what an analyst wants from a HAR taken right after an
    action. Returns the JSON text, how many entries survived, whether any were
    dropped, and the encoded byte length. A log that still exceeds the cap with
    no entries left is left for the caller to reject, since only the caller knows
    which error envelope to raise.
    """
    kept = list(entries)
    truncated = False
    text = json.dumps(build_har(kept), ensure_ascii=False)
    encoded = text.encode("utf-8")
    while kept and len(encoded) > max_bytes:
        drop = max(1, len(kept) // 8)
        del kept[:drop]
        truncated = True
        text = json.dumps(build_har(kept), ensure_ascii=False)
        encoded = text.encode("utf-8")
    return SerializedHar(text=text, entry_count=len(kept), truncated=truncated, size=len(encoded))
