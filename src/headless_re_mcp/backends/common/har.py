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


class HarReadError(ValueError):
    """Bytes handed to :func:`read_har_entries` are not a HAR 1.2 log.

    The reader raises this rather than returning an empty list so a caller can
    tell "a HAR with no requests" from "not a HAR at all" and map the latter to
    ``invalid_params`` instead of silently answering with zero entries.
    """


def read_har_entries(text: str) -> list[JsonObject]:
    """Normalise a HAR 1.2 document's entries to the compact request summary.

    Reads back what :func:`serialize_har` writes -- and any spec HAR a browser,
    proxy or ``har-validator`` produced -- projecting each entry onto the exact
    ``url``/``method``/``status``/``mimeType``/``resourceType`` keys the live
    ``web.network.list`` reader returns, in the browser track's CDP-native
    camelCase, so an agent reads ``entry["mimeType"]`` off a saved capture the
    same way it does off a running one instead of switching to a snake_case
    spelling. ``resourceType`` is always present, defaulting to ``""`` when the
    HAR carried no ``_resourceType`` hint (a proxy-produced HAR), matching the
    live reader's empty-string default rather than dropping the key. The one
    field with no live sibling, ``startedDateTime``, rides along under its own
    HAR-spec name because a static HAR is the one place that timestamp survives.

    Sub-objects are read defensively: a malformed entry (not an object, or with
    a non-object ``request``/``response``) contributes its available fields
    rather than aborting the whole read, since a partial HAR is still worth
    listing. Raises :class:`HarReadError` only when the top-level shape is not a
    HAR log with an ``entries`` array -- the structural contract the caller maps
    to ``invalid_params``.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HarReadError(f"not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise HarReadError("HAR root is not a JSON object")
    log = document.get("log")
    if not isinstance(log, dict):
        raise HarReadError("HAR has no log object")
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise HarReadError("HAR log has no entries array")
    summaries: list[JsonObject] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        request = request if isinstance(request, dict) else {}
        response = entry.get("response")
        response = response if isinstance(response, dict) else {}
        content = response.get("content")
        content = content if isinstance(content, dict) else {}
        status = response.get("status")
        resource_type = entry.get("_resourceType")
        summary: JsonObject = {
            "url": str(request.get("url", "")),
            "method": str(request.get("method", "")),
            "status": status if isinstance(status, int) else None,
            "mimeType": str(content.get("mimeType", "")),
            # Always present, "" when absent -- the live reader's default -- so a
            # caller never has to guard the key across the two producers.
            "resourceType": resource_type if isinstance(resource_type, str) else "",
            "startedDateTime": str(entry.get("startedDateTime", "")),
        }
        summaries.append(summary)
    return summaries


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
