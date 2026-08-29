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
import math
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
# "does not apply / was not measured" sentinel. A capture that measured a phase
# (the proxy computes send/wait/receive from mitmproxy's flow timestamps, the
# same way mitmproxy's own HAR export does) passes it in ``timings_ms``; every
# unmeasured phase stays -1 and ``time`` is the sum of the non-negative phases
# -- exactly what the spec defines ``time`` to be, so an entry with no measured
# phase keeps the historical ``time: 0``.
_UNKNOWN_TIMINGS = {"send": -1, "wait": -1, "receive": -1}
_TIMING_PHASES = ("send", "wait", "receive")
# The captures keep no per-request header set or payload length, so every size
# is the spec's "not available" value rather than a fabricated zero.
_UNKNOWN_SIZE = -1
_ENTRY_COMMENT = "per-flow headers, bodies and phase timings were not captured"
# An entry whose phases were measured must not claim they were not: the comment
# is the file's own explanation of its -1 placeholders, and a reader told
# "timings were not captured" under a populated timings object would rightly
# distrust the rest of it.
_ENTRY_COMMENT_TIMED = "per-flow headers and bodies were not captured"


class SerializedHar(NamedTuple):
    text: str
    entry_count: int
    truncated: bool
    size: int


def _iso_now() -> str:
    """Export-time instant in ISO 8601 with an explicit offset (the TZD HAR wants)."""
    return datetime.now(UTC).isoformat()


def iso_from_epoch(epoch: float | None) -> str | None:
    """ISO 8601 (with offset) for a Unix epoch, or None when it is unknown.

    HAR's ``startedDateTime`` is mandatory, so an entry with no captured time
    falls back to the export instant. But a capture that *does* know when a
    request began (the proxy records mitmproxy's ``request.timestamp_start``)
    should say so: passing the real time through here makes a HAR viewer's
    waterfall reflect the actual request order instead of stamping every flow
    with the single export instant, which reads as if they all happened at once.
    Returns None for an absent or unparseable epoch so the caller takes the
    export-time fallback rather than emitting a bad timestamp.
    """
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC).isoformat()
    except (ValueError, OverflowError, OSError, TypeError):
        return None


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
    timings_ms: JsonObject | None = None,
    error: str | None = None,
    redirect_url: str | None = None,
) -> JsonObject:
    """One spec-complete HAR 1.2 entry from the fields a summary actually has.

    Members the captures never recorded are filled with the spec's placeholders
    -- empty cookie/header arrays, -1 sizes, unknown timings -- because omitting
    them makes a strict consumer reject the entire log rather than the one
    absent field. ``queryString`` is parsed from the URL, and when the capture
    knows the received (on-wire) response body length (``response_body_size``)
    it fills ``content.size`` and ``response.bodySize`` instead of the -1
    sentinel. That on-wire length is exactly ``bodySize``; the capture holds no
    separate decoded length, so a compressed response's ``content.size`` (which
    the spec defines as the uncompressed size) carries the same on-wire figure
    rather than a -1 -- accurate for the uncompressed common case and a floor
    otherwise.
    ``resource_type`` rides along as Chrome's ``_resourceType`` extension so the
    browser capture keeps that hint. ``timings_ms`` carries whichever of the
    send/wait/receive phases the capture measured (milliseconds); measured
    phases replace the -1 sentinel and ``time`` becomes their sum -- the spec's
    own definition of ``time`` -- so a HAR viewer's waterfall shows real
    durations instead of zero-width bars. A phase that is absent, negative, or
    not a finite number stays -1 rather than corrupting the total.

    ``error`` marks an entry the capture could not complete (a proxy flow
    mitmproxy failed, a browser request CDP reported ``loadingFailed`` for): the
    reason rides along as Chrome DevTools' own ``_error`` extension, the same
    convention DevTools and mitmproxy use so their HAR viewers surface it,
    alongside the ``status: 0`` a null status already produces. Without it a
    failed exchange exported as a plain status-0 entry is indistinguishable from
    a genuine zero-status response, and the reason recorded on the row -- often
    the finding -- is dropped from the artifact. ``None`` (a completed exchange)
    emits no ``_error`` field at all.

    ``redirect_url`` fills the spec's ``response.redirectURL`` for a 3xx hop (the
    Location it sent the client to), which the browser capture records for each
    redirect it preserves; absent it stays the empty string the spec uses for a
    non-redirect response, so a HAR viewer draws the redirect chain instead of
    showing each hop as an unrelated row.
    """
    status_code = int(status) if isinstance(status, int) else 0
    url_text = str(url or "")
    if isinstance(response_body_size, int) and response_body_size >= 0:
        content_size = response_body_size
    else:
        content_size = _UNKNOWN_SIZE
    timings: dict[str, float | int] = dict(_UNKNOWN_TIMINGS)
    if timings_ms:
        for phase in _TIMING_PHASES:
            value = timings_ms.get(phase)
            if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
                timings[phase] = round(float(value), 3)
    measured = [value for value in timings.values() if value >= 0]
    entry: JsonObject = {
        "startedDateTime": started_date_time or _iso_now(),
        "time": round(sum(measured), 3) if measured else 0,
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
            "redirectURL": str(redirect_url or ""),
            "headersSize": _UNKNOWN_SIZE,
            "bodySize": content_size,
        },
        "cache": {},
        "timings": timings,
        "comment": _ENTRY_COMMENT_TIMED if measured else _ENTRY_COMMENT,
    }
    if resource_type:
        entry["_resourceType"] = str(resource_type)
    if error is not None:
        entry["_error"] = str(error)
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
