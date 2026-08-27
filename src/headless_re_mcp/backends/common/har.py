"""Build HAR 1.2 documents that standard viewers actually accept.

A HAR ``entry`` has required members well beyond method/url/status:
``startedDateTime``, ``time``, a ``request`` and ``response`` each carrying
``httpVersion``/``cookies``/``headers`` (plus ``queryString`` on the request and
``content`` on the response) and ``headersSize``/``bodySize``, a ``cache``
object, and ``timings``. The proxy and web exporters used to emit only
method/url/status/mimeType, which Chrome DevTools and other HAR tools reject as
malformed -- a file that opens nowhere is not an export. These builders fill
every required field, using the real capture timestamp when one was recorded
and honest "unknown" sentinels (``-1`` sizes, empty arrays) where the capture
did not retain that detail, so the document loads while never claiming data it
does not have.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

JsonObject = dict[str, Any]

# The receiver keys off `entries`, not the creator, but the field is required.
_CREATOR: JsonObject = {"name": "headless-re-mcp"}


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
    extra: JsonObject | None = None,
) -> JsonObject:
    """One spec-complete HAR entry from the little a capture summary retains.

    Only method/url/status/mimeType and an optional start time are known here;
    every other required member is emitted with a valid empty/unknown value so
    the entry is well-formed. ``extra`` carries custom ``_``-prefixed fields
    (e.g. the web capture's resource type), which HAR permits.
    """
    entry: JsonObject = {
        "startedDateTime": iso8601(started_at),
        # No per-phase timing was captured; 0 is valid and keeps the invariant
        # that ``time`` equals the sum of the (all-zero) timings below.
        "time": 0.0,
        "request": {
            "method": method or "",
            "url": url or "",
            "httpVersion": http_version,
            "cookies": [],
            "headers": [],
            "queryString": [],
            "headersSize": -1,
            "bodySize": -1,
        },
        "response": {
            "status": int(status or 0),
            "statusText": "",
            "httpVersion": http_version,
            "cookies": [],
            "headers": [],
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
