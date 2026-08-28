"""Shared aggregation for endpoint/secret findings over a string corpus.

endpoint_scan.py and secret_scan.py own the per-text matching primitive; this
owns the step above it that every ``*.endpoints`` / ``*.secrets`` tool repeats:
dedup by value, count occurrences, attach a per-string reference (so a finding
can be pivoted back to where it lives), summarise the distinct URL hosts, filter
by name, sort, page and cap. Callers pass an iterable of ``(text, ref)`` pairs --
``ref`` is a small dict merged into each new finding (a vaddr/address for a
native binary, a token for a .NET literal) -- and get the standard payload back.

The APK and .NET lines predate this and keep their own equivalent loops; the
native lines (radare2, Ghidra) share it, since their string items carry the same
address-style reference.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from headless_re_mcp.backends.common.endpoint_scan import iter_endpoint_matches
from headless_re_mcp.backends.common.secret_scan import iter_secret_matches

JsonObject = dict[str, Any]

_MAX_EP_FINDINGS = 50000
_MAX_EP_VALUE = 512
_MAX_EP_SOURCE = 512
_MAX_EP_HOSTS = 512
_MAX_SEC_FINDINGS = 20000
_MAX_SEC_VALUE = 512
_MAX_SEC_SOURCE = 512
_PAGE_CAP = 2000


def _page(rows: list[JsonObject], offset: int, limit: int) -> tuple[list[JsonObject], int, bool]:
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _PAGE_CAP))
    window = rows[start : start + cap]
    return window, start, start + len(window) < len(rows)


def _merge_ref(row: JsonObject, ref: JsonObject | None) -> None:
    if not ref:
        return
    for key, value in ref.items():
        if value is not None and key not in row:
            row[key] = value


def aggregate_endpoints(
    pairs: Iterable[tuple[str, JsonObject | None]],
    *,
    include_paths: bool = True,
    name_filter: str = "",
    offset: int = 0,
    limit: int = 200,
    scan_capped: bool = False,
) -> JsonObject:
    """Aggregate endpoints across ``(text, ref)`` pairs into the standard payload."""
    aggregates: dict[str, JsonObject] = {}
    stop = False
    for text, ref in pairs:
        source = str(text or "")
        if not source:
            continue
        for value, kind, scheme, host in iter_endpoint_matches(source, include_paths=include_paths):
            current = aggregates.get(value)
            if current is None:
                if len(aggregates) >= _MAX_EP_FINDINGS:
                    scan_capped = True
                    stop = True
                    break
                row: JsonObject = {
                    "value": value[:_MAX_EP_VALUE],
                    "kind": kind,
                    "scheme": scheme,
                    "host": host,
                    "source": source[:_MAX_EP_SOURCE],
                    "count": 1,
                }
                if len(value) > _MAX_EP_VALUE:
                    row["value_truncated"] = True
                if len(source) > _MAX_EP_SOURCE:
                    row["source_truncated"] = True
                _merge_ref(row, ref)
                aggregates[value] = row
            else:
                current["count"] = int(current["count"]) + 1
        if stop:
            break
    endpoints = list(aggregates.values())
    needle = name_filter.strip().casefold() if isinstance(name_filter, str) else ""
    if needle:
        endpoints = [
            e
            for e in endpoints
            if needle in str(e["value"]).casefold() or needle in str(e["host"]).casefold()
        ]
    endpoints.sort(key=lambda e: (-int(e["count"]), str(e["value"])))
    host_set = sorted({str(e["host"]) for e in endpoints if e["kind"] == "url" and e["host"]})
    window, start, has_more = _page(endpoints, offset, limit)
    return {
        "endpoints": window,
        "count": len(window),
        "total": len(endpoints),
        "offset": start,
        "has_more": has_more,
        "hosts": host_set[:_MAX_EP_HOSTS],
        "hosts_truncated": len(host_set) > _MAX_EP_HOSTS,
        "scan_capped": scan_capped,
    }


def aggregate_secrets(
    pairs: Iterable[tuple[str, JsonObject | None]],
    *,
    include_generic: bool = False,
    name_filter: str = "",
    offset: int = 0,
    limit: int = 200,
    scan_capped: bool = False,
) -> JsonObject:
    """Aggregate credential findings across ``(text, ref)`` pairs."""
    aggregates: dict[tuple[str, str], JsonObject] = {}
    stop = False
    for text, ref in pairs:
        source = str(text or "")
        if not source:
            continue
        for detector, matched in iter_secret_matches(source, include_generic=include_generic):
            key = (detector, matched)
            current = aggregates.get(key)
            if current is None:
                if len(aggregates) >= _MAX_SEC_FINDINGS:
                    scan_capped = True
                    stop = True
                    break
                row: JsonObject = {
                    "detector": detector,
                    "value": matched[:_MAX_SEC_VALUE],
                    "source": source[:_MAX_SEC_SOURCE],
                    "count": 1,
                }
                if len(matched) > _MAX_SEC_VALUE:
                    row["value_truncated"] = True
                if len(source) > _MAX_SEC_SOURCE:
                    row["source_truncated"] = True
                _merge_ref(row, ref)
                aggregates[key] = row
            else:
                current["count"] = int(current["count"]) + 1
        if stop:
            break
    secrets = list(aggregates.values())
    needle = name_filter.strip().casefold() if isinstance(name_filter, str) else ""
    if needle:
        secrets = [
            s
            for s in secrets
            if needle in str(s["detector"]).casefold() or needle in str(s["value"]).casefold()
        ]
    secrets.sort(key=lambda s: (str(s["detector"]), -int(s["count"]), str(s["value"])))
    detectors = sorted({str(s["detector"]) for s in secrets})
    window, start, has_more = _page(secrets, offset, limit)
    return {
        "secrets": window,
        "count": len(window),
        "total": len(secrets),
        "offset": start,
        "has_more": has_more,
        "detectors": detectors,
        "scan_capped": scan_capped,
    }
