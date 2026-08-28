"""Pin that a malformed captured URL cannot break HAR export.

``test_har_export_spec.py`` drives ``_query_string`` with well-formed URLs and
asserts the parsed ``queryString`` pairs, but never a URL that ``urlsplit``
refuses -- an unbalanced IPv6 bracket such as ``http://[::1`` raises
``ValueError`` at parse time. That URL is not hypothetical: the HAR exporters
serialise whatever the browser and proxy captures recorded, and a target can
make a request to any string it likes. The guard degrades a URL it cannot
split to an empty ``queryString`` instead of letting the ValueError abort the
whole export, so one hostile flow cannot cost the analyst the entire HAR of a
session. Pinned end to end: the helper, one entry, and a full serialized log.
"""

from __future__ import annotations

import json

import pytest

from headless_re_mcp.backends.common.har import (
    _query_string,
    build_har,
    har_entry,
    serialize_har,
)

# urlsplit raises ValueError on these at parse time (unbalanced or non-address
# IPv6 brackets), which is exactly the arm the guard exists to absorb.
_UNSPLITTABLE_URLS = [
    "http://[::1",
    "http://[/x",
    "http://[:::]/p?a=b",
]


@pytest.mark.parametrize("url", _UNSPLITTABLE_URLS)
def test_query_string_degrades_a_url_it_cannot_split_to_empty(url: str) -> None:
    # No raise, no crash: a URL urlsplit refuses yields no parameters rather
    # than propagating ValueError up through the exporter.
    assert _query_string(url) == []


def test_query_string_still_parses_a_normal_url() -> None:
    # The guard must not have swallowed the ordinary path with the error one.
    assert _query_string("https://h/p?a=1&b=2&b=3") == [
        {"name": "a", "value": "1"},
        {"name": "b", "value": "2"},
        {"name": "b", "value": "3"},
    ]


def test_har_entry_with_a_malformed_url_stays_spec_complete() -> None:
    # The URL rides through verbatim (an analyst still sees what was requested),
    # the queryString is empty, and every mandatory member is present so a
    # strict HAR consumer still loads the entry.
    entry = har_entry(
        method="GET",
        url="http://[::1",
        status=200,
        mime_type="text/html",
    )
    assert entry["request"]["url"] == "http://[::1"
    assert entry["request"]["queryString"] == []
    for member in ("startedDateTime", "time", "request", "response", "cache", "timings"):
        assert member in entry


def test_a_hostile_url_in_one_flow_does_not_break_the_serialized_log() -> None:
    # A well-formed flow and a malformed one in the same capture: the export
    # must produce one valid HAR carrying both, not raise on the bad entry.
    entries = [
        har_entry(method="GET", url="https://good/one?x=1", status=200, mime_type="text/html"),
        har_entry(method="GET", url="http://[::1", status=200, mime_type="text/html"),
    ]
    result = serialize_har(entries, max_bytes=64 * 1024 * 1024)
    assert result.truncated is False
    assert result.entry_count == 2

    doc = json.loads(result.text)
    urls = [entry["request"]["url"] for entry in doc["log"]["entries"]]
    assert urls == ["https://good/one?x=1", "http://[::1"]
    # Sanity that build_har wrapped the same entries the serializer encoded.
    assert build_har(entries)["log"]["entries"] == entries
