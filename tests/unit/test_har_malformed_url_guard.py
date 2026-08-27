"""A single malformed URL in a capture must not sink the whole HAR export.

``har_entry`` parses the request URL into the HAR ``queryString`` list via
``urlsplit``, and ``urlsplit`` raises ``ValueError`` on some real-world-plausible
URLs -- an unterminated IPv6 literal (``http://[::1``) is the clearest. Both the
CDP (``web.har.export``) and mitmproxy (``proxy.export_har``) captures store
whatever URL the target actually used, so a page that fetched a malformed URL
drops one into the flow ring. If ``_query_string`` let that ``ValueError`` out,
``har_entry`` would raise and ``serialize_har`` would crash on that one flow,
losing the entire capture rather than one field of one entry.

``_query_string`` swallows the error and returns an empty ``queryString``. These
tests pin that whole path -- the parser, one entry, and a mixed export -- so a
later "urlsplit never raises" cleanup cannot quietly turn a single bad URL into
a failed export. ``test_har_export_spec.py`` only ever feeds well-formed URLs,
so this failure mode is otherwise unexercised.
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

# urlsplit rejects this outright (the IPv6 bracket is never closed), so it is a
# clean, version-stable trigger for the guard rather than something that only
# raises when a later member like .port is touched.
_MALFORMED_URL = "http://[::1"


def test_urlsplit_actually_rejects_the_fixture() -> None:
    # Documents the premise: without the guard this call inside har_entry raises.
    from urllib.parse import urlsplit

    with pytest.raises(ValueError, match="Invalid IPv6 URL"):
        urlsplit(_MALFORMED_URL)


def test_query_string_swallows_a_url_urlsplit_rejects() -> None:
    assert _query_string(_MALFORMED_URL) == []


def test_har_entry_survives_a_malformed_url_and_stays_spec_valid() -> None:
    entry = har_entry(
        method="GET",
        url=_MALFORMED_URL,
        status=200,
        mime_type="text/html",
    )

    # The URL is preserved verbatim (HAR allows any string), queryString is the
    # spec's empty list, and the entry still encodes as valid JSON.
    assert entry["request"]["url"] == _MALFORMED_URL
    assert entry["request"]["queryString"] == []
    doc = json.loads(json.dumps(build_har([entry])))
    assert doc["log"]["entries"][0]["request"]["url"] == _MALFORMED_URL


def test_serialize_har_keeps_every_flow_when_one_url_is_malformed() -> None:
    entries = [
        har_entry(
            method="GET", url="https://example.com/before?a=1", status=200, mime_type="text/html"
        ),
        har_entry(method="GET", url=_MALFORMED_URL, status=0, mime_type=""),
        har_entry(
            method="GET", url="https://example.com/after?b=2", status=200, mime_type="text/html"
        ),
    ]

    result = serialize_har(entries, max_bytes=64 * 1024 * 1024)

    # The bad flow neither raised nor was dropped: all three survive intact.
    assert result.truncated is False
    assert result.entry_count == 3
    doc = json.loads(result.text)
    urls = [entry["request"]["url"] for entry in doc["log"]["entries"]]
    assert urls == [
        "https://example.com/before?a=1",
        _MALFORMED_URL,
        "https://example.com/after?b=2",
    ]
    # The good neighbours still parsed their query strings.
    assert doc["log"]["entries"][0]["request"]["queryString"] == [{"name": "a", "value": "1"}]
    assert doc["log"]["entries"][1]["request"]["queryString"] == []
