"""proxy.summary tallies the retained capture into a bounded distribution."""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend, _content_family


class _Recorder:
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries = entries

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._entries)


class _Inst:
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self.recorder = _Recorder(entries)


def _backend(monkeypatch: pytest.MonkeyPatch, entries: list[dict[str, Any]]) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Inst(entries))
    return backend


def test_summary_distributes_status_method_type_and_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        {
            "seq": 1,
            "method": "GET",
            "host": "a.com",
            "status": 200,
            "content_type": "application/json",
            "response_size": 100,
        },
        {
            "seq": 2,
            "method": "POST",
            "host": "a.com",
            "status": 404,
            "content_type": "text/html",
            "response_size": 50,
        },
        {
            "seq": 3,
            "method": "GET",
            "host": "b.com",
            "status": 301,
            "content_type": "",
            "response_size": 0,
        },
        {
            "seq": 4,
            "method": "GET",
            "host": "c.com",
            "status": None,
            "content_type": "",
            "response_size": 0,
            "error": True,
            "error_msg": "tls",
        },
        {
            "seq": 5,
            "method": "GET",
            "host": "a.com",
            "status": 200,
            "content_type": "image/png",
            "response_size": 9999,
            "body_omitted": True,
        },
    ]
    payload = _backend(monkeypatch, entries).summary("s")
    assert payload["total"] == 5
    assert payload["hosts"] == 3
    assert payload["status_classes"] == {"1xx": 0, "2xx": 2, "3xx": 1, "4xx": 1, "5xx": 0}
    assert payload["methods"] == {"GET": 4, "POST": 1}
    assert payload["content_types"] == {"json": 1, "html": 1, "none": 2, "image": 1}
    assert payload["errored"] == 1
    assert payload["no_status"] == 1
    assert payload["body_omitted"] == 1
    assert payload["total_response_bytes"] == 10149
    assert payload["dropped"] == 0


def test_summary_reports_dropped_from_the_ring(monkeypatch: pytest.MonkeyPatch) -> None:
    """dropped is the gap between the newest seq and what the ring still holds.

    A tally read as the whole session's history would overcount 2xx by however
    many the ring already evicted; dropped names that gap.
    """
    entries = [
        {
            "seq": 8,
            "method": "GET",
            "host": "a",
            "status": 200,
            "content_type": "",
            "response_size": 0,
        },
        {
            "seq": 9,
            "method": "GET",
            "host": "a",
            "status": 200,
            "content_type": "",
            "response_size": 0,
        },
        {
            "seq": 10,
            "method": "GET",
            "host": "a",
            "status": 200,
            "content_type": "",
            "response_size": 0,
        },
    ]
    payload = _backend(monkeypatch, entries).summary("s")
    assert payload["total"] == 3
    assert payload["dropped"] == 7


def test_summary_of_an_empty_capture_is_all_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _backend(monkeypatch, []).summary("s")
    assert payload["total"] == 0
    assert payload["hosts"] == 0
    assert payload["methods"] == {}
    assert payload["content_types"] == {}
    assert payload["status_classes"] == {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    assert payload["dropped"] == 0
    assert payload["total_response_bytes"] == 0


@pytest.mark.parametrize(
    ("content_type", "family"),
    [
        ("application/json; charset=utf-8", "json"),
        ("application/vnd.api+json", "json"),
        ("text/html", "html"),
        ("application/xhtml+xml", "xml"),
        ("application/xml", "xml"),
        ("image/png", "image"),
        ("font/woff2", "font"),
        ("text/css", "text"),
        ("application/javascript", "javascript"),
        ("application/octet-stream", "binary"),
        ("application/vnd.acme.thing", "binary"),
        ("weird/thing", "other"),
        ("", "none"),
        (None, "none"),
    ],
)
def test_content_family_buckets_are_fixed(content_type: object, family: str) -> None:
    assert _content_family(content_type) == family
