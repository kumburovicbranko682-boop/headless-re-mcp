"""web.har.read: parse a HAR file off disk and page it like a live capture.

Three layers are pinned here because a HAR reader spans all of them and each
carries its own contract:

* ``read_har_entries`` (backends/common/har.py) -- projects a HAR 1.2 log onto
  the same compact request shape ``web.network.list`` returns, tolerates a
  malformed entry, and refuses a document that is not a HAR log at all.
* ``WebBackend.read_har`` -- the only reader here that needs no browser session;
  it resolves a path, refuses an oversized or missing or non-HAR file with the
  canonical codes, never deletes the caller's input, and pages with the shared
  ``_MAX_PAGE`` / ``offset`` / ``has_more`` clamp.
* ``AnalysisService.web_har_read`` -- wraps the backend into the ``Result``
  envelope with no session id, since the read is session-independent.

The round-trip case (``serialize_har`` -> ``read_har_entries``) is the load-
bearing one: it proves an exported capture reads back into the same fields,
which is the whole point of pairing the reader with ``web.har.export``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.har import (
    HarReadError,
    build_har,
    har_entry,
    read_har_entries,
    serialize_har,
)
from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _entries(count: int) -> list[dict]:
    return [
        har_entry(
            method="GET",
            url=f"https://a.test/{i}",
            status=200,
            mime_type="text/html",
        )
        for i in range(count)
    ]


def _write_har(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "capture.har"
    path.write_text(json.dumps(build_har(entries), ensure_ascii=False), encoding="utf-8")
    return path


# ---- read_har_entries: the parser ----------------------------------------


def test_a_serialized_har_reads_back_into_the_network_list_shape() -> None:
    entries = [
        har_entry(
            method="GET",
            url="https://a.test/app.js?x=1",
            status=200,
            mime_type="application/javascript",
            resource_type="script",
        ),
        har_entry(
            method="POST",
            url="https://a.test/api",
            status=500,
            mime_type="application/json",
        ),
    ]
    text = serialize_har(entries, max_bytes=10_000_000).text
    summaries = read_har_entries(text)

    assert [s["url"] for s in summaries] == ["https://a.test/app.js?x=1", "https://a.test/api"]
    assert summaries[0]["method"] == "GET"
    assert summaries[0]["status"] == 200
    assert summaries[0]["mimeType"] == "application/javascript"
    assert summaries[0]["resourceType"] == "script"
    # A static HAR is the one place the request timestamp survives.
    assert summaries[0]["startedDateTime"]
    # No _resourceType on the second entry -> resourceType defaults to "", the
    # same always-present empty default the live reader uses, not a missing key.
    assert summaries[1]["resourceType"] == ""
    assert summaries[1]["status"] == 500


def test_the_summary_keys_are_the_live_network_list_camelcase_keys() -> None:
    """The reader's whole selling point is that a saved capture pages like a
    running one, which only holds if the keys match verbatim. web.network.list
    returns CDP-native camelCase (url/method/status/mimeType/resourceType); a
    regression that spelled these snake_case would silently break any agent that
    read both, so pin the exact key set (plus the HAR-only startedDateTime)."""
    entry = har_entry(
        method="GET",
        url="https://a.test/x",
        status=200,
        mime_type="text/html",
        resource_type="script",
    )
    (summary,) = read_har_entries(serialize_har([entry], max_bytes=10_000).text)
    assert set(summary) == {
        "url",
        "method",
        "status",
        "mimeType",
        "resourceType",
        "startedDateTime",
    }


def test_reads_a_richer_external_har_and_projects_only_the_summary() -> None:
    """A HAR from Chrome DevTools / Firefox carries request and response headers,
    bodies, cache and timings this reader does not surface. It must still list
    the summary fields and ignore the rest -- the "reads any spec HAR" half of
    the contract, beyond our own exporter's output."""
    doc = {
        "log": {
            "version": "1.2",
            "creator": {"name": "WebInspector", "version": "537.36"},
            "entries": [
                {
                    "startedDateTime": "2026-08-28T06:00:00.000Z",
                    "time": 42.5,
                    "request": {
                        "method": "GET",
                        "url": "https://ext.test/app.css?v=2",
                        "httpVersion": "http/2.0",
                        "headers": [{"name": "accept", "value": "text/css"}],
                        "queryString": [{"name": "v", "value": "2"}],
                        "cookies": [],
                        "headersSize": 120,
                        "bodySize": 0,
                    },
                    "response": {
                        "status": 304,
                        "statusText": "Not Modified",
                        "httpVersion": "http/2.0",
                        "headers": [{"name": "content-type", "value": "text/css"}],
                        "cookies": [],
                        "content": {"size": 0, "mimeType": "text/css", "text": "body{}"},
                        "redirectURL": "",
                        "headersSize": 88,
                        "bodySize": 0,
                    },
                    "cache": {},
                    "timings": {"send": 0, "wait": 40, "receive": 2.5},
                    "_resourceType": "stylesheet",
                }
            ],
        }
    }
    assert read_har_entries(json.dumps(doc)) == [
        {
            "url": "https://ext.test/app.css?v=2",
            "method": "GET",
            "status": 304,
            "mimeType": "text/css",
            "resourceType": "stylesheet",
            "startedDateTime": "2026-08-28T06:00:00.000Z",
        }
    ]


def test_non_json_is_a_har_read_error() -> None:
    with pytest.raises(HarReadError):
        read_har_entries("<html>not json</html>")


@pytest.mark.parametrize(
    "bad",
    ["[]", '"a string"', "{}", '{"log": {}}', '{"log": {"entries": {}}}'],
)
def test_json_that_is_not_a_har_log_is_a_har_read_error(bad: str) -> None:
    with pytest.raises(HarReadError):
        read_har_entries(bad)


def test_a_har_with_no_entries_is_empty_not_an_error() -> None:
    assert read_har_entries('{"log": {"entries": []}}') == []


def test_a_malformed_entry_contributes_what_it_has_without_crashing() -> None:
    text = json.dumps(
        {
            "log": {
                "entries": [
                    "not-an-object",
                    {"request": {"url": "https://x.test/"}},
                    {"request": 5, "response": {"status": "oops"}},
                ]
            }
        }
    )
    summaries = read_har_entries(text)

    # The bare string is skipped; the two objects survive.
    assert len(summaries) == 2
    assert summaries[0]["url"] == "https://x.test/"
    assert summaries[0]["method"] == ""
    assert summaries[0]["status"] is None
    # A non-object request and a non-int status degrade to blanks, not a crash.
    assert summaries[1]["url"] == ""
    assert summaries[1]["status"] is None


# ---- WebBackend.read_har: session-independent file reader ------------------


def test_backend_reads_a_har_with_no_open_session(tmp_path: Path) -> None:
    path = _write_har(tmp_path, _entries(2))
    result = WebBackend().read_har(str(path))
    assert result["total"] == 2
    assert result["count"] == 2
    assert result["path"] == str(path.resolve()) or result["path"] == str(path)


def test_backend_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(WebError) as info:
        WebBackend().read_har(str(tmp_path / "nope.har"))
    assert info.value.code == "not_found"


def test_backend_non_har_is_invalid_params(tmp_path: Path) -> None:
    path = tmp_path / "bad.har"
    path.write_text("not json at all", encoding="utf-8")
    with pytest.raises(WebError) as info:
        WebBackend().read_har(str(path))
    assert info.value.code == "invalid_params"


def test_backend_over_the_cap_is_too_large_and_leaves_the_input_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_har(tmp_path, _entries(3))
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 10)
    with pytest.raises(WebError) as info:
        WebBackend().read_har(str(path))
    assert info.value.code == "too_large"
    assert info.value.details["max_file_size"] == 10
    # The caller owns this file -- unlike a capture we wrote, it is never deleted.
    assert path.is_file()


def test_backend_pages_with_offset_and_the_has_more_boundary(tmp_path: Path) -> None:
    path = _write_har(tmp_path, _entries(6))
    backend = WebBackend()

    first = backend.read_har(str(path), offset=0, limit=3)
    assert first["count"] == 3
    assert first["total"] == 6
    assert first["offset"] == 0
    assert first["has_more"] is True
    assert [e["url"] for e in first["entries"]] == [
        "https://a.test/0",
        "https://a.test/1",
        "https://a.test/2",
    ]

    # Last page exactly fills: 3 + 3 == 6 -> has_more False.
    last = backend.read_har(str(path), offset=3, limit=3)
    assert last["count"] == 3
    assert last["has_more"] is False
    # One row short of the end: 2 + 3 == 5 < 6 -> has_more True.
    short = backend.read_har(str(path), offset=2, limit=3)
    assert short["has_more"] is True


def test_backend_clamps_the_limit_to_the_page_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(web_client, "_MAX_PAGE", 2)
    path = _write_har(tmp_path, _entries(5))
    page = WebBackend().read_har(str(path), offset=0, limit=1000)
    assert page["count"] == 2
    assert page["has_more"] is True


def test_backend_clamps_a_negative_offset_and_zero_limit(tmp_path: Path) -> None:
    """The agent/bridge transports bypass the schema's ``offset >= 0`` /
    ``limit >= 1`` bound and call read_har directly, so it re-enforces both with
    ``max(0, offset)`` and ``max(1, min(limit, _MAX_PAGE))``. Without the clamp
    ``offset=-1`` would tail-slice ``entries[-1:...]`` -- a wrong page still
    claiming has_more, the same paging bug apk's _clamp_page fixed. network_list
    and scripts pin this; read_har shares the same defensive lines, so pin it too.
    """
    path = _write_har(tmp_path, _entries(6))
    page = WebBackend().read_har(str(path), offset=-10, limit=0)
    assert page["offset"] == 0
    assert page["count"] == 1
    assert page["has_more"] is True
    assert page["entries"][0]["url"] == "https://a.test/0"


# ---- AnalysisService.web_har_read: the mixin ------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_a_har_without_a_session(tmp_path: Path) -> None:
    path = _write_har(tmp_path, _entries(2))
    service = _service(tmp_path)
    try:
        result = service.web_har_read(str(path))
        assert result.ok is True
        assert result.data is not None
        assert result.data["total"] == 2
        assert result.data["count"] == 2
        # A path-based reader needs no session, so none rides in the envelope.
        assert "session_id" not in result.meta
    finally:
        service.close_all()


def test_service_maps_a_non_har_to_invalid_params(tmp_path: Path) -> None:
    path = tmp_path / "bad.har"
    path.write_text("{not a har}", encoding="utf-8")
    service = _service(tmp_path)
    try:
        result = service.web_har_read(str(path))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_both_har_exporters_point_at_the_reader(tmp_path: Path) -> None:
    """Discovery wiring: web.har.read reads a HAR that either exporter writes,
    but it lives in the web.* namespace, so a proxy user meets it only if the
    exporter description names it. A tool description is the agent's discovery
    surface, so pin the cross-reference from both exporters so it cannot rot."""
    from headless_re_mcp.tools.proxy import build_proxy_tools
    from headless_re_mcp.tools.web import build_web_tools

    service = _service(tmp_path)
    try:
        web = {binding.name: binding for binding in build_web_tools(service)}
        proxy = {binding.name: binding for binding in build_proxy_tools(service)}
        assert "web.har.read" in web
        for exporter in (web["web.har.export"], proxy["proxy.export_har"]):
            assert "web.har.read" in (exporter.handler.__doc__ or "")
    finally:
        service.close_all()


def test_the_docstring_names_every_field_read_har_actually_returns(tmp_path: Path) -> None:
    """The docstring is the agent's only map of a tool's answer shape, and last
    cycle's bug was exactly that -- the docstring promised a field spelling
    (mime_type) the backend did not return (mimeType). Tie the two together so
    they cannot desync again: every top-level key read_har returns, and every
    entry sub-key, must be named verbatim in the web.har.read docstring. Reading
    the keys off a live call rather than a hardcoded list keeps this honest if
    the backend grows or renames a field. Reverting the docstring to snake_case
    (or dropping a field from either side) turns this red."""
    from headless_re_mcp.tools.web import build_web_tools

    service = _service(tmp_path)
    try:
        doc = next(
            (b.handler.__doc__ or "" for b in build_web_tools(service) if b.name == "web.har.read"),
            "",
        )
    finally:
        service.close_all()
    assert doc, "web.har.read must describe itself"

    path = _write_har(
        tmp_path,
        [
            har_entry(
                method="GET",
                url="https://a.test/x",
                status=200,
                mime_type="text/html",
                resource_type="script",
            )
        ],
    )
    result = WebBackend().read_har(str(path))
    for key in result:
        assert key in doc, f"read_har returns {key!r} but the docstring never names it"
    for key in result["entries"][0]:
        assert key in doc, f"read_har entries carry {key!r} but the docstring never names it"
