"""The offline HAR reader (summarize_har) and its web.har.inspect routing.

The two exporters could write a HAR that nothing here could read back: an
analyst holding a .har -- from this tool, Chrome DevTools, or mitmproxy -- had
no offline way to ask what hosts it talked to or what failed without standing a
browser or proxy back up. summarize_har closes that round trip with the stdlib
alone. These tests pin the summary shape, the filters, the whole-log honesty of
its counts and host histogram, its refusal of non-HAR input, and the service
routing that turns a bad file into a precise envelope rather than a fault.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.har import HarParseError, summarize_har
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _entry(
    method: str,
    url: str,
    status: int,
    mime: str,
    *,
    size: int = 123,
    resource_type: str | None = None,
) -> dict:
    entry: dict = {
        "startedDateTime": "2026-08-28T00:00:00Z",
        "time": 1,
        "request": {"method": method, "url": url},
        "response": {"status": status, "content": {"size": size, "mimeType": mime}},
        "cache": {},
        "timings": {"send": -1, "wait": -1, "receive": -1},
    }
    if resource_type:
        entry["_resourceType"] = resource_type
    return entry


def _document() -> dict:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "chrome", "version": "120"},
            "entries": [
                _entry(
                    "GET",
                    "https://api.example.com/v1/users?id=1",
                    200,
                    "application/json",
                    resource_type="xhr",
                ),
                _entry("POST", "https://api.example.com/v1/login", 403, "application/json"),
                _entry("GET", "https://cdn.example.com/app.js", 200, "application/javascript"),
                _entry("GET", "https://cdn.example.com/style.css", 200, "text/css"),
                _entry("GET", "https://tracker.ads.net/pixel.gif", 404, "image/gif"),
            ],
        }
    }


def test_full_summary_carries_the_analyst_facing_fields() -> None:
    out = summarize_har(_document())
    assert out["version"] == "1.2"
    assert out["creator"] == {"name": "chrome", "version": "120"}
    assert out["total"] == 5
    assert out["entries_total"] == 5
    assert out["count"] == 5
    assert out["has_more"] is False
    first = out["entries"][0]
    assert first["method"] == "GET"
    assert first["url"] == "https://api.example.com/v1/users?id=1"
    assert first["host"] == "api.example.com"
    assert first["status"] == 200
    assert first["mime_type"] == "application/json"
    assert first["response_size"] == 123
    assert first["resource_type"] == "xhr"


def test_host_histogram_describes_the_whole_log_not_the_page() -> None:
    # A page of two must still report every host and the full per-host counts,
    # the same honesty the paginated capture listings keep.
    out = summarize_har(_document(), offset=0, limit=2)
    assert out["count"] == 2
    assert out["total"] == 5
    assert out["has_more"] is True
    assert out["hosts"] == {
        "api.example.com": 2,
        "cdn.example.com": 2,
        "tracker.ads.net": 1,
    }
    assert out["distinct_hosts"] == 3
    assert out["hosts_truncated"] is False


def test_host_filter_is_exact_and_counts_the_filtered_set() -> None:
    out = summarize_har(_document(), host="cdn.example.com")
    assert out["total"] == 2
    assert {e["url"] for e in out["entries"]} == {
        "https://cdn.example.com/app.js",
        "https://cdn.example.com/style.css",
    }
    assert out["hosts"] == {"cdn.example.com": 2}
    assert out["filters"]["host"] == "cdn.example.com"


def test_method_filter_is_case_insensitive() -> None:
    out = summarize_har(_document(), method="post")
    assert out["total"] == 1
    assert out["entries"][0]["url"] == "https://api.example.com/v1/login"


def test_status_filter_is_exact() -> None:
    out = summarize_har(_document(), status=404)
    assert out["total"] == 1
    assert out["entries"][0]["url"] == "https://tracker.ads.net/pixel.gif"


def test_pagination_windows_the_filtered_stream() -> None:
    out = summarize_har(_document(), offset=2, limit=2)
    assert out["offset"] == 2
    assert out["limit"] == 2
    assert out["count"] == 2
    assert out["total"] == 5
    assert out["has_more"] is True
    # offset past the end is an empty page, not an error.
    tail = summarize_har(_document(), offset=99, limit=10)
    assert tail["count"] == 0
    assert tail["total"] == 5
    assert tail["has_more"] is False


def test_missing_and_wrong_typed_members_do_not_raise() -> None:
    doc = {
        "log": {
            "entries": [
                {},  # no request/response at all
                {"request": "not-a-dict", "response": {"status": "nope"}},
                _entry("GET", "https://ok.example/x", 200, "text/html"),
            ]
        }
    }
    out = summarize_har(doc)
    assert out["entries_total"] == 3
    assert out["total"] == 3
    empty = out["entries"][0]
    assert empty["method"] == "" and empty["url"] == "" and empty["status"] is None
    # A non-int status string collapses to None rather than crashing.
    assert out["entries"][1]["status"] is None


def test_oversized_fields_are_bounded() -> None:
    huge = "h" * 20000
    doc = {"log": {"entries": [_entry("GET", "https://x/" + huge, 200, "t/" + huge)]}}
    out = summarize_har(doc)
    entry = out["entries"][0]
    assert len(entry["url"]) == 8000
    assert len(entry["mime_type"]) == 8000


def test_a_bare_log_object_is_tolerated() -> None:
    # Some callers unwrap one level; a bare log with entries still reads.
    out = summarize_har({"version": "1.2", "entries": []})
    assert out["total"] == 0
    assert out["entries_total"] == 0


@pytest.mark.parametrize(
    "document",
    [
        "a string",
        123,
        {"not_log": {}},
        {"log": "not-a-dict"},
        {"log": {"entries": "not-a-list"}},
        {"log": {}},
    ],
)
def test_non_har_documents_raise_harparseerror(document: object) -> None:
    with pytest.raises(HarParseError):
        summarize_har(document)


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_a_har_session(tmp_path: Path) -> None:
    har = tmp_path / "capture.har"
    har.write_text(json.dumps(_document()), encoding="utf-8")
    service = _service(tmp_path)
    session = service.registry.create(har)
    result = service.web_har_inspect(session.id)
    assert result.ok, result.model_dump(mode="json")
    assert result.data["total"] == 5


def test_service_refuses_a_non_har_file(tmp_path: Path) -> None:
    junk = tmp_path / "capture.har"
    junk.write_text("<<not json>>", encoding="utf-8")
    service = _service(tmp_path)
    session = service.registry.create(junk)
    result = service.web_har_inspect(session.id)
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_refuses_a_url_session_as_target_mismatch(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session = service.registry.create("https://example.com/app")
    assert session.binary is None
    result = service.web_har_inspect(session.id)
    assert not result.ok
    assert result.error.code == "target_mismatch"


def test_service_refuses_an_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.core.service_web as service_web

    monkeypatch.setattr(service_web, "HAR_INSPECT_MAX_BYTES", 16)
    har = tmp_path / "capture.har"
    har.write_text(json.dumps(_document()), encoding="utf-8")
    service = _service(tmp_path)
    session = service.registry.create(har)
    result = service.web_har_inspect(session.id)
    assert not result.ok
    assert result.error.code == "too_large"
