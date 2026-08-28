"""proxy tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOWS,
    ProxyBackend,
    _FlowRecorder,
)
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_proxy_flows_puts_the_page_in_flows_with_content_type(
    monkeypatch: Any,
) -> None:
    """The catalog said content type and never named the list field.

    Measured: 25 held, limit 10 -> count 10, total 25, field is flows not
    items or requests, and each row carries content_type with no
    'content type' key. Looking for those after a successful call reads as
    an empty capture, and a full page with no total reads as the whole log.
    """
    recorder = _FlowRecorder(capacity=50)
    for index in range(25):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    payload = backend.flows("s", offset=0, limit=10)
    assert "items" not in payload
    assert "requests" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["flows"]) == 10
    row = payload["flows"][0]
    assert "content type" not in row
    assert row["content_type"] == "text/plain"
    normalized = backend.flows("s", offset=-10, limit=0)
    assert normalized["offset"] == 0
    assert normalized["count"] == 1
    assert normalized["has_more"] is True
    doc = _tool_docstring("proxy.flows")
    assert "Answers with flows" in doc
    assert "content_type" in doc
    assert "total" in doc
    assert "body_omitted" in doc
    assert "metadata_truncated" in doc


def test_proxy_flows_names_has_more_and_dropped(monkeypatch: Any) -> None:
    """The catalog named the page and never said when the ring had already lost rows.

    Measured: capacity 5, 12 responses, limit 3 -> count 3, total 5, has_more
    True, dropped 7. Looking at a full page with no has_more reads as the
    whole capture; looking with no dropped reads as nothing evicted.
    """
    recorder = _FlowRecorder(capacity=5)
    for index in range(12):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    payload = backend.flows("s", offset=0, limit=3)
    assert payload["count"] == 3
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["dropped"] == 7
    assert len(payload["flows"]) == 3
    doc = _tool_docstring("proxy.flows")
    assert "has_more" in doc
    assert "dropped" in doc


def _record(recorder: _FlowRecorder, *, method: str, url: str, host: str, status: int, ctype: str,
            flow_id: str) -> None:
    request = SimpleNamespace(method=method, pretty_url=url, host=host)
    response = SimpleNamespace(status_code=status, headers={"content-type": ctype})
    recorder.response(SimpleNamespace(id=flow_id, request=request, response=response))


def _filterable_backend(monkeypatch: Any) -> ProxyBackend:
    recorder = _FlowRecorder(capacity=50)
    _record(recorder, method="GET", url="http://api.example.com/users", host="api.example.com",
            status=200, ctype="application/json", flow_id="a")
    _record(recorder, method="POST", url="http://api.example.com/login", host="api.example.com",
            status=401, ctype="application/json", flow_id="b")
    _record(recorder, method="GET", url="http://cdn.other.com/app.js", host="cdn.other.com",
            status=200, ctype="application/javascript", flow_id="c")
    _record(recorder, method="GET", url="http://api.example.com/health", host="api.example.com",
            status=500, ctype="text/plain", flow_id="d")
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_proxy_flows_filters_narrow_the_log(monkeypatch: Any) -> None:
    """A busy capture must be narrowable server-side, not only paged.

    method is an exact verb, host/url_contains/content_type are case-insensitive
    substrings, status is exact, and filters AND together. total becomes the
    match count while captured stays the whole ring, so a narrow result is never
    read as a small capture.
    """
    backend = _filterable_backend(monkeypatch)

    # No filter: total == captured, and no filter key is echoed.
    plain = backend.flows("s")
    assert plain["total"] == 4
    assert plain["captured"] == 4
    assert "filter" not in plain

    # Exact verb.
    posts = backend.flows("s", method="post")
    assert posts["total"] == 1
    assert posts["captured"] == 4
    assert [row["method"] for row in posts["flows"]] == ["POST"]
    # The echoed filter is normalised to the case the match used.
    assert posts["filter"] == {"method": "POST"}

    # Host substring, case-insensitive.
    api = backend.flows("s", host="API.example.com")
    assert api["total"] == 3
    assert all("api.example.com" in row["host"] for row in api["flows"])
    assert api["filter"] == {"host": "api.example.com"}

    cdn = backend.flows("s", host="cdn")
    assert cdn["total"] == 1
    assert cdn["flows"][0]["id"] == "c"

    # Content-type substring.
    json_flows = backend.flows("s", content_type="json")
    assert json_flows["total"] == 2
    assert {row["id"] for row in json_flows["flows"]} == {"a", "b"}

    # URL substring.
    login = backend.flows("s", url_contains="/LOGIN")
    assert login["total"] == 1
    assert login["flows"][0]["id"] == "b"

    # Exact status; 0 means any.
    ok = backend.flows("s", status=200)
    assert ok["total"] == 2
    assert {row["id"] for row in ok["flows"]} == {"a", "c"}
    assert backend.flows("s", status=0)["total"] == 4

    # Filters combine with AND.
    get_json = backend.flows("s", method="GET", content_type="json")
    assert get_json["total"] == 1
    assert get_json["flows"][0]["id"] == "a"
    assert get_json["filter"] == {"method": "GET", "content_type": "json"}

    # A filter that matches nothing is a clean empty page, not the whole log.
    none = backend.flows("s", host="nonexistent.invalid")
    assert none["total"] == 0
    assert none["count"] == 0
    assert none["flows"] == []
    assert none["captured"] == 4


def test_proxy_flows_filter_paginates_over_matches(monkeypatch: Any) -> None:
    """offset/limit page the filtered set, and has_more reflects the matches."""
    recorder = _FlowRecorder(capacity=50)
    for index in range(10):
        # Even ids are POST, odd are GET; page over the five POSTs.
        _record(recorder, method="POST" if index % 2 == 0 else "GET",
                url=f"http://x/{index}", host="x", status=200, ctype="text/plain",
                flow_id=str(index))
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))

    first = backend.flows("s", method="POST", offset=0, limit=3)
    assert first["total"] == 5
    assert first["count"] == 3
    assert first["has_more"] is True
    second = backend.flows("s", method="POST", offset=3, limit=3)
    assert second["count"] == 2
    assert second["has_more"] is False


def test_proxy_flows_docstring_names_the_filter_fields() -> None:
    doc = _tool_docstring("proxy.flows")
    for token in ("captured", "url_contains", "content_type", "status", "filter"):
        assert token in doc, token


def test_proxy_stats_aggregates_the_capture(monkeypatch: Any) -> None:
    """proxy.stats must profile the ring across every triage dimension."""
    backend = _filterable_backend(monkeypatch)

    stats = backend.stats("s")

    assert stats["captured"] == 4
    assert stats["total"] == 4
    assert stats["dropped"] == 0
    assert stats["methods"] == {"GET": 3, "POST": 1}
    assert stats["status_classes"] == {"2xx": 2, "4xx": 1, "5xx": 1}
    # Ranked count-desc, ties broken by key asc.
    assert stats["statuses"] == [
        {"status": 200, "count": 2},
        {"status": 401, "count": 1},
        {"status": 500, "count": 1},
    ]
    assert stats["hosts"] == [
        {"host": "api.example.com", "count": 3},
        {"host": "cdn.other.com", "count": 1},
    ]
    assert stats["content_types"] == [
        {"content_type": "application/json", "count": 2},
        {"content_type": "application/javascript", "count": 1},
        {"content_type": "text/plain", "count": 1},
    ]
    assert stats["websocket_flows"] == 0
    assert stats["body_omitted"] == 0
    assert "filter" not in stats


def test_proxy_stats_respects_the_flow_filters(monkeypatch: Any) -> None:
    """The same filter surface as proxy.flows profiles just one slice."""
    backend = _filterable_backend(monkeypatch)

    api = backend.stats("s", host="api.example.com")

    assert api["captured"] == 4  # the whole ring is still disclosed
    assert api["total"] == 3  # but only the matching subset is counted
    assert api["methods"] == {"GET": 2, "POST": 1}
    assert api["status_classes"] == {"2xx": 1, "4xx": 1, "5xx": 1}
    assert api["hosts"] == [{"host": "api.example.com", "count": 3}]
    assert api["filter"] == {"host": "api.example.com"}


def test_proxy_stats_normalises_content_type_charset(monkeypatch: Any) -> None:
    """A charset parameter must not split one media type into two groups."""
    recorder = _FlowRecorder(capacity=50)
    _record(recorder, method="GET", url="http://x/1", host="x", status=200,
            ctype="application/json; charset=utf-8", flow_id="1")
    _record(recorder, method="GET", url="http://x/2", host="x", status=200,
            ctype="application/json", flow_id="2")
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))

    stats = backend.stats("s")
    assert stats["content_types"] == [{"content_type": "application/json", "count": 2}]


def test_proxy_stats_ranks_and_caps_unbounded_dimensions(monkeypatch: Any) -> None:
    """A capture of many hosts must cap the ranked list and disclose it."""
    monkeypatch.setattr(proxy_client, "_MAX_STATS_GROUPS", 2)
    recorder = _FlowRecorder(capacity=50)
    # host "a" gets 3 flows, "b" gets 2, "c" gets 1 -- the top two survive the cap.
    for host, hits in (("a", 3), ("b", 2), ("c", 1)):
        for index in range(hits):
            _record(recorder, method="GET", url=f"http://{host}/{index}", host=host,
                    status=200, ctype="text/plain", flow_id=f"{host}{index}")
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))

    stats = backend.stats("s")
    assert stats["hosts"] == [
        {"host": "a", "count": 3},
        {"host": "b", "count": 2},
    ]
    assert stats["hosts_truncated"] is True


def test_proxy_stats_docstring_names_the_fields() -> None:
    doc = _tool_docstring("proxy.stats")
    for token in ("methods", "status_classes", "hosts", "content_types", "captured"):
        assert token in doc, token


def test_proxy_flow_get_names_body_path_on_the_response(tmp_path: Path, monkeypatch: Any) -> None:
    """The catalog said headers and body, never where a spill actually lands.

    Measured: 200001-byte body -> no top-level body or headers, response.size
    200001, response.body_path set, response.body absent. Looking for body
    after a successful large fetch reads as a missing capture.
    """
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/1", headers={"accept": "text/plain"}
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain"},
        raw_content=b"x" * 200_001,
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    payload = backend.flow_get("s", "f1", tmp_path)
    repeated = backend.flow_get("s", "f1", tmp_path)
    hostile = backend.flow_get("s", "../../escaped", tmp_path)
    assert "body" not in payload
    assert "headers" not in payload
    assert "body" not in payload["response"]
    assert payload["response"]["size"] == 200_001
    paths = [
        Path(str(item["response"]["body_path"]))
        for item in (payload, repeated, hostile)
    ]
    assert len(set(paths)) == 3
    assert all(path.parent == tmp_path for path in paths)
    assert all(path.name.startswith("flow-") and path.suffix == ".bin" for path in paths)
    assert all(path.is_file() for path in paths)
    assert not (tmp_path.parent / "escaped.bin").exists()
    doc = _tool_docstring("proxy.flow.get")
    assert "body_path" in doc
    assert "response" in doc


def test_proxy_flow_get_spills_a_small_binary_body_as_real_bytes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A small binary body must spill to a file, not mangle into inline text.

    A captured .wasm (well under the 200 KB inline cap) used to come back inline
    -- useless for the very static tools a proxy capture exists to feed. The
    subtle case is a module whose bytes are all in the ASCII range, so a strict
    utf-8 decode wrongly accepts it as text; the NUL byte a real module carries
    is what marks it binary. Measured: a WASM header (all bytes <= 0x7f, with
    NULs) plus some high bytes -> response.body absent, response.body_path set,
    and the file holds the exact bytes (magic intact).
    """
    # Deliberately all-low-byte-with-NUL like a real wasm header: every byte is
    # <= 0x7f, so a strict-utf-8-only check would inline it; it spills purely
    # because of the NUL sniff, which is exactly the case that regressed.
    wasm = b"\x00asm\x01\x00\x00\x00\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f"
    assert all(b <= 0x7F for b in wasm) and b"\x00" in wasm
    assert len(wasm) < 200_000
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/m.wasm", headers={"accept": "*/*"}
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/wasm"},
        raw_content=wasm,
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    payload = backend.flow_get("s", "f1", tmp_path)
    assert "body" not in payload["response"], payload["response"]
    body_path = Path(str(payload["response"]["body_path"]))
    assert body_path.is_file()
    assert body_path.read_bytes() == wasm
    assert payload["response"]["size"] == len(wasm)


def test_proxy_flow_get_still_inlines_a_small_text_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A small text body must still inline as response.body, not spill.

    The binary-spill guard must not sweep up ordinary text: a short UTF-8 body
    stays inline (that is what callers read for a captured JSON/HTML response),
    so only genuinely binary or oversized bodies land on disk.
    """
    text = "hello-\u00e9\u4e2d\u6587-9449"  # multi-byte but valid UTF-8
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/p", headers={"accept": "text/plain"}
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain; charset=utf-8"},
        raw_content=text.encode("utf-8"),
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    payload = backend.flow_get("s", "f1", tmp_path)
    assert "body_path" not in payload["response"], payload["response"]
    assert payload["response"]["body"] == text


def test_proxy_status_names_flow_count_and_retained_max() -> None:
    """The catalog said how many flows and never named the count field.

    Measured: 3 retained -> running True, flow_count 3, retained_max 2000,
    no count or flows key. Looking for count after a successful status
    reads as a proxy that captured nothing.
    """
    recorder = _FlowRecorder(capacity=8)
    for index in range(3):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(
        host="127.0.0.1", port=8080, recorder=recorder
    )
    payload = backend.status("s")
    assert "count" not in payload
    assert "flows" not in payload
    assert payload["running"] is True
    assert payload["flow_count"] == 3
    assert payload["retained_max"] == _MAX_FLOWS
    assert payload["retained_bytes"] >= 0
    assert payload["retained_bytes_max"] > payload["retained_bytes"]
    idle = backend.status("missing")
    assert idle == {"running": False}
    doc = _tool_docstring("proxy.status")
    assert "flow_count" in doc
    assert "retained_max" in doc
    assert "retained_bytes" in doc
    assert "retained_bytes_max" in doc


def test_proxy_export_har_names_path_and_entry_count(
    tmp_path: Path,
) -> None:
    """The catalog said a HAR artifact and never named the payload.

    Measured: 4 flows -> path ending capture.har, entry_count 4, no har or
    output key. Looking for har after a successful export reads as a missing
    capture.
    """
    recorder = _FlowRecorder()
    for index in range(4):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert "har" not in payload
    assert "output" not in payload
    assert payload["entry_count"] == 4
    assert payload["captured"] == 4
    assert "filter" not in payload
    assert payload["path"].endswith("capture.har")
    doc = _tool_docstring("proxy.export_har")
    assert "path" in doc
    assert "entry_count" in doc


def test_proxy_export_har_filters_the_exported_subset(tmp_path: Path, monkeypatch: Any) -> None:
    """The same filters as proxy.flows must narrow what HAR export writes.

    entry_count becomes the matching-flow count, captured stays the whole ring
    (so entry_count reads as N of M), and the echoed filter records what was
    applied. The written HAR must contain exactly the matching entries.
    """
    import json as _json

    backend = _filterable_backend(monkeypatch)

    out = tmp_path / "posts.har"
    payload = backend.export_har("s", out, method="post")
    assert payload["entry_count"] == 1
    assert payload["captured"] == 4
    assert payload["filter"] == {"method": "POST"}
    doc = _json.loads(out.read_text(encoding="utf-8"))
    urls = [e["request"]["url"] for e in doc["log"]["entries"]]
    assert len(urls) == 1
    assert urls[0].endswith("/login")

    # A substring filter over host, and an AND combination, each narrow the file.
    host_out = tmp_path / "api.har"
    host_payload = backend.export_har("s", host_out, host="api.example.com")
    assert host_payload["entry_count"] == 3
    assert host_payload["captured"] == 4

    # A filter matching nothing writes a valid, empty HAR -- not the whole log.
    empty_out = tmp_path / "none.har"
    empty_payload = backend.export_har("s", empty_out, host="nonexistent.invalid")
    assert empty_payload["entry_count"] == 0
    assert empty_payload["captured"] == 4
    empty_doc = _json.loads(empty_out.read_text(encoding="utf-8"))
    assert empty_doc["log"]["entries"] == []


def test_proxy_export_har_docstring_names_the_filter_fields() -> None:
    doc = _tool_docstring("proxy.export_har")
    for token in ("captured", "filter", "url_contains", "content_type", "status"):
        assert token in doc, token
