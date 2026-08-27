"""proxy tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOWS,
    _MAX_WS_STORED_MSG,
    _MITM_WS_TAIL,
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


def test_proxy_flows_filters_the_capture_before_paginating(monkeypatch: Any) -> None:
    """A large capture had to be paged by hand to find one request.

    Drive the method/host/url_contains/status filters and assert each narrows
    the set before pagination, that they combine, that total describes the match
    while unfiltered_total keeps the whole capture's size visible, and that an
    unfiltered call still omits the filtered/unfiltered_total keys.
    """
    recorder = _FlowRecorder(capacity=50)

    def add(fid: str, method: str, url: str, host: str, status: int) -> None:
        request = SimpleNamespace(method=method, pretty_url=url, host=host)
        response = SimpleNamespace(status_code=status, headers={"content-type": "text/plain"})
        recorder.response(SimpleNamespace(id=fid, request=request, response=response))

    add("1", "GET", "http://api.example.com/users", "api.example.com", 200)
    add("2", "POST", "http://api.example.com/login", "api.example.com", 401)
    add("3", "GET", "http://cdn.other.com/app.js", "cdn.other.com", 200)
    add("4", "POST", "http://api.example.com/users", "api.example.com", 500)

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )

    posts = backend.flows("s", method="post")  # exact, case-insensitive
    assert {row["id"] for row in posts["flows"]} == {"2", "4"}
    assert posts["filtered"] is True
    assert posts["total"] == 2
    assert posts["unfiltered_total"] == 4

    host_hits = backend.flows("s", host="EXAMPLE.com")  # substring, case-insensitive
    assert {row["id"] for row in host_hits["flows"]} == {"1", "2", "4"}

    users = backend.flows("s", url_contains="/users")
    assert {row["id"] for row in users["flows"]} == {"1", "4"}

    err = backend.flows("s", status=500)
    assert {row["id"] for row in err["flows"]} == {"4"}

    combined = backend.flows("s", method="GET", host="example.com")
    assert {row["id"] for row in combined["flows"]} == {"1"}

    plain = backend.flows("s")
    assert "filtered" not in plain
    assert "unfiltered_total" not in plain
    assert plain["total"] == 4

    doc = _tool_docstring("proxy.flows")
    assert "url_contains" in doc
    assert "unfiltered_total" in doc


def test_proxy_flows_status_filter_skips_a_failed_flow(monkeypatch: Any) -> None:
    """A status filter must not match a flow that has no status yet.

    A failed or in-flight request carries a null status; treating null as "any"
    would surface it under every status query. Assert a status filter excludes
    the failed flow while a method filter still finds it.
    """
    recorder = _FlowRecorder(capacity=10)
    ok_req = SimpleNamespace(method="GET", pretty_url="http://x/ok", host="x")
    recorder.response(
        SimpleNamespace(
            id="ok",
            request=ok_req,
            response=SimpleNamespace(status_code=200, headers={"content-type": "text/plain"}),
        )
    )
    dead_req = SimpleNamespace(method="GET", pretty_url="http://x/dead", host="x", headers={})
    recorder.error(
        SimpleNamespace(
            id="dead", request=dead_req, response=None,
            error=SimpleNamespace(msg="connection refused"),
        )
    )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )

    by_status = backend.flows("s", status=200)
    assert {row["id"] for row in by_status["flows"]} == {"ok"}

    by_method = backend.flows("s", method="GET")
    assert {row["id"] for row in by_method["flows"]} == {"ok", "dead"}


def test_proxy_flows_flags_a_request_that_carried_a_body(monkeypatch: Any) -> None:
    """A scan of the list should reveal which flows have a request payload.

    Measured: a GET summary has no has_request_body key, while a flow whose
    request carried raw_content is flagged has_request_body True. Without the
    flag, finding the POST worth fetching means opening every flow in turn.
    """
    recorder = _FlowRecorder(capacity=10)
    get_req = SimpleNamespace(method="GET", pretty_url="http://x/get", host="x")
    post_req = SimpleNamespace(
        method="POST",
        pretty_url="http://x/login",
        host="x",
        raw_content=b'{"user":"alice"}',
    )
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    recorder.response(SimpleNamespace(id="g", request=get_req, response=response))
    recorder.response(SimpleNamespace(id="p", request=post_req, response=response))

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    rows = {row["id"]: row for row in backend.flows("s")["flows"]}
    assert "has_request_body" not in rows["g"]
    assert rows["p"]["has_request_body"] is True
    doc = _tool_docstring("proxy.flows")
    assert "has_request_body" in doc


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

        def websocket(self, flow_id: str) -> Any:
            return None

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


def test_proxy_flow_get_returns_the_request_body(tmp_path: Path, monkeypatch: Any) -> None:
    """The request payload used to be dropped, leaving only the response.

    Measured: a POST body under the cap comes back as request.body with
    request.size, alongside the response body; a body over the cap spills to
    request.body_path with no request.body. Looking for the POSTed credentials
    or JSON after a capture used to read as a flow that never carried them.
    """
    small = b'{"user":"alice","pass":"s3cr3t"}'
    request = SimpleNamespace(
        method="POST",
        pretty_url="http://x/login",
        headers={"content-type": "application/json"},
        raw_content=small,
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/json"},
        raw_content=b'{"ok":true}',
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

        def websocket(self, flow_id: str) -> Any:
            return None

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["request"]["body"] == small.decode()
    assert payload["request"]["size"] == len(small)
    assert "body_path" not in payload["request"]
    assert payload["response"]["body"] == '{"ok":true}'

    request.raw_content = b"P" * 200_001
    spilled = backend.flow_get("s", "f1", tmp_path)
    assert "body" not in spilled["request"]
    assert spilled["request"]["size"] == 200_001
    body_path = Path(str(spilled["request"]["body_path"]))
    assert body_path.parent == tmp_path
    assert body_path.name.startswith("flow-req-") and body_path.suffix == ".bin"
    assert body_path.read_bytes() == request.raw_content
    doc = _tool_docstring("proxy.flow.get")
    assert "request body" in doc


def test_proxy_flow_get_decodes_a_gzip_response_body(tmp_path: Path, monkeypatch: Any) -> None:
    """A gzip'd response must come back as the payload, not compressed bytes.

    flow.get used to hand back raw_content, so a gzip/br/deflate/zstd API
    response read as binary garbage. Driven with a real mitmproxy Response
    whose raw body is gzip: the returned body is the decoded JSON, size is the
    decoded length, and content_encoding names the wire encoding.
    """
    from mitmproxy.http import Request, Response

    payload = b'{"token":"s3cr3t","items":[1,2,3]}'
    request = Request.make("GET", "http://x/api", b"", {})
    response = Response.make(
        200,
        payload,
        {"Content-Encoding": "gzip", "Content-Type": "application/json"},
    )
    # Sanity: the wire body really is compressed and not the plaintext.
    assert response.raw_content[:2] == b"\x1f\x8b"
    assert response.raw_content != payload
    flow = SimpleNamespace(request=request, response=response, error=None)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

        def websocket(self, flow_id: str) -> Any:
            return None

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    result = backend.flow_get("s", "f1", tmp_path)
    assert result["response"]["body"] == payload.decode()
    assert result["response"]["size"] == len(payload)
    assert result["response"]["size"] != len(response.raw_content)
    assert result["response"]["content_encoding"] == "gzip"
    # A plaintext request carries no content_encoding key.
    assert "content_encoding" not in result["request"]
    # Guard against re-compressing the file when a decoded body spills.
    big = b'{"k":"' + b"a" * 400_000 + b'"}'
    response.set_content(big)
    response.headers["Content-Encoding"] = "gzip"
    assert response.raw_content[:2] == b"\x1f\x8b"
    spilled = backend.flow_get("s", "f1", tmp_path)
    assert "body" not in spilled["response"]
    assert Path(str(spilled["response"]["body_path"])).read_bytes() == big
    assert spilled["response"]["size"] == len(big)

    doc = _tool_docstring("proxy.flow.get")
    assert "content_encoding" in doc


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
    assert payload["path"].endswith("capture.har")
    doc = _tool_docstring("proxy.export_har")
    assert "path" in doc
    assert "entry_count" in doc


def test_proxy_export_har_emits_conformant_har_1_2(tmp_path: Path) -> None:
    """The HAR entries must be valid HAR 1.2, not a bare method/url stub.

    A HAR whose entries omit startedDateTime/timings/headers/queryString is
    rejected by DevTools Import HAR and har-validator. Record a flow whose
    request carries an auth header and a query string and whose response
    carries a content-type, then assert the exported entry has the conformant
    shape: request/response header arrays (carrying those values), the parsed
    query string, per-flow start time and timings, status and a non-negative
    content size.
    """
    import json

    recorder = _FlowRecorder()
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://api.example/v1/items?page=2&q=secret",
        host="api.example",
        headers={"Authorization": "Bearer tok123", "Accept": "application/json"},
        http_version="HTTP/1.1",
        timestamp_start=1_700_000_000.0,
    )
    response = SimpleNamespace(
        status_code=200,
        reason="OK",
        headers={"content-type": "application/json"},
        http_version="HTTP/1.1",
        timestamp_start=1_700_000_000.0,
        timestamp_end=1_700_000_000.25,
    )
    recorder.response(SimpleNamespace(id="f1", request=request, response=response))
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)

    out = tmp_path / "capture.har"
    payload = backend.export_har("s", out)
    assert payload["entry_count"] == 1
    assert payload["truncated"] is False
    assert payload["size"] > 0

    log = json.loads(out.read_text(encoding="utf-8"))["log"]
    assert log["version"] == "1.2"
    entry = log["entries"][0]

    # startedDateTime is an ISO stamp; timings are present and non-negative.
    assert entry["startedDateTime"].startswith("20")
    assert entry["time"] >= 0
    assert set(entry["timings"]) == {"send", "wait", "receive"}
    assert entry["timings"]["wait"] >= 0
    assert entry["cache"] == {}

    req = entry["request"]
    assert req["method"] == "GET"
    assert req["httpVersion"] == "HTTP/1.1"
    assert {"name": "Authorization", "value": "Bearer tok123"} in req["headers"]
    # The query string must be parsed into HAR name/value pairs.
    assert {"name": "page", "value": "2"} in req["queryString"]
    assert {"name": "q", "value": "secret"} in req["queryString"]

    resp = entry["response"]
    assert resp["status"] == 200
    assert resp["statusText"] == "OK"
    assert {"name": "content-type", "value": "application/json"} in resp["headers"]
    assert resp["content"]["mimeType"] == "application/json"
    assert isinstance(resp["content"]["size"], int)


def test_proxy_export_har_marks_a_failed_flow(tmp_path: Path) -> None:
    """A failed upstream flow must be exported with status 0 and an _error note.

    An errored flow has a request but no response; dropping it would make the
    HAR look like the request was never attempted. Record a failed flow and
    assert the entry carries status 0 and the failure message.
    """
    import json

    recorder = _FlowRecorder()
    request = SimpleNamespace(method="GET", pretty_url="http://down.example/x", host="down.example")
    error = SimpleNamespace(msg="connection refused")
    recorder.error(SimpleNamespace(id="bad", request=request, error=error))
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)

    out = tmp_path / "failed.har"
    backend.export_har("s", out)
    entry = json.loads(out.read_text(encoding="utf-8"))["log"]["entries"][0]
    assert entry["response"]["status"] == 0
    assert entry["response"]["_error"] == "connection refused"


def _ws_flow(flow_id: str, messages: list[Any]) -> Any:
    return SimpleNamespace(id=flow_id, websocket=SimpleNamespace(messages=messages))


def test_proxy_records_websocket_frames_and_flags_the_flow() -> None:
    """websocket_message must capture frames, flag the flow, and stay bounded.

    Feed a handshake, then frames the way mitmproxy delivers them (the newest on
    flow.websocket.messages), and assert the recorder stores direction/size/text,
    flags the summary is_websocket with a running count, truncates an oversized
    frame, and trims mitmproxy's own ever-growing list to a short tail.
    """
    recorder = _FlowRecorder(capacity=10)
    handshake = SimpleNamespace(status_code=101, headers={"content-type": ""})
    request = SimpleNamespace(method="GET", pretty_url="http://x/socket", host="x")
    recorder.response(SimpleNamespace(id="ws", request=request, response=handshake))

    messages: list[Any] = []
    messages.append(SimpleNamespace(from_client=True, content=b'{"cmd":"hi"}'))
    recorder.websocket_message(_ws_flow("ws", messages))
    messages.append(SimpleNamespace(from_client=False, content=b"pong"))
    recorder.websocket_message(_ws_flow("ws", messages))
    # An oversized binary frame must be truncated and marked, not stored whole.
    messages.append(SimpleNamespace(from_client=True, content=b"\xff" * (_MAX_WS_STORED_MSG + 50)))
    recorder.websocket_message(_ws_flow("ws", messages))

    captured = recorder.websocket("ws")
    assert captured is not None
    assert captured["message_count"] == 3
    assert captured["returned"] == 3
    first = captured["messages"][0]
    assert first["from_client"] is True
    assert first["text"] == '{"cmd":"hi"}'
    assert first["size"] == len(b'{"cmd":"hi"}')
    big = captured["messages"][2]
    assert big["truncated"] is True
    assert big["binary"] is True
    assert big["size"] == _MAX_WS_STORED_MSG + 50

    summary = next(f for f in recorder.snapshot() if f["id"] == "ws")
    assert summary["is_websocket"] is True
    assert summary["websocket_messages"] == 3

    # mitmproxy keeps every frame forever; the recorder must trim the shared list.
    assert len(messages) <= _MITM_WS_TAIL

    # A non-WebSocket flow has no websocket payload.
    assert recorder.websocket("missing") is None
    doc = _tool_docstring("proxy.flow.get")
    assert "websocket" in doc


def test_proxy_error_records_a_failed_flow_that_never_got_a_response(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A flow whose upstream fails must be recorded, not silently dropped.

    mitmproxy delivers such flows through the error hook, never response, so
    without it the capture is empty even though a request was attempted. Drive
    error() and assert the flow is listed failed with the message and a null
    status, is retrievable, and that an error following a real response only
    annotates the existing row instead of adding a second.
    """
    recorder = _FlowRecorder(capacity=10)
    request = SimpleNamespace(method="GET", pretty_url="http://x/dead", host="x", headers={})
    flow = SimpleNamespace(
        id="e", request=request, response=None, error=SimpleNamespace(msg="connection refused")
    )
    recorder.error(flow)

    rows = {row["id"]: row for row in recorder.snapshot()}
    assert rows["e"]["failed"] is True
    assert rows["e"]["error"] == "connection refused"
    assert rows["e"]["status"] is None
    assert recorder.raw("e") is flow

    # flow.get surfaces the failure with an empty response, not a phantom body.
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    fetched = backend.flow_get("s", "e", tmp_path)
    assert fetched["failed"] is True
    assert fetched["error"] == "connection refused"
    assert fetched["response"]["status"] is None
    assert fetched["response"]["size"] == 0

    # An error arriving after a real response annotates that row, not a new one.
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    good = SimpleNamespace(id="g", request=request, response=response)
    recorder.response(good)
    recorder.error(
        SimpleNamespace(id="g", request=request, response=response,
                        error=SimpleNamespace(msg="reset"))
    )
    g_rows = [row for row in recorder.snapshot() if row["id"] == "g"]
    assert len(g_rows) == 1
    assert g_rows[0]["failed"] is True
    assert g_rows[0]["error"] == "reset"
    assert g_rows[0]["status"] == 200
    doc = _tool_docstring("proxy.flows")
    assert "failed" in doc
