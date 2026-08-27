"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_COOKIES,
    _MAX_HEADER_VALUE_BYTES,
    _MAX_METADATA_BYTES,
    _MAX_STORAGE_ITEMS,
    _MAX_STORAGE_VALUE_BYTES,
    _MAX_URL_BYTES,
    WebBackend,
)
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FakeHandle:
    def __init__(self, count: int, *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.console = deque({"text": str(index)} for index in range(count))
        self.requests = {
            str(index): {
                "requestId": str(index),
                "url": f"https://example/{index}",
                "method": "GET",
                "resourceType": "XHR",
                "status": 200,
                "mimeType": "application/json",
            }
            for index in range(count)
        }
        self.scripts = {
            str(index): {
                "scriptId": str(index),
                "url": f"https://example/{index}",
                "language": "WebAssembly" if index % 2 else "JavaScript",
            }
            for index in range(count)
        }
        self.scripts_dropped = dropped
        self.console_dropped = 0
        self.requests_dropped = 0


def test_web_console_puts_messages_in_console_and_says_when_it_stopped(
    monkeypatch: Any,
) -> None:
    """The catalog said messages and never named the payload.

    Measured: 25 held, limit 10 -> count 10, has_more True, field is console
    not messages or logs. Looking for messages after a successful call reads
    as an empty console, and a full page with no has_more reads as the buffer.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(25))
    payload = backend.console("s", limit=10)
    assert "messages" not in payload
    assert "logs" not in payload
    assert payload["count"] == 10
    assert len(payload["console"]) == 10
    assert payload["has_more"] is True
    assert payload["dropped"] == 0
    doc = _tool_docstring("web.console")
    assert "Answers with console" in doc
    assert "has_more" in doc
    assert "dropped" in doc
    assert "text_truncated" in doc


def test_web_network_list_puts_the_page_in_requests_not_type(
    monkeypatch: Any,
) -> None:
    """The catalog said type and never named the list field.

    Measured: 25 held, limit 10 -> count 10, total 25, field is requests
    not items or network, and each row carries resourceType with no type
    key. Looking for type or network after a successful call reads as an
    empty capture, and a full page with no total reads as the whole log.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(25))
    payload = backend.network_list("s", offset=0, limit=10)
    assert "network" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["offset"] == 0
    assert payload["has_more"] is True
    assert payload["dropped"] == 0
    assert len(payload["requests"]) == 10
    row = payload["requests"][0]
    assert "type" not in row
    assert row["resourceType"] == "XHR"
    normalized = backend.network_list("s", offset=-10, limit=0)
    assert normalized["offset"] == 0
    assert normalized["count"] == 1
    assert normalized["has_more"] is True
    doc = _tool_docstring("web.network.list")
    assert "Answers with requests" in doc
    assert "resourceType" in doc
    assert "total" in doc
    assert "has_more" in doc
    assert "dropped" in doc
    assert "metadata_truncated" in doc


class _MixedNetworkHandle:
    """A session handle whose capture holds mixed traffic for the filter tests."""

    def __init__(self, rows: list[dict[str, Any]], *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.requests = {str(row["requestId"]): row for row in rows}
        self.requests_dropped = dropped


def test_web_network_list_filters_narrow_the_capture(monkeypatch: Any) -> None:
    """A capture of mixed traffic must narrow by method/url/status/type/failed.

    Finding the one XHR to an API host among documents, scripts and images
    otherwise meant paging the whole capture. Assert each filter narrows to the
    matching subset, that total/has_more describe that subset (not the whole
    capture), and that filtered/unfiltered_total are reported so a small match
    is not mistaken for a small capture.
    """
    rows = [
        {"requestId": "1", "url": "https://app/index.html", "method": "GET",
         "resourceType": "Document", "status": 200},
        {"requestId": "2", "url": "https://cdn/app.js", "method": "GET",
         "resourceType": "Script", "status": 200},
        {"requestId": "3", "url": "https://api.example.com/v1/login", "method": "POST",
         "resourceType": "XHR", "status": 401, "has_request_body": True},
        {"requestId": "4", "url": "https://api.example.com/v1/me", "method": "GET",
         "resourceType": "XHR", "status": 200},
        {"requestId": "5", "url": "https://cdn/pixel.gif", "method": "GET",
         "resourceType": "Image", "status": None, "failed": True,
         "error_text": "net::ERR_BLOCKED_BY_CLIENT"},
    ]
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _MixedNetworkHandle(rows, dropped=7))

    # url_contains folds case and matches a host fragment; the two API calls hit.
    api = backend.network_list("s", url_contains="API.EXAMPLE.com")
    assert {row["requestId"] for row in api["requests"]} == {"3", "4"}
    assert api["total"] == 2
    assert api["has_more"] is False
    assert api["filtered"] is True
    assert api["unfiltered_total"] == 5
    # dropped stays the whole-capture eviction count, not the filtered count.
    assert api["dropped"] == 7

    # resource_type is exact and case-insensitive: only the two XHRs.
    xhr = backend.network_list("s", resource_type="xhr")
    assert {row["requestId"] for row in xhr["requests"]} == {"3", "4"}

    # method is exact and case-insensitive.
    posts = backend.network_list("s", method="post")
    assert [row["requestId"] for row in posts["requests"]] == ["3"]

    # status is an exact int; the pending/failed request (status None) never matches.
    ok = backend.network_list("s", status=200)
    assert {row["requestId"] for row in ok["requests"]} == {"1", "2", "4"}

    # failed selects only the blocked/aborted request.
    dead = backend.network_list("s", failed=True)
    assert [row["requestId"] for row in dead["requests"]] == ["5"]
    alive = backend.network_list("s", failed=False)
    assert {row["requestId"] for row in alive["requests"]} == {"1", "2", "3", "4"}

    # Filters combine: an XHR POST to the API host is just the login call.
    combo = backend.network_list("s", resource_type="xhr", method="POST", url_contains="login")
    assert [row["requestId"] for row in combo["requests"]] == ["3"]

    # An unfiltered call carries neither key, so a plain listing is not read as
    # a filtered one.
    plain = backend.network_list("s")
    assert "filtered" not in plain
    assert "unfiltered_total" not in plain
    assert plain["total"] == 5

    doc = _tool_docstring("web.network.list")
    assert "url_contains" in doc
    assert "resource_type" in doc
    assert "filtered" in doc
    assert "unfiltered_total" in doc


def test_web_network_stats_folds_the_capture_into_a_summary(monkeypatch: Any) -> None:
    """A busy page's capture must summarize by method/status/type/host/content.

    network.list is a paged listing; before filtering, a caller wants to know
    what the capture holds. Drive mixed traffic and assert the aggregate: method
    counts, status classes, resource-type counts, ranked hosts, merged content
    types, and the failed/with_request_body/finished/no_status tallies.
    """
    rows = [
        {"requestId": "1", "url": "https://app.example/index.html", "method": "GET",
         "resourceType": "Document", "status": 200, "mimeType": "text/html; charset=utf-8",
         "finished": True},
        {"requestId": "2", "url": "https://cdn.example/app.js", "method": "GET",
         "resourceType": "Script", "status": 200, "mimeType": "application/javascript",
         "finished": True},
        {"requestId": "3", "url": "https://api.example/login", "method": "POST",
         "resourceType": "XHR", "status": 401, "mimeType": "application/json",
         "has_request_body": True, "finished": True},
        {"requestId": "4", "url": "https://api.example/me", "method": "GET",
         "resourceType": "XHR", "status": 500, "mimeType": "application/json",
         "finished": True},
        {"requestId": "5", "url": "https://cdn.example/pixel.gif", "method": "GET",
         "resourceType": "Image", "status": None, "failed": True,
         "error_text": "net::ERR_BLOCKED_BY_CLIENT"},
    ]
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _MixedNetworkHandle(rows, dropped=4))
    stats = backend.network_stats("s")

    assert stats["total"] == 5
    assert stats["dropped"] == 4
    assert stats["by_method"] == {"GET": 4, "POST": 1}
    assert stats["by_status_class"] == {"2xx": 2, "4xx": 1, "5xx": 1}
    assert stats["no_status"] == 1
    assert stats["by_resource_type"] == {"Document": 1, "Script": 1, "XHR": 2, "Image": 1}
    assert stats["failed"] == 1
    assert stats["with_request_body"] == 1
    assert stats["finished"] == 4
    # Hosts come from the URL netloc and rank by count; cdn/api lead with two each.
    host_counts = {row["host"]: row["count"] for row in stats["top_hosts"]}
    assert host_counts["cdn.example"] == 2
    assert host_counts["api.example"] == 2
    assert host_counts["app.example"] == 1
    assert stats["host_count"] == 3
    # "application/json" merges across the two XHRs; the charset param is dropped.
    ctype_counts = {row["content_type"]: row["count"] for row in stats["top_content_types"]}
    assert ctype_counts["application/json"] == 2
    assert ctype_counts["text/html"] == 1
    assert stats["content_type_count"] == 3
    # The summary is not a second listing.
    assert "requests" not in stats
    assert "flows" not in stats

    doc = _tool_docstring("web.network.stats")
    assert "by_method" in doc
    assert "by_status_class" in doc
    assert "by_resource_type" in doc
    assert "top_hosts" in doc
    assert "no_status" in doc
    assert "dropped" in doc


def test_web_network_stats_caps_the_top_lists_but_counts_all(monkeypatch: Any) -> None:
    """Hundreds of hosts must not turn the summary into a second full listing.

    Feed more distinct hosts than the cap and assert top_hosts is trimmed while
    host_count still reports every distinct host, so a trimmed list is read as
    trimmed rather than the whole picture.
    """
    from headless_re_mcp.backends.web.client import _MAX_STATS_HOSTS

    hosts = _MAX_STATS_HOSTS + 5
    rows = [
        {"requestId": str(index), "url": f"https://h{index}.example/x", "method": "GET",
         "resourceType": "XHR", "status": 200, "mimeType": "application/json"}
        for index in range(hosts)
    ]
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _MixedNetworkHandle(rows))
    stats = backend.network_stats("s")

    assert len(stats["top_hosts"]) == _MAX_STATS_HOSTS
    assert stats["host_count"] == hosts
    assert all(row["count"] == 1 for row in stats["top_hosts"])
    assert len(stats["top_content_types"]) == 1
    assert stats["content_type_count"] == 1


def test_web_event_metadata_is_bounded_before_entering_capture_rings() -> None:
    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    huge = "é" * (_MAX_URL_BYTES + 1)

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "request-1",
            "request": {"url": huge, "method": huge},
            "type": huge,
        }
    )
    cdp.handlers["Network.responseReceived"](
        {
            "requestId": "request-1",
            "response": {"status": 200, "mimeType": huge},
        }
    )
    cdp.handlers["Debugger.scriptParsed"](
        {"scriptId": "script-1", "url": huge, "scriptLanguage": huge}
    )

    request = handle.requests["request-1"]
    assert len(str(request["url"]).encode()) <= _MAX_URL_BYTES
    assert len(str(request["method"]).encode()) <= _MAX_METADATA_BYTES
    assert len(str(request["resourceType"]).encode()) <= _MAX_METADATA_BYTES
    assert len(str(request["mimeType"]).encode()) <= _MAX_METADATA_BYTES
    assert request["metadata_truncated"] is True
    script = handle.scripts["script-1"]
    assert len(str(script["url"]).encode()) <= _MAX_URL_BYTES
    assert len(str(script["language"]).encode()) <= _MAX_METADATA_BYTES
    assert script["metadata_truncated"] is True


def test_web_loading_failed_marks_the_request_instead_of_leaving_it_pending() -> None:
    """Network.loadingFailed must flag the request; a blocked call has no response.

    Wire the events, open a request, then fire loadingFailed the way Chromium
    does for a blocked resource (errorText plus blockedReason). Assert the entry
    is flagged failed with the reason kept and no phantom status, and that a
    failure for an unknown/evicted request id is ignored rather than crashing.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    assert "Network.loadingFailed" in cdp.handlers
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "request-1",
            "request": {"url": "https://blocked/x", "method": "GET"},
            "type": "XHR",
        }
    )
    cdp.handlers["Network.loadingFailed"](
        {
            "requestId": "request-1",
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "blockedReason": "inspector",
            "canceled": False,
        }
    )
    cdp.handlers["Network.loadingFailed"](
        {"requestId": "ghost", "errorText": "net::ERR_ABORTED"}
    )

    entry = handle.requests["request-1"]
    assert entry["failed"] is True
    assert entry["error_text"] == "net::ERR_BLOCKED_BY_CLIENT"
    assert entry["blocked_reason"] == "inspector"
    assert entry["status"] is None
    assert "canceled" not in entry
    assert "ghost" not in handle.requests
    doc = _tool_docstring("web.network.list")
    assert "failed" in doc
    assert "error_text" in doc


def test_web_accumulates_response_sizes_from_data_and_loading_finished() -> None:
    """Chunked dataReceived + loadingFinished must yield the response's size.

    Without them a captured response has no size at all -- network.list can't
    flag a heavy response and the HAR reports content.size 0. Fire two body
    chunks and a finish the way Chromium does and assert the decoded and
    on-wire body sizes sum and the transfer total is kept, and that a chunk for
    an evicted request id is ignored rather than crashing.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    assert "Network.dataReceived" in cdp.handlers
    assert "Network.loadingFinished" in cdp.handlers

    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {"url": "https://x/big.json", "method": "GET"},
            "type": "XHR",
        }
    )
    cdp.handlers["Network.dataReceived"](
        {"requestId": "r1", "dataLength": 1000, "encodedDataLength": 400}
    )
    cdp.handlers["Network.dataReceived"](
        {"requestId": "r1", "dataLength": 500, "encodedDataLength": 200}
    )
    cdp.handlers["Network.loadingFinished"](
        {"requestId": "r1", "encodedDataLength": 720}
    )
    # A stray chunk for an evicted/unknown id must not raise or resurrect it.
    cdp.handlers["Network.dataReceived"](
        {"requestId": "ghost", "dataLength": 9, "encodedDataLength": 9}
    )

    entry = handle.requests["r1"]
    assert entry["response_size"] == 1500
    assert entry["response_encoded_size"] == 600
    assert entry["transfer_size"] == 720
    assert entry["finished"] is True
    assert "ghost" not in handle.requests
    doc = _tool_docstring("web.network.list")
    assert "response_size" in doc
    assert "transfer_size" in doc


def test_web_captures_bounded_request_and_response_headers() -> None:
    """Headers (auth, cookies, content type) must be captured and bounded.

    Wire the events, fire a request/response the way Chromium does (headers on
    request.headers and response.headers), and assert the entry carries
    request_headers and response_headers, that an oversized value is clipped and
    flags metadata_truncated, and that network.list omits headers while the
    stored entry keeps them for network.get.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    huge = "z" * (_MAX_HEADER_VALUE_BYTES + 500)
    cdp.handlers["Network.requestWillBeSent"](
        {
            "requestId": "r1",
            "request": {
                "url": "https://api/x",
                "method": "POST",
                "headers": {"Authorization": "Bearer secret", "X-Big": huge},
            },
            "type": "XHR",
        }
    )
    cdp.handlers["Network.responseReceived"](
        {
            "requestId": "r1",
            "response": {
                "status": 200,
                "mimeType": "application/json",
                "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=abc"},
            },
        }
    )

    entry = handle.requests["r1"]
    assert entry["request_headers"]["Authorization"] == "Bearer secret"
    assert len(entry["request_headers"]["X-Big"].encode()) <= _MAX_HEADER_VALUE_BYTES
    assert entry["metadata_truncated"] is True
    assert entry["response_headers"]["Content-Type"] == "application/json"
    assert entry["response_headers"]["Set-Cookie"] == "sid=abc"

    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[assignment]
    row = backend.network_list("s")["requests"][0]
    assert "request_headers" not in row
    assert "response_headers" not in row
    # The list row is a copy: stripping it must not strip the stored entry.
    assert "response_headers" in handle.requests["r1"]
    doc = _tool_docstring("web.network.get")
    assert "request_headers" in doc
    assert "response_headers" in doc


def test_web_uncaught_exception_lands_in_the_console_ring() -> None:
    """Runtime.exceptionThrown must be captured; console.* is not the only source.

    Wire the events and fire an exceptionThrown the way Chromium does (the error
    lives in exceptionDetails.exception.description), then assert it enters the
    console ring as an error entry tagged source exception with the stack text,
    and that a details-less event is ignored rather than crashing the handler.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    assert "Runtime.exceptionThrown" in cdp.handlers
    cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"description": "Error: boom\n    at http://x/app.js:1:1"},
            }
        }
    )
    cdp.handlers["Runtime.exceptionThrown"]({})  # malformed: must be ignored

    captured = list(handle.console)
    assert len(captured) == 1
    entry = captured[0]
    assert entry["type"] == "error"
    assert entry["source"] == "exception"
    assert "boom" in entry["text"]
    doc = _tool_docstring("web.console")
    assert "exception" in doc


def test_web_console_and_exception_carry_their_source_location() -> None:
    """A console line or error is worthless for triage without its script site.

    CDP hands both events a stackTrace whose first callFrame is the call site
    (an exception also pins url/lineNumber at the top of exceptionDetails).
    Fire each the way Chromium does and assert the entry gains url, 1-based
    line/column, and function; a bare console.log with no stackTrace must not
    invent any of those fields.
    """

    class _Cdp:
        def __init__(self) -> None:
            self.handlers: dict[str, Any] = {}

        def send(self, method: str) -> None:
            del method

        def on(self, event: str, handler: Any) -> None:
            self.handlers[event] = handler

    cdp = _Cdp()
    handle = _FakeHandle(0)
    handle.cdp = cdp  # type: ignore[attr-defined]
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    cdp.handlers["Runtime.consoleAPICalled"](
        {
            "type": "log",
            "args": [{"value": "hello"}],
            "stackTrace": {
                "callFrames": [
                    {
                        "functionName": "doThing",
                        "url": "http://x/app.js",
                        "lineNumber": 41,  # 0-based -> reported as 42
                        "columnNumber": 7,  # 0-based -> reported as 8
                    }
                ]
            },
        }
    )
    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"value": "bare"}]}  # no stackTrace
    )
    cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "url": "http://x/boom.js",
                "lineNumber": 9,  # 0-based -> reported as 10
                "columnNumber": 2,  # 0-based -> reported as 3
                "exception": {"description": "Error: boom"},
            }
        }
    )

    captured = list(handle.console)
    assert len(captured) == 3
    logged, bare, thrown = captured

    assert logged["url"] == "http://x/app.js"
    assert logged["line"] == 42
    assert logged["column"] == 8
    assert logged["function"] == "doThing"

    assert "url" not in bare
    assert "line" not in bare
    assert "column" not in bare
    assert "function" not in bare

    assert thrown["url"] == "http://x/boom.js"
    assert thrown["line"] == 10
    assert thrown["column"] == 3

    doc = _tool_docstring("web.console")
    assert "line" in doc
    assert "column" in doc


class _CookieRunner:
    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()


class _CookieContext:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies = cookies

    def cookies(self) -> list[dict[str, Any]]:
        return self._cookies


class _CookieHandle:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self.context = _CookieContext(cookies)
        self.runner = _CookieRunner()


def test_web_cookies_returns_a_bounded_jar_with_flags(monkeypatch: Any) -> None:
    """web had no way to read the cookie jar -- the auth/session state itself.

    Drive the context's cookies() and assert the value (the token you are
    after) comes back, the security flags are normalised to http_only/secure/
    same_site, a persistent cookie keeps expires while a session one (-1) does
    not, and an oversized value is bounded and flagged rather than returned raw.
    """
    long_value = "j" * (_MAX_HEADER_VALUE_BYTES + 500)
    raw = [
        {
            "name": "sid",
            "value": "abc123",
            "domain": "example.com",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax",
            "expires": 1893456000,
        },
        {"name": "sess", "value": long_value, "domain": "x", "path": "/", "expires": -1},
    ]
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _CookieHandle(raw))
    payload = backend.cookies("s")

    assert payload["count"] == 2
    assert payload["has_more"] is False
    sid = payload["cookies"][0]
    assert sid["name"] == "sid"
    assert sid["value"] == "abc123"
    assert sid["http_only"] is True
    assert sid["secure"] is True
    assert sid["same_site"] == "Lax"
    assert sid["expires"] == 1893456000

    sess = payload["cookies"][1]
    # A session cookie's -1 expiry is not surfaced as a real timestamp.
    assert "expires" not in sess
    assert len(str(sess["value"]).encode("utf-8")) <= _MAX_HEADER_VALUE_BYTES
    assert sess["metadata_truncated"] is True
    # Flags default to False, never absent, so "unknown" cannot read as "set".
    assert sess["http_only"] is False
    assert sess["secure"] is False

    doc = _tool_docstring("web.cookies")
    assert "http_only" in doc
    assert "same_site" in doc


def test_web_cookies_caps_a_huge_jar(monkeypatch: Any) -> None:
    """A page setting thousands of cookies must not return an unbounded list."""
    raw = [
        {"name": f"c{index}", "value": "v", "domain": "x", "path": "/"}
        for index in range(_MAX_COOKIES + 25)
    ]
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _CookieHandle(raw))
    payload = backend.cookies("s")
    assert payload["count"] == _MAX_COOKIES
    assert payload["has_more"] is True


class _StoragePage:
    """A stand-in page.evaluate that mimics the in-page storage dump.

    It honours the maxItems/maxValueChars the backend passes (so the item cap
    and the coarse in-page value slice are exercised) and can simulate an area
    the origin refused by returning an error for localStorage.
    """

    def __init__(
        self,
        local: list[tuple[str, str]],
        session: list[tuple[str, str]],
        *,
        origin: str = "https://app.example",
        local_error: str | None = None,
    ) -> None:
        self._local = local
        self._session = session
        self._origin = origin
        self._local_error = local_error

    def evaluate(self, script: str, arg: dict[str, Any]) -> dict[str, Any]:
        del script
        max_items = int(arg["maxItems"])
        max_chars = int(arg["maxValueChars"])

        def dump(pairs: list[tuple[str, str]], err: str | None) -> dict[str, Any]:
            if err is not None:
                return {"entries": [], "total": 0, "error": err}
            entries = [[str(k), str(v)[:max_chars]] for k, v in pairs[:max_items]]
            return {"entries": entries, "total": len(pairs)}

        return {
            "origin": self._origin,
            "local": dump(self._local, self._local_error),
            "session": dump(self._session, None),
        }


class _StorageHandle:
    def __init__(self, page: _StoragePage) -> None:
        self.page = page
        self.runner = _CookieRunner()


def test_web_storage_reads_both_areas_with_bounds(monkeypatch: Any) -> None:
    """web.cookies read the jar but not Web Storage -- where SPAs stash tokens.

    Drive page.evaluate and assert both areas come back keyed and valued, the
    origin is surfaced, and an oversized value (past the byte cap but under the
    in-page char slice) is bounded and flagged rather than returned raw.
    """
    oversized = "j" * (_MAX_STORAGE_VALUE_BYTES + 500)
    page = _StoragePage(
        local=[("access_token", "eyJhbGciOi.J"), ("blob", oversized)],
        session=[("csrf", "tok-9")],
    )
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _StorageHandle(page))
    payload = backend.storage("s")

    assert payload["origin"] == "https://app.example"
    local = payload["local"]
    assert local["count"] == 2
    assert local["total"] == 2
    assert local["has_more"] is False
    token = local["items"][0]
    assert token["key"] == "access_token"
    assert token["value"] == "eyJhbGciOi.J"
    assert "metadata_truncated" not in token
    blob = local["items"][1]
    assert len(str(blob["value"]).encode("utf-8")) <= _MAX_STORAGE_VALUE_BYTES
    assert blob["metadata_truncated"] is True

    session = payload["session"]
    assert session["count"] == 1
    assert session["items"][0] == {"key": "csrf", "value": "tok-9"}

    doc = _tool_docstring("web.storage")
    assert "localStorage" in doc
    assert "sessionStorage" in doc
    assert "metadata_truncated" in doc
    assert "has_more" in doc


def test_web_storage_caps_a_huge_area(monkeypatch: Any) -> None:
    """An origin stuffing thousands of keys must not return an unbounded list."""
    local = [(f"k{index}", "v") for index in range(_MAX_STORAGE_ITEMS + 25)]
    page = _StoragePage(local=local, session=[])
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _StorageHandle(page))
    payload = backend.storage("s")
    assert payload["local"]["count"] == _MAX_STORAGE_ITEMS
    assert payload["local"]["total"] == _MAX_STORAGE_ITEMS + 25
    assert payload["local"]["has_more"] is True


def test_web_storage_reports_a_denied_area(monkeypatch: Any) -> None:
    """A SecurityError on one area degrades to an error, not a silent empty.

    An opaque origin or disabled storage makes window.localStorage throw. That
    area must come back empty with a reason -- and must not take down the other
    area or the whole call.
    """
    page = _StoragePage(
        local=[],
        session=[("only", "here")],
        local_error="SecurityError: storage is not available",
    )
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _StorageHandle(page))
    payload = backend.storage("s")
    assert payload["local"]["items"] == []
    assert payload["local"]["count"] == 0
    assert "SecurityError" in payload["local"]["error"]
    assert payload["session"]["count"] == 1


def test_web_wasm_list_puts_modules_in_scripts_not_modules(
    monkeypatch: Any,
) -> None:
    """The catalog said modules and never named the payload.

    Measured: 10 parsed scripts, 5 of them WebAssembly -> count 5, field is
    scripts not modules or wasm. Looking for modules after a successful call
    reads as the page loading none.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(10, dropped=3))
    payload = backend.scripts("s", wasm_only=True)
    assert "modules" not in payload
    assert "wasm" not in payload
    assert payload["count"] == 5
    assert len(payload["scripts"]) == 5
    assert all(row["language"] == "WebAssembly" for row in payload["scripts"])
    assert payload["has_more"] is False
    assert payload["dropped"] == 3
    doc = _tool_docstring("web.wasm.list")
    assert "Answers with scripts" in doc
    assert "no modules field" in doc
    assert "has_more" in doc
