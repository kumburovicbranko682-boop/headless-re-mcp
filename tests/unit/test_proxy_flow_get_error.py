"""proxy.flow.get surfaces the error of a flow that never completed.

The error hook already captures a flow mitmproxy could not complete (TLS
handshake refused, upstream unreachable, connection reset mid-request) and
proxy.flows marks that row error / error_msg with a null status. But such a
flow has no response, so flow.get built status null and an empty body and
returned nothing else -- indistinguishable, on flow.get alone, from a request
that simply answered with an empty body. An agent that goes straight to
flow.get for the detail of "why did this fail?" learned nothing.

flow.get now surfaces the flow's own error the same way the summary does:
top-level error true and error_msg, response.status still null, while a
completed flow carries no error field. These tests drive flow_get with fakes
shaped like the error hook's input; a live gate proves the same against a real
mitmproxy failing to reach a refused upstream.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _MAX_METADATA_BYTES, ProxyBackend
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


def _backend_with_flow(monkeypatch: Any, flow: Any) -> ProxyBackend:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def _errored_flow(
    msg: str | None = "[Errno 111] Connect call failed ('127.0.0.1', 47027)",
) -> Any:
    # An errored flow: the request was parsed, but mitmproxy never got a
    # response, so flow.response is None and flow.error holds the reason.
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/beacon", headers={}, raw_content=b""
    )
    error = SimpleNamespace(msg=msg) if msg is not None else None
    return SimpleNamespace(request=request, response=None, error=error)


def _ok_flow() -> Any:
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/ok", headers={}, raw_content=b""
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=b"ok"
    )
    return SimpleNamespace(request=request, response=response)


def test_flow_get_marks_an_errored_flow_with_its_reason(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The bug: an errored flow's flow.get looked like an empty 200-less response."""
    backend = _backend_with_flow(monkeypatch, _errored_flow())

    payload = backend.flow_get("s", "e1", tmp_path)

    assert payload["error"] is True
    assert payload["error_msg"] == "[Errno 111] Connect call failed ('127.0.0.1', 47027)"
    # A failure is not a response: status stays null and the body is empty,
    # but now the error says why rather than leaving the reader to guess.
    assert payload["response"]["status"] is None
    assert payload["response"]["body"] == ""
    # The request that was attempted is still described.
    assert payload["request"]["url"] == "http://x/beacon"


def test_flow_get_on_a_completed_flow_carries_no_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A flow that answered must not sprout an error field."""
    backend = _backend_with_flow(monkeypatch, _ok_flow())

    payload = backend.flow_get("s", "ok", tmp_path)

    assert "error" not in payload
    assert "error_msg" not in payload
    assert payload["response"]["status"] == 200
    assert payload["response"]["body"] == "ok"


def test_flow_get_bounds_a_huge_error_message(tmp_path: Path, monkeypatch: Any) -> None:
    backend = _backend_with_flow(monkeypatch, _errored_flow(msg="é" * (_MAX_METADATA_BYTES + 50)))

    payload = backend.flow_get("s", "big", tmp_path)

    assert payload["error"] is True
    assert len(str(payload["error_msg"]).encode("utf-8")) <= _MAX_METADATA_BYTES
    assert payload["metadata_truncated"] is True


def test_flow_get_error_falls_back_when_the_error_names_no_reason(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Mirror the recorder: a present-but-empty error still reads as errored.

    mitmproxy always attaches a message, but the recorder defends against an
    error object that names none; flow.get uses the identical expression, so a
    falsy error object still surfaces error true with the "flow error" default
    rather than being dropped.
    """

    class _FalsyError:
        msg = None

        def __bool__(self) -> bool:
            return False

    request = SimpleNamespace(
        method="GET", pretty_url="http://x/q", headers={}, raw_content=b""
    )
    flow = SimpleNamespace(request=request, response=None, error=_FalsyError())
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "nomsg", tmp_path)
    assert payload["error"] is True
    assert payload["error_msg"] == "flow error"


def test_flow_get_docstring_names_the_error_fields() -> None:
    doc = " ".join(_tool_docstring("proxy.flow.get").split())
    assert "error true" in doc
    assert "error_msg" in doc
    assert "status stays null" in doc
