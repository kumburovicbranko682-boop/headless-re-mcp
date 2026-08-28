"""proxy.ws.search must find a literal inside WebSocket frames, across flows.

The HTTP-side twin (proxy.search) has its own suite; this covers the frame-level
scan: locating a hit by flow + frame index + direction, the direction/flow_id
scoping, binary-opcode payloads, paging, and the scan/match ceilings.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_SEARCH_QUERY,
    ProxyBackend,
    ProxyError,
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


def _msg(content: bytes, *, from_client: bool, opcode: int = 0x1, ts: float = 0.0) -> Any:
    return SimpleNamespace(content=content, from_client=from_client, type=opcode, timestamp=ts)


def _ws_flow(flow_id: str, url: str, messages: list[Any], *, host: str = "x") -> Any:
    request = SimpleNamespace(
        method="GET", pretty_url=url, host=host, headers={}, raw_content=b""
    )
    response = SimpleNamespace(
        status_code=101, headers={"content-type": ""}, raw_content=b""
    )
    websocket = SimpleNamespace(messages=list(messages))
    return SimpleNamespace(id=flow_id, request=request, response=response, websocket=websocket)


def _http_flow(url: str = "http://x/") -> Any:
    request = SimpleNamespace(
        method="GET", pretty_url=url, host="x", headers={}, raw_content=b""
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=b"body"
    )
    return SimpleNamespace(request=request, response=response)


class _FakeRecorder:
    def __init__(self, summaries: list[dict[str, Any]], raws: dict[str, Any]) -> None:
        self._summaries = summaries
        self._raws = raws

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._summaries)

    def raw(self, flow_id: str) -> Any:
        return self._raws.get(flow_id)


def _ws_summary(flow_id: str, *, seq: int, url: str, host: str = "x") -> dict[str, Any]:
    return {
        "id": flow_id,
        "seq": seq,
        "method": "GET",
        "url": url,
        "host": host,
        "status": 101,
        "content_type": "",
        "websocket": True,
    }


def _http_summary(flow_id: str, *, seq: int, url: str = "http://x/") -> dict[str, Any]:
    return {
        "id": flow_id,
        "seq": seq,
        "method": "GET",
        "url": url,
        "host": "x",
        "status": 200,
        "content_type": "text/plain",
    }


def _backend(monkeypatch: Any, recorder: Any) -> ProxyBackend:
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_finds_a_frame_hit_and_locates_it(monkeypatch: Any) -> None:
    """A needle in one sent frame returns it located by flow + frame + direction.

    A plain HTTP flow in the same ring is ignored, ws_flows counts only the
    WebSocket flows, and frames_searched counts every frame scanned.
    """
    summaries = [
        _ws_summary("w1", seq=1, url="ws://api/socket"),
        _http_summary("h1", seq=2),
        _ws_summary("w2", seq=3, url="ws://api/other"),
    ]
    raws = {
        "w1": _ws_flow(
            "w1",
            "ws://api/socket",
            [
                _msg(b'{"type":"hello"}', from_client=False),
                _msg(b'{"auth":"tok-WS-9449"}', from_client=True),
            ],
        ),
        "h1": _http_flow(),
        "w2": _ws_flow("w2", "ws://api/other", [_msg(b"noise", from_client=False)]),
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.ws_search("s", "tok-WS-9449")
    assert out["total"] == 1
    assert out["count"] == 1
    assert out["ws_flows"] == 2
    assert out["frames_searched"] == 3
    assert out["frames_capped"] is False
    assert out["matches_capped"] is False
    match = out["matches"][0]
    assert match["flow_id"] == "w1"
    assert match["frame_index"] == 1
    assert match["direction"] == "sent"
    assert match["type"] == "text"
    assert match["match_count"] == 1
    assert "tok-WS-9449" in match["snippet"]
    assert "direction" not in out
    assert "flow_id" not in out


def test_case_insensitive_unless_asked(monkeypatch: Any) -> None:
    summaries = [_ws_summary("w1", seq=1, url="ws://x")]
    raws = {"w1": _ws_flow("w1", "ws://x", [_msg(b"Bearer sk-live", from_client=True)])}
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    assert backend.ws_search("s", "bearer")["total"] == 1
    assert backend.ws_search("s", "bearer", case_sensitive=True)["total"] == 0
    exact = backend.ws_search("s", "Bearer", case_sensitive=True)
    assert exact["total"] == 1
    assert exact["case_sensitive"] is True


def test_direction_filter(monkeypatch: Any) -> None:
    summaries = [_ws_summary("w1", seq=1, url="ws://x")]
    raws = {
        "w1": _ws_flow(
            "w1",
            "ws://x",
            [
                _msg(b"sent-secret", from_client=True),
                _msg(b"recv-secret", from_client=False),
            ],
        )
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    sent = backend.ws_search("s", "secret", direction="sent")
    assert sent["total"] == 1
    assert sent["matches"][0]["direction"] == "sent"
    assert sent["direction"] == "sent"

    received = backend.ws_search("s", "secret", direction="received")
    assert received["total"] == 1
    assert received["matches"][0]["direction"] == "received"

    with pytest.raises(ProxyError) as bad:
        backend.ws_search("s", "secret", direction="up")
    assert bad.value.code == "invalid_params"


def test_flow_id_scopes_and_validates(monkeypatch: Any) -> None:
    summaries = [
        _ws_summary("w1", seq=1, url="ws://a"),
        _ws_summary("w2", seq=2, url="ws://b"),
        _http_summary("h1", seq=3),
    ]
    raws = {
        "w1": _ws_flow("w1", "ws://a", [_msg(b"has token here", from_client=True)]),
        "w2": _ws_flow("w2", "ws://b", [_msg(b"has token here too", from_client=True)]),
        "h1": _http_flow(),
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    scoped = backend.ws_search("s", "token", flow_id="w1")
    assert scoped["total"] == 1
    assert scoped["ws_flows"] == 1
    assert scoped["flow_id"] == "w1"
    assert scoped["matches"][0]["flow_id"] == "w1"

    with pytest.raises(ProxyError) as missing:
        backend.ws_search("s", "token", flow_id="zzz")
    assert missing.value.code == "not_found"

    with pytest.raises(ProxyError) as not_ws:
        backend.ws_search("s", "token", flow_id="h1")
    assert not_ws.value.code == "invalid_state"


def test_binary_opcode_payload_is_still_searched(monkeypatch: Any) -> None:
    """A JSON body carried on a binary opcode is decoded and matched as binary."""
    summaries = [_ws_summary("w1", seq=1, url="ws://x")]
    raws = {
        "w1": _ws_flow(
            "w1",
            "ws://x",
            [_msg(b'{"k":"binmarker-9449"}', from_client=False, opcode=0x2)],
        )
    }
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.ws_search("s", "binmarker-9449")
    assert out["total"] == 1
    assert out["matches"][0]["type"] == "binary"


def test_paginates_over_matches(monkeypatch: Any) -> None:
    summaries = [_ws_summary("w1", seq=1, url="ws://x")]
    frames = [_msg(f"hit-{i}".encode(), from_client=(i % 2 == 0)) for i in range(7)]
    raws = {"w1": _ws_flow("w1", "ws://x", frames)}
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    first = backend.ws_search("s", "hit-", offset=0, limit=3)
    assert first["total"] == 7
    assert first["count"] == 3
    assert first["has_more"] is True
    last = backend.ws_search("s", "hit-", offset=6, limit=3)
    assert last["count"] == 1
    assert last["has_more"] is False


def test_scan_ceiling_is_disclosed(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_WS_SEARCH_SCAN", 2)
    summaries = [_ws_summary("w1", seq=1, url="ws://x")]
    frames = [_msg(b"hit", from_client=True) for _ in range(3)]
    raws = {"w1": _ws_flow("w1", "ws://x", frames)}
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.ws_search("s", "hit")
    assert out["frames_searched"] == 2
    assert out["frames_capped"] is True


def test_match_ceiling_is_disclosed(monkeypatch: Any) -> None:
    monkeypatch.setattr(proxy_client, "_MAX_WS_SEARCH_MATCHES", 2)
    summaries = [_ws_summary("w1", seq=1, url="ws://x")]
    frames = [_msg(b"hit", from_client=True) for _ in range(3)]
    raws = {"w1": _ws_flow("w1", "ws://x", frames)}
    backend = _backend(monkeypatch, _FakeRecorder(summaries, raws))

    out = backend.ws_search("s", "hit")
    assert out["total"] == 2
    assert out["matches_capped"] is True


def test_rejects_bad_query(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _FakeRecorder([], {}))
    with pytest.raises(ProxyError) as empty:
        backend.ws_search("s", "")
    assert empty.value.code == "invalid_params"
    with pytest.raises(ProxyError) as huge:
        backend.ws_search("s", "x" * (_MAX_SEARCH_QUERY + 1))
    assert huge.value.code == "invalid_params"


def test_over_the_real_recorder(monkeypatch: Any) -> None:
    """End to end over the actual ring: frames pushed through the hooks are found."""
    recorder = _FlowRecorder(capacity=10)
    flow = _ws_flow("w1", "ws://api/live", [])
    # The 101 handshake is summarised first, then each frame arrives via the hook.
    flow.websocket.messages = []
    recorder.response(flow)
    for payload, from_client in (
        (b'{"op":"sub"}', True),
        (b'{"token":"live-tok-9449"}', False),
    ):
        flow.websocket.messages.append(_msg(payload, from_client=from_client))
        recorder.websocket_message(flow)
    backend = _backend(monkeypatch, recorder)

    hit = backend.ws_search("s", "live-tok-9449")
    assert hit["total"] == 1
    match = hit["matches"][0]
    assert match["flow_id"] == "w1"
    assert match["direction"] == "received"

    miss = backend.ws_search("s", "not-present-anywhere")
    assert miss["total"] == 0
    assert miss["matches"] == []


def test_docstring_names_the_fields() -> None:
    doc = _tool_docstring("proxy.ws.search")
    for token in ("matches", "frame_index", "direction", "ws_flows", "frames_searched"):
        assert token in doc, token
