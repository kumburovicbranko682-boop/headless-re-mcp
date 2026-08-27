"""proxy.flow.get returns the decompressed body, not the opaque wire bytes.

mitmproxy keeps two views of a message body: ``raw_content`` is the bytes
exactly as they crossed the wire, and ``content`` is those bytes with any
``Content-Encoding`` undone. Modern HTTP responses are almost always gzip- or
brotli-compressed, so ``raw_content`` is opaque compressed bytes. flow.get read
``raw_content``, so ``_emit_body`` could only spill it as an unreadable ``.bin``
(spill_reason "binary") -- hiding the very JSON or HTML an analyst opened
flow.get to read. It now reads ``content``, so a compressed body comes back as
its real bytes, and falls back to the wire bytes only when the encoding cannot
be decoded (corrupt or unsupported) rather than dropping the body.

These tests drive ``flow_get`` with a fake that mimics mitmproxy's content vs
raw_content split (so the unit lane needs no mitmproxy); a live gate proves the
same against a real mitmproxy decompressing a real gzip origin.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend
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


class _Part:
    """A request/response body view like mitmproxy's: raw bytes plus a decoded view.

    ``content`` is what mitmproxy returns after undoing Content-Encoding. Pass an
    exception instance for ``content`` to model an encoding mitmproxy cannot
    decode -- accessing ``.content`` then raises, exactly as the real property
    does on a corrupt gzip.
    """

    def __init__(self, *, raw: bytes | None, content: Any, **attrs: Any) -> None:
        self._raw = raw
        self._content = content
        for key, value in attrs.items():
            setattr(self, key, value)

    @property
    def raw_content(self) -> bytes | None:
        return self._raw

    @property
    def content(self) -> bytes | None:
        if isinstance(self._content, BaseException):
            raise self._content
        return self._content


def _backend_with_flow(monkeypatch: Any, flow: Any) -> ProxyBackend:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def _request(**overrides: Any) -> _Part:
    defaults: dict[str, Any] = {
        "raw": b"",
        "content": b"",
        "method": "GET",
        "pretty_url": "http://x/",
        "headers": {},
    }
    defaults.update(overrides)
    return _Part(**defaults)


def _response(**overrides: Any) -> _Part:
    defaults: dict[str, Any] = {
        "raw": b"",
        "content": b"",
        "status_code": 200,
        "headers": {"content-type": "application/json"},
    }
    defaults.update(overrides)
    return _Part(**defaults)


def test_flow_get_returns_the_decompressed_response_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The bug: a gzip response used to come back as an opaque .bin.

    A gzip'd JSON body has compressed wire bytes (raw_content) and readable
    decoded bytes (content). flow.get now returns the decoded JSON inline, sized
    by its decompressed length -- never spilling the gzip blob as binary.
    """
    wire = b"\x1f\x8b\x08\x00compressed-gzip-bytes\xff\xfe"
    decoded = b'{"token":"decoded-json-an-analyst-can-read"}'
    flow = SimpleNamespace(
        request=_request(),
        response=_response(
            raw=wire,
            content=decoded,
            headers={"content-type": "application/json", "content-encoding": "gzip"},
        ),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "f1", tmp_path)

    resp = payload["response"]
    assert resp["body"] == decoded.decode("utf-8")
    assert resp["size"] == len(decoded)
    # The compressed wire bytes were never handed back or spilled as a .bin.
    assert "body_path" not in resp
    assert "spill_reason" not in resp


def test_flow_get_decompresses_the_request_body_too(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A gzip'd request payload (what was POSTed) is decoded the same way."""
    sent_decoded = b'{"user":"root","action":"login"}'
    flow = SimpleNamespace(
        request=_request(
            method="POST",
            pretty_url="http://x/login",
            raw=b"\x1f\x8bcompressed-request",
            content=sent_decoded,
            headers={"content-type": "application/json", "content-encoding": "gzip"},
        ),
        response=_response(raw=b"ok", content=b"ok", headers={"content-type": "text/plain"}),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "f2", tmp_path)

    assert payload["request"]["body"] == sent_decoded.decode("utf-8")
    assert payload["request"]["size"] == len(sent_decoded)
    assert "body_path" not in payload["request"]


def test_flow_get_falls_back_to_wire_bytes_when_the_encoding_is_corrupt(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A body mitmproxy cannot decode is surfaced from the wire, not dropped.

    When ``content`` raises (corrupt/unsupported encoding), the raw wire bytes
    are returned instead of an empty body, so the analyst still gets something
    -- here a binary blob that spills to a .bin holding exactly those bytes.
    """
    wire = b"\x1f\x8b\x08 not-actually-decodable \xff\x00\x01"
    flow = SimpleNamespace(
        request=_request(),
        response=_response(
            raw=wire,
            content=ValueError("ValueError when decoding with 'gzip'"),
            headers={"content-encoding": "gzip"},
        ),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "f3", tmp_path)

    resp = payload["response"]
    assert "body" not in resp
    assert resp["spill_reason"] == "binary"
    assert resp["size"] == len(wire)
    assert Path(resp["body_path"]).read_bytes() == wire


def test_flow_get_falls_back_to_readable_wire_text_when_undecodable(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The fallback surfaces raw text inline, not just binary spills."""
    wire = b"plaintext body the server mislabeled as encoded"
    flow = SimpleNamespace(
        request=_request(),
        response=_response(
            raw=wire,
            content=ValueError("unsupported Content-Encoding"),
            headers={"content-encoding": "made-up"},
        ),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    resp = backend.flow_get("s", "f4", tmp_path)["response"]
    assert resp["body"] == wire.decode("utf-8")
    assert resp["size"] == len(wire)


def test_flow_get_leaves_an_unencoded_body_untouched(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """No Content-Encoding: content equals the wire bytes, and flow.get returns them."""
    body = b'{"plain":"identity body, no compression"}'
    flow = SimpleNamespace(
        request=_request(),
        response=_response(raw=body, content=body),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    resp = backend.flow_get("s", "f5", tmp_path)["response"]
    assert resp["body"] == body.decode("utf-8")
    assert resp["size"] == len(body)


def test_flow_get_reports_an_empty_body_for_a_bodyless_response(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A 204/redirect with no body stays empty, not a spurious spill."""
    flow = SimpleNamespace(
        request=_request(),
        response=_response(raw=None, content=None, status_code=204, headers={}),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    resp = backend.flow_get("s", "f6", tmp_path)["response"]
    assert resp["body"] == ""
    assert resp["size"] == 0
    assert "body_path" not in resp


def test_flow_get_docstring_states_the_body_is_decompressed() -> None:
    doc = " ".join(_tool_docstring("proxy.flow.get").split())
    assert "content-encoding decoded" in doc
    assert "gzip" in doc
    # The old promise that size matched the wire length is gone: the decoded
    # size can exceed proxy.flows' on-wire response_size.
    assert "response_size" in doc


def test_flows_docstring_no_longer_calls_response_size_decoded() -> None:
    """response_size stays the on-wire (compressed) length; the doc must say so."""
    doc = " ".join(_tool_docstring("proxy.flows").split())
    assert "on-wire" in doc
    assert "decoded response body length" not in doc
