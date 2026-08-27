"""web.network.get description must name body_truncated, not truncated."""

from __future__ import annotations

import ast
import base64
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend, WebError
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Cdp:
    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"body": "z" * (_MAX_INLINE_BODY + 25), "base64Encoded": False}


class _Handle:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x"}}
    cdp = _Cdp()


def test_web_network_get_names_body_truncated_not_truncated(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said a spill and never named the cut flag.

    Measured: body_truncated True, truncated absent, body 200000 chars
    (the cap), body_path set. Looking for truncated after a successful
    call reads as a complete body.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)
    repeated = backend.network_get("s", "r1", tmp_path)
    assert "truncated" not in payload
    assert payload["body_truncated"] is True
    assert len(payload["body"]) == _MAX_INLINE_BODY
    assert "body_path" in payload
    assert payload["body_path"] != repeated["body_path"]
    assert Path(str(payload["body_path"])).is_file()
    assert Path(str(repeated["body_path"])).is_file()
    doc = _tool_docstring("web.network.get")
    assert "body_truncated" in doc
    assert "body_path" in doc


def _binary_backend(body_b64: str, monkeypatch: Any) -> WebBackend:
    """A backend whose one request returns ``body_b64`` with base64Encoded set."""

    class _BinCdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return {"body": body_b64, "base64Encoded": True}

    class _BinHandle:
        lock = Lock()
        requests = {"r1": {"requestId": "r1", "url": "https://x/asset"}}
        cdp = _BinCdp()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _BinHandle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_network_get_writes_decoded_bytes_for_a_large_binary_body(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A spilled binary artifact must be the asset, not base64 text.

    The old path handed the base64 string straight to the text spill, so the
    .bin file held base64 characters and could not be read back as the bytes
    it claimed to be. Decoding first makes body_path the real image/font/wasm.
    """
    raw = bytes(range(6)) + b"\xff\xfe\xfd"
    body_b64 = base64.b64encode(raw).decode("ascii")
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 4)
    backend = _binary_backend(body_b64, monkeypatch)

    payload = backend.network_get("s", "r1", tmp_path)

    assert payload["base64_encoded"] is True
    assert payload["size"] == len(raw)
    assert payload["body"] == ""
    assert payload["body_truncated"] is True
    written = Path(str(payload["body_path"]))
    assert written.read_bytes() == raw
    assert written.read_bytes() != body_b64.encode("ascii")


def test_web_network_get_inlines_a_small_binary_as_decodable_base64(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A small binary comes back inline as base64 the caller can decode.

    Nothing is cut, so the inline body is always a whole, decodable base64
    string -- never a truncated one that would fail to decode at the boundary.
    """
    raw = b"\x00\x01\x02\xff"
    body_b64 = base64.b64encode(raw).decode("ascii")
    backend = _binary_backend(body_b64, monkeypatch)

    payload = backend.network_get("s", "r1", tmp_path)

    assert payload["base64_encoded"] is True
    assert payload["size"] == len(raw)
    assert payload["body"] == body_b64
    assert payload["body_truncated"] is False
    assert "body_path" not in payload
    assert base64.b64decode(payload["body"]) == raw
    assert list(tmp_path.iterdir()) == []


def test_web_network_get_caps_a_binary_body_by_its_decoded_length(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A binary body over the cap is refused, and the reported size is decoded."""
    raw = b"\x00\x01\x02\x03\x04\x05"
    body_b64 = base64.b64encode(raw).decode("ascii")
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 1)
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    backend = _binary_backend(body_b64, monkeypatch)

    with pytest.raises(WebError) as caught:
        backend.network_get("s", "r1", tmp_path)

    assert caught.value.code == "too_large"
    assert caught.value.details["size"] == len(raw)
    assert list(tmp_path.iterdir()) == []


def test_web_network_get_measures_the_cap_against_decoded_not_base64_length(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A body the base64 inflated past the cap is kept when its bytes fit.

    Six bytes encode to eight base64 characters. With the cap at six, the old
    base64-length check refused it; measuring the decoded length lets the real
    asset through and spills its true bytes.
    """
    raw = bytes(range(6))
    body_b64 = base64.b64encode(raw).decode("ascii")
    assert len(body_b64) > 6 >= len(raw)
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 4)
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 6)
    backend = _binary_backend(body_b64, monkeypatch)

    payload = backend.network_get("s", "r1", tmp_path)

    assert payload["base64_encoded"] is True
    assert payload["size"] == len(raw)
    assert Path(str(payload["body_path"])).read_bytes() == raw
