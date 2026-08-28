"""proxy.flow.get must serve decoded bodies and return the request body too.

The response body used to come back as the raw on-wire bytes -- so a gzip/br
response was an unreadable compressed blob even though proxy.search and the HAR
export already read the decoded content -- and the request body was dropped
entirely. These pin the decode-by-default behaviour, the raw escape hatch, the
request body, and the content_encoding/decoded disclosure.
"""

from __future__ import annotations

import ast
import gzip
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
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
    """A fake mitmproxy request/response part with a decoding ``content``.

    ``.content`` mimics mitmproxy: it returns the entity bytes with the HTTP
    content-encoding removed, and can be made to raise like a malformed encoding.
    ``.raw_content`` is the on-wire (still-encoded) bytes.
    """

    def __init__(
        self,
        *,
        headers: dict[str, str] | None = None,
        raw_content: bytes = b"",
        content: bytes | None = None,
        content_raises: bool = False,
        **attrs: Any,
    ) -> None:
        self.headers = headers or {}
        self.raw_content = raw_content
        self._content = content
        self._content_raises = content_raises
        for key, value in attrs.items():
            setattr(self, key, value)

    @property
    def content(self) -> bytes | None:
        if self._content_raises:
            raise ValueError("malformed content-encoding")
        return self._content


def _backend_for(flow: Any, monkeypatch: Any) -> ProxyBackend:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

        def ws_dropped(self, flow_id: str) -> int:
            return 0

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def test_gzip_response_body_decodes_to_readable_text(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The headline fix: a gzipped response comes back as its decompressed text.

    Before, flow.get served raw_content -- the gzip bytes -- so the body a caller
    could search (proxy.search decodes) was an unreadable blob when fetched. Now
    the decompressed text inlines, and content_encoding/decoded disclose that it
    was gzip and was decoded.
    """
    text = b'{"marker":"proxy-decode-9449","ok":true}'
    gz = gzip.compress(text)
    assert gz != text
    request = _Part(method="GET", pretty_url="http://x/api", headers={})
    response = _Part(
        status_code=200,
        headers={"content-encoding": "gzip", "content-type": "application/json"},
        raw_content=gz,
        content=text,
    )
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_for(flow, monkeypatch)

    out = backend.flow_get("s", "f1", tmp_path)
    assert out["response"]["body"] == text.decode("utf-8")
    assert out["response"]["size"] == len(text)
    assert out["response"]["content_encoding"] == "gzip"
    assert out["response"]["decoded"] is True
    assert "body_path" not in out["response"]


def test_raw_true_serves_the_on_wire_compressed_bytes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """raw=True returns the exact compressed bytes, spilled and marked not decoded."""
    text = b"x" * 64 + b"\x00compressible-marker-9449"
    gz = gzip.compress(text)
    response = _Part(
        status_code=200,
        headers={"content-encoding": "gzip"},
        raw_content=gz,
        content=text,
    )
    flow = SimpleNamespace(
        request=_Part(method="GET", pretty_url="http://x/api", headers={}),
        response=response,
    )
    backend = _backend_for(flow, monkeypatch)

    out = backend.flow_get("s", "f1", tmp_path, raw=True)
    assert "body" not in out["response"]
    body_path = Path(str(out["response"]["body_path"]))
    assert body_path.read_bytes() == gz
    assert out["response"]["content_encoding"] == "gzip"
    assert out["response"]["decoded"] is False
    assert out["response"]["size"] == len(gz)


def test_request_body_is_returned(tmp_path: Path, monkeypatch: Any) -> None:
    """A POST's request body is now included, not dropped."""
    payload = b'{"user":"alice","token":"secret-9449"}'
    request = _Part(
        method="POST",
        pretty_url="http://x/login",
        headers={"content-type": "application/json"},
        raw_content=payload,
        content=payload,
    )
    response = _Part(status_code=200, headers={}, raw_content=b"ok", content=b"ok")
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_for(flow, monkeypatch)

    out = backend.flow_get("s", "f1", tmp_path)
    assert out["request"]["method"] == "POST"
    assert out["request"]["body"] == payload.decode("utf-8")
    assert out["request"]["size"] == len(payload)
    assert out["response"]["body"] == "ok"


def test_binary_request_body_spills_to_a_path(tmp_path: Path, monkeypatch: Any) -> None:
    """A binary upload body spills to a request body_path, exact bytes on disk."""
    upload = b"\x89PNG\r\n\x1a\n\x00\x00binary-upload-9449"
    request = _Part(
        method="PUT",
        pretty_url="http://x/upload",
        headers={"content-type": "image/png"},
        raw_content=upload,
        content=upload,
    )
    response = _Part(status_code=201, headers={}, raw_content=b"", content=b"")
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_for(flow, monkeypatch)

    out = backend.flow_get("s", "f1", tmp_path)
    assert "body" not in out["request"]
    body_path = Path(str(out["request"]["body_path"]))
    assert body_path.read_bytes() == upload
    assert out["request"]["size"] == len(upload)


def test_undecodable_encoding_is_disclosed_not_decoded(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A body whose .content raises is served raw and marked decoded False.

    A malformed content-encoding must not be silently passed off as plaintext;
    the caller sees decoded False (with the content_encoding) so it knows the
    bytes are still compressed.
    """
    garbage = b"\x1f\x8b\x08not-actually-valid-gzip"
    response = _Part(
        status_code=200,
        headers={"content-encoding": "gzip"},
        raw_content=garbage,
        content_raises=True,
    )
    flow = SimpleNamespace(
        request=_Part(method="GET", pretty_url="http://x/api", headers={}),
        response=response,
    )
    backend = _backend_for(flow, monkeypatch)

    out = backend.flow_get("s", "f1", tmp_path)
    assert out["response"]["content_encoding"] == "gzip"
    assert out["response"]["decoded"] is False
    body_path = Path(str(out["response"]["body_path"]))
    assert body_path.read_bytes() == garbage


def test_plain_body_carries_no_encoding_disclosure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An uncompressed body inlines with no content_encoding/decoded noise."""
    text = b"plain-body-9449"
    response = _Part(status_code=200, headers={}, raw_content=text, content=text)
    flow = SimpleNamespace(
        request=_Part(method="GET", pretty_url="http://x/api", headers={}),
        response=response,
    )
    backend = _backend_for(flow, monkeypatch)

    out = backend.flow_get("s", "f1", tmp_path)
    assert out["response"]["body"] == text.decode("utf-8")
    assert "content_encoding" not in out["response"]
    assert "decoded" not in out["response"]


def test_service_registers_both_spilled_bodies(tmp_path: Path, monkeypatch: Any) -> None:
    """A spilled request body and response body each get a distinct artifact id.

    Registering makes a spilled body openable by id and reclaimable by retention;
    the two land under artifact_id (response) and request_artifact_id (request) so
    neither clobbers the other.
    """
    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        req_body = tmp_path / "req.bin"
        req_body.write_bytes(b"\x00request-bytes")
        resp_body = tmp_path / "resp.bin"
        resp_body.write_bytes(b"\x00response-bytes")
        payload = {
            "id": "f1",
            "request": {"method": "POST", "body_path": str(req_body)},
            "response": {"status": 200, "body_path": str(resp_body)},
        }
        monkeypatch.setattr(service._proxy, "flow_get", lambda *a, **k: payload)
        monkeypatch.setattr(service, "_proxy_artifact_dir", lambda sid: tmp_path)

        seen: dict[str, str] = {}

        def _record(**fields: Any) -> dict[str, str]:
            name = Path(fields["path"]).name
            art_id = f"art-{len(seen)}"
            seen[name] = art_id
            return {"id": art_id}

        monkeypatch.setattr(service, "record_artifact", _record)

        out = service.proxy_flow_get("sess", "f1")
        assert out.ok, out.error
        assert out.data is not None
        assert out.data["artifact_id"] == seen["resp.bin"]
        assert out.data["request_artifact_id"] == seen["req.bin"]
        assert out.data["artifact_id"] != out.data["request_artifact_id"]
    finally:
        service.close_all()


def test_docstring_names_the_new_contract() -> None:
    doc = _tool_docstring("proxy.flow.get")
    for token in ("content_encoding", "decoded", "raw", "request", "body_path"):
        assert token in doc, token
