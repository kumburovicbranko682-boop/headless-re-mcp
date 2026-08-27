"""proxy.flow.get must not hand back a binary body as mangled U+FFFD text.

An inline (<=200000 byte) response body was decoded with
``bytes.decode("utf-8", errors="replace")``. For the many flows a capturing
proxy sees that are not UTF-8 -- images, protobuf, an encrypted blob, or a body
still gzip/br-compressed on the wire -- that returns a string full of U+FFFD
replacement characters, lossy and with nothing to say it was ever bytes. The
sibling ``web.network.get`` already reports ``base64_encoded``; ``flow_get`` now
does the same, returning the exact bytes base64-encoded (and flagged) when they
are not valid UTF-8, and plain text (flagged false) when they are. The bytes
returned are the same bytes the recorder held -- nothing is decompressed here,
so this adds no decode-bomb surface.
"""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend


def _backend(monkeypatch: Any, raw_content: bytes) -> ProxyBackend:
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/1", headers={"accept": "*/*"}
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/octet-stream"},
        raw_content=raw_content,
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def test_a_binary_inline_body_comes_back_base64_not_replacement_text(
    tmp_path: Path, monkeypatch: Any
) -> None:
    raw = b"\x89PNG\r\n\x1a\n\x00\xff\xfe\x01\x02"  # invalid UTF-8
    payload = _backend(monkeypatch, raw).flow_get("s", "f1", tmp_path)
    resp = payload["response"]
    assert resp["base64_encoded"] is True
    # The exact bytes round-trip; no U+FFFD, no loss.
    assert base64.b64decode(resp["body"]) == raw
    assert "\ufffd" not in resp["body"]
    assert "body_path" not in resp


def test_a_utf8_inline_body_is_still_plain_text(tmp_path: Path, monkeypatch: Any) -> None:
    raw = '{"ok": true, "s": "héllo"}'.encode()
    payload = _backend(monkeypatch, raw).flow_get("s", "f1", tmp_path)
    resp = payload["response"]
    assert resp["base64_encoded"] is False
    assert resp["body"] == raw.decode("utf-8")
    assert "body_path" not in resp
