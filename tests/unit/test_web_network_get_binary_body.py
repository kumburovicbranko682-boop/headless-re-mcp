"""web.network.get must handle a base64-encoded (binary) response body.

A binary body reaches CDP base64-encoded. Treated as text it (a) is measured
against the ~33%-inflated base64 length, so a payload that fits the capture cap
is refused as too_large, and (b) spills base64 text into a .bin file, so
body_path is not the real artifact a downstream tool could use. These pin the
bytes-aware path: the cap is measured against the decoded size and the spill is
the raw bytes.
"""

from __future__ import annotations

import base64
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import WebBackend, WebError


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


def _make_backend(monkeypatch: Any, raw: bytes) -> WebBackend:
    encoded = base64.b64encode(raw).decode("ascii")

    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            del method, params
            return {"body": encoded, "base64Encoded": True}

    class _Handle:
        lock = Lock()
        requests = {"r1": {"requestId": "r1", "url": "https://x"}}
        cdp = _Cdp()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_small_binary_body_round_trips_as_base64(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A small binary body inlines as base64 that decodes back to the bytes."""
    raw = bytes(range(256))
    backend = _make_backend(monkeypatch, raw)
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["body_truncated"] is False
    assert "body_path" not in payload
    assert base64.b64decode(payload["body"]) == raw


def test_binary_body_that_fits_decoded_is_not_refused_for_base64_inflation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The old text path measured base64 length and refused a body that fits.

    cap 1000: 900 raw bytes fit on disk, but their base64 is 1200 chars, so the
    text path raised too_large. The bytes-aware path measures the decoded size,
    spills the raw bytes (body_path is the real artifact, not base64 text), and
    leaves a decodable base64 head as the inline preview.
    """
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 1000)
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 100)
    raw = bytes((index * 7) % 256 for index in range(900))
    assert len(base64.b64encode(raw)) > 1000
    backend = _make_backend(monkeypatch, raw)
    payload = backend.network_get("s", "r1", tmp_path)
    assert payload["base64_encoded"] is True
    assert payload["body_truncated"] is True
    path = Path(str(payload["body_path"]))
    assert path.is_file()
    assert path.read_bytes() == raw
    assert base64.b64decode(payload["body"]) == raw[: (100 // 4) * 3]


def test_binary_body_over_the_cap_when_decoded_is_refused(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A decoded size over the cap is still refused, and nothing is written."""
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 1000)
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 100)
    raw = bytes(1200)
    backend = _make_backend(monkeypatch, raw)
    with pytest.raises(WebError) as caught:
        backend.network_get("s", "r1", tmp_path)
    assert caught.value.code == "too_large"
    assert list(tmp_path.iterdir()) == []
