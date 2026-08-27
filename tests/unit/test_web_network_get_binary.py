"""web.network.get must deliver a binary body as raw bytes, not base64 text."""

from __future__ import annotations

import base64
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


def _backend_returning(monkeypatch: Any, response: dict[str, Any]) -> WebBackend:
    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            return response

    class _Handle:
        lock = Lock()
        requests = {"r1": {"requestId": "r1", "url": "https://x/img", "mimeType": "image/png"}}
        cdp = _Cdp()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_binary_body_is_decoded_to_raw_bytes_on_disk(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A base64 binary body used to be written to the .bin artifact still base64-encoded.

    Measured: a PNG-signature blob -> body_path holds the exact decoded bytes,
    body is empty, body_truncated false, base64_encoded true, and body_bytes
    is the decoded length. An agent opening body_path gets the image, not text.
    """
    blob = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 3
    backend = _backend_returning(
        monkeypatch,
        {"body": base64.b64encode(blob).decode("ascii"), "base64Encoded": True},
    )

    payload = backend.network_get("s", "r1", tmp_path)

    assert payload["base64_encoded"] is True
    assert payload["body"] == ""
    assert payload["body_truncated"] is False
    assert payload["body_bytes"] == len(blob)
    spilled = Path(payload["body_path"])
    assert spilled.parent == tmp_path
    assert spilled.suffix == ".bin"
    assert spilled.read_bytes() == blob


def test_invalid_base64_body_reports_an_error_rather_than_lying(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A body flagged base64 that will not decode must surface, not be treated as bytes.

    And it must keep the same documented shape as the getResponseBody-failed
    path: this error arises one step later, but a caller reading result["body"]
    / base64_encoded / body_truncated must not hit a missing key. Before the
    fix this branch returned only the request metadata plus body_error, so
    payload["body"] raised KeyError -- the very failure the sibling path guards.
    """
    # Five base64-alphabet characters: a valid data run is a multiple of four,
    # so a length of five (4n+1) can never be legal and always raises.
    backend = _backend_returning(
        monkeypatch,
        {"body": "aaaaa", "base64Encoded": True},
    )

    payload = backend.network_get("s", "r1", tmp_path)

    assert "body_error" in payload
    assert "body_path" not in payload
    # Full documented shape, so the two error paths cannot drift apart again.
    assert payload["body"] == ""
    assert payload["base64_encoded"] is False
    assert payload["body_truncated"] is False
    # The request metadata the caller already had is preserved.
    assert payload["url"] == "https://x/img"
    assert payload["mimeType"] == "image/png"
