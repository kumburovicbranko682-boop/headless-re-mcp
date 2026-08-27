from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client


def test_spill_rejects_a_filename_that_escapes_the_artifact_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 1)
    artifact_dir = tmp_path / "artifacts" / "web"
    escaped = tmp_path / "escaped.txt"

    with pytest.raises(web_client.WebError) as caught:
        web_client._spill_text(
            "large enough to spill",
            artifact_dir=artifact_dir,
            filename="../../escaped.txt",
            kind="script source",
        )

    assert caught.value.code == "invalid_params"
    assert not artifact_dir.exists()
    assert not escaped.exists()


def test_spill_applies_the_capture_limit_to_encoded_bytes_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 1)
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    artifact_dir = tmp_path / "artifacts"

    with pytest.raises(web_client.WebError) as caught:
        web_client._spill_text(
            "ééé",
            artifact_dir=artifact_dir,
            filename="source.js",
            kind="script source",
        )

    assert caught.value.code == "too_large"
    assert caught.value.details["size"] == 6
    assert not artifact_dir.exists()


def test_spill_preview_is_bounded_by_encoded_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 4)
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)

    preview, path, truncated = web_client._spill_text(
        "ééé",
        artifact_dir=tmp_path,
        filename="source.js",
        kind="script source",
    )

    assert preview == "éé"
    assert len(preview.encode("utf-8")) == 4
    assert path == tmp_path / "source.js"
    assert path.read_bytes() == "ééé".encode()
    assert truncated is True


def test_spill_forces_a_disk_copy_when_the_encoded_size_alone_exceeds_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A body under the raw preview cap can still blow the JSON-encoded budget.

    Before, such a body inlined whole with no spill, so the transport discarded
    the entire reply (the body_path pointer with it). Now the inline is trimmed
    to the encoded budget and the full body is spilled, so a truncated reply
    always points at the rest.
    """
    import json

    from headless_re_mcp.backends.common import json_budget

    monkeypatch.setattr(json_budget, "RESULT_BUDGET_BYTES", 400)
    monkeypatch.setattr(web_client, "_WEB_FIELD_RESERVE", 100)
    # Well under the raw preview cap (default 200000), so only the encoded bound
    # bites -- the old size<=cap path would have inlined this whole.
    body = "a" * 2000

    inline, path, truncated = web_client._spill_text(
        body,
        artifact_dir=tmp_path,
        filename="body.bin",
        kind="response body",
    )

    assert truncated is True
    assert path is not None and path.read_bytes() == body.encode()
    assert len(inline) < len(body)
    assert len(json.dumps(inline, ensure_ascii=False).encode("utf-8")) <= 400 - 100


def test_network_get_reply_stays_under_the_transport_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A big captured body must return with its body_path, not be nuked whole.

    Builds a response-body reply the size a real capture produces, with a
    max-length url alongside it, and confirms the transport passes it through
    intact instead of replacing the whole envelope (body_path and all) with a
    ~16 KiB summary. Before the encoded bound, a 200 KB body plus a 16 KB url
    could tip the reply over the budget.
    """
    from threading import Lock

    from headless_re_mcp.agent.context import bounded_tool_result
    from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
    from headless_re_mcp.backends.web.client import _MAX_URL_BYTES, WebBackend

    class _Cdp:
        def send(self, method: str, params: dict[str, object]) -> dict[str, object]:
            return {"body": "z" * 5_000_000, "base64Encoded": False}

    class _Handle:
        lock = Lock()
        requests = {
            "r1": {
                "requestId": "r1",
                "url": "h" * _MAX_URL_BYTES,
                "method": "GET",
                "status": 200,
                "mimeType": "text/html",
            }
        }
        response_headers: dict[str, dict[str, object]] = {}
        request_headers: dict[str, dict[str, str]] = {}
        cdp = _Cdp()

    class _Immediate:
        def call(self, work: Any, timeout: float | None = None) -> Any:
            return work()

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.network_get("s", "r1", tmp_path)

    assert payload["body_truncated"] is True
    assert "body_path" in payload
    bounded, truncated = bounded_tool_result(payload, max_bytes=RESULT_BUDGET_BYTES)
    assert truncated is False, "network_get reply should already fit the transport budget"
    assert "summary" not in bounded
    assert bounded.get("body_path") == payload["body_path"]
