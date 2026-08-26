from __future__ import annotations

from pathlib import Path

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
