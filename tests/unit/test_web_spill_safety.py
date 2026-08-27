from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.web import client as web_client


def test_spill_text_returns_a_small_body_inline_without_touching_disk() -> None:
    """A body under the inline ceiling is returned as-is with no spill path and
    no artifact directory created -- the common case must not write to disk."""
    artifact_dir = Path("/definitely/not/created/by/this/call")
    inline, path, truncated = web_client._spill_text(
        "small body",
        artifact_dir=artifact_dir,
        filename="unused.txt",
        kind="script source",
    )
    assert inline == "small body"
    assert path is None
    assert truncated is False
    assert not artifact_dir.exists()


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


def test_spill_bytes_rejects_a_filename_that_escapes_the_artifact_directory(
    tmp_path: Path,
) -> None:
    """The binary-body path must guard its filename exactly as the text path
    does: a response body cannot be written outside its session artifact dir."""
    artifact_dir = tmp_path / "artifacts" / "web"
    escaped = tmp_path / "escaped.bin"

    with pytest.raises(web_client.WebError) as caught:
        web_client._spill_bytes(
            b"\x89PNG\r\n",
            artifact_dir=artifact_dir,
            filename="../../escaped.bin",
            kind="response body",
        )

    assert caught.value.code == "invalid_params"
    assert not artifact_dir.exists()
    assert not escaped.exists()


def test_spill_bytes_refuses_a_body_over_the_capture_cap_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cap is measured on the real bytes and enforced before any write, so
    an oversized binary body never lands on disk even momentarily."""
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    artifact_dir = tmp_path / "artifacts"

    with pytest.raises(web_client.WebError) as caught:
        web_client._spill_bytes(
            b"\x00\x01\x02\x03\x04\x05",
            artifact_dir=artifact_dir,
            filename="body.bin",
            kind="response body",
        )

    assert caught.value.code == "too_large"
    assert caught.value.details["size"] == 6
    assert not artifact_dir.exists()


def test_spill_bytes_writes_a_body_within_the_cap_to_the_artifact_dir(
    tmp_path: Path,
) -> None:
    raw = b"\x89PNG\r\n\x1a\n binary body"
    out = web_client._spill_bytes(
        raw,
        artifact_dir=tmp_path,
        filename="body.bin",
        kind="response body",
    )
    assert out == tmp_path / "body.bin"
    assert out.read_bytes() == raw
