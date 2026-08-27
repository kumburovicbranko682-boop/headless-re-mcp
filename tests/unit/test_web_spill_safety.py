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


def test_spill_preview_drops_a_dangling_partial_char_on_a_byte_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The inline preview is a byte slice, so the cap can land mid-character.

    Every other preview test caps on a clean multi-byte boundary, where
    ``errors="ignore"`` and ``errors="replace"`` decode identically -- so the
    choice of error handler is inert. Cap ``ééé`` (six bytes) at five: the slice
    ends one byte into the third ``é``. The dangling byte must be dropped, not
    surfaced as U+FFFD, and the spilled artifact must still hold all six bytes.
    """
    monkeypatch.setattr(web_client, "_MAX_INLINE_BODY", 5)
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)

    preview, path, truncated = web_client._spill_text(
        "ééé",
        artifact_dir=tmp_path,
        filename="source.js",
        kind="script source",
    )

    assert preview == "éé"
    assert "\ufffd" not in preview
    assert len(preview.encode("utf-8")) == 4
    assert truncated is True
    assert path is not None
    assert path.read_bytes() == "ééé".encode()


def test_spill_bytes_refuses_a_body_over_the_capture_cap_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The raw-bytes spill is the binary counterpart of the text spill.

    It is only ever reached through web.network.get's base64 branch, which the
    fixtures always feed a small, in-cap blob -- so the capture-cap refusal has
    never fired. Hand it bytes past the cap directly: it must raise too_large
    reporting the real byte size, and it must refuse *before* creating the
    artifact directory, so an oversized binary body cannot touch the disk.
    """
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    artifact_dir = tmp_path / "artifacts"

    with pytest.raises(web_client.WebError) as caught:
        web_client._spill_bytes(
            b"12345",
            artifact_dir=artifact_dir,
            filename="body.bin",
            kind="response body",
        )

    assert caught.value.code == "too_large"
    assert caught.value.details["size"] == 5
    assert caught.value.details["cap"] == 4
    assert not artifact_dir.exists()


def test_spill_bytes_rejects_a_filename_that_escapes_the_artifact_directory(
    tmp_path: Path,
) -> None:
    """web.network.get names its own artifact via uuid4, so the filename guard
    here is unreachable through the public path -- pin it directly. A traversing
    name is refused as invalid_params, and nothing is written inside or outside
    the artifact directory.
    """
    artifact_dir = tmp_path / "artifacts" / "web"
    escaped = tmp_path / "escaped.bin"

    with pytest.raises(web_client.WebError) as caught:
        web_client._spill_bytes(
            b"payload",
            artifact_dir=artifact_dir,
            filename="../../escaped.bin",
            kind="response body",
        )

    assert caught.value.code == "invalid_params"
    assert not artifact_dir.exists()
    assert not escaped.exists()


def test_spill_bytes_writes_the_exact_bytes_under_the_cap(
    tmp_path: Path,
) -> None:
    """The in-cap happy path returns a path under the artifact dir holding the
    exact bytes handed in -- no base64, no re-encoding.
    """
    raw = b"\x89PNG\r\n\x1a\n\x00\x01\x02"
    out = web_client._spill_bytes(
        raw,
        artifact_dir=tmp_path,
        filename="body.bin",
        kind="response body",
    )

    assert out.parent == tmp_path
    assert out.name == "body.bin"
    assert out.read_bytes() == raw
