from __future__ import annotations

import os
from pathlib import Path

import pytest

import headless_re_mcp.backends.jadx.client as jadx_client
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _class_to_java_path,
)


def test_configured_but_missing_jadx_falls_back_to_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale HEADLESS_RE_JADX must not hide a jadx that is on PATH.

    __init__ kept any configured path verbatim, so a typo'd or stale
    HEADLESS_RE_JADX left available False and every apk.decompile /
    apk.export_sources call capability_unavailable even with jadx on PATH --
    while doctor's probe_optional_tool and the r2/webcrack/wabt resolvers fall
    back to PATH, so doctor reported jadx detected while the tools said missing.
    """
    on_path = tmp_path / "path-jadx"
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(jadx_client, "_discover_jadx", lambda: on_path)

    client = JadxClient(tmp_path / "missing-jadx")

    assert client.available is True
    assert client.executable == on_path


def test_missing_jadx_everywhere_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_discover_jadx", lambda: None)

    client = JadxClient(tmp_path / "missing-jadx")

    assert client.available is False


def test_configured_jadx_that_exists_is_used(tmp_path: Path) -> None:
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")

    client = JadxClient(tool)

    assert client.available is True
    assert client.executable == tool


@pytest.mark.parametrize(
    "class_name",
    [
        "../../outside",
        "com..outside.Main",
        r"C:\outside",
        "com.example.\x00Main",
    ],
)
def test_jadx_rejects_class_names_that_are_not_relative_java_paths(
    class_name: str,
) -> None:
    with pytest.raises(JadxError) as caught:
        _class_to_java_path(class_name)

    assert caught.value.code == "invalid_params"


def test_jadx_keeps_valid_dotted_and_smali_class_names() -> None:
    assert _class_to_java_path("com.example.Main") == Path("com/example/Main.java")
    assert _class_to_java_path("Lcom/example/Main$Inner;") == Path(
        "com/example/Main.java"
    )


@pytest.mark.skipif(os.name == "nt", reason="creating test symlinks needs Windows privileges")
def test_jadx_does_not_read_a_source_symlink_outside_its_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "private.java"
    outside.write_text("private source", encoding="utf-8")
    out = tmp_path / "out"
    candidate = out / "sources" / "com" / "example" / "Main.java"
    candidate.parent.mkdir(parents=True)
    candidate.symlink_to(outside)
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "invalid_params"
    assert "private source" not in str(caught.value.details)


@pytest.mark.skipif(os.name == "nt", reason="creating test symlinks needs Windows privileges")
def test_jadx_rejects_a_sources_directory_redirected_outside_the_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "sources").symlink_to(outside, target_is_directory=True)
    client = JadxClient(tmp_path / "jadx")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {})

    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert caught.value.code == "backend_error"
