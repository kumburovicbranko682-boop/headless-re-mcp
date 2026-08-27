"""apk.decompile / apk.export_sources refuse a non-zip input before the JVM.

jadx needs a zip-format APK, and it runs on the session's APK target without
apk.open (the only step that parses it as a zip) being a prerequisite. Before
the precheck jadx only confirmed the path existed, so a truncated download, a
wrong path, or a build output that slipped past its own validation reached the
tool, which started a JVM and only then failed -- ``_run`` read the empty tree
and reported "jadx produced no sources" as a backend_error, turning a parameter
mistake into an opaque failure after paying the startup cost. The precheck
turns that into a precise invalid_params up front, the same fail-fast shape as
apktool d / apksigner rejecting a non-zip before their JVM.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _executable(path: Path) -> Path:
    # available only checks is_file(), so any real file stands in for jadx.
    path.write_text("x\n", encoding="utf-8")
    return path


def _non_zip(path: Path) -> Path:
    path.write_bytes(b"this is a truncated download, not a zip archive")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


class _Reached(Exception):
    """Raised by the run_bounded stub to prove control got past the precheck."""


def test_export_sources_rejects_non_zip_before_launching_jadx(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _non_zip(tmp_path / "a.apk")
    calls: list[tuple[Any, ...]] = []

    def _run_bounded(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        raise AssertionError("run_bounded must not be reached for a non-zip input")

    monkeypatch.setattr(jadx_client, "run_bounded", _run_bounded)
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(JadxError) as info:
        client.export_sources(apk, tmp_path / "out")
    assert info.value.code == "invalid_params"
    assert calls == []


def test_decompile_rejects_non_zip_before_launching_jadx(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _non_zip(tmp_path / "a.apk")

    def _run_bounded(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("run_bounded must not be reached for a non-zip input")

    monkeypatch.setattr(jadx_client, "run_bounded", _run_bounded)
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(JadxError) as info:
        client.decompile(apk, tmp_path / "out", "Lcom/example/Main;")
    assert info.value.code == "invalid_params"


def test_export_sources_accepts_a_real_zip_and_reaches_jadx(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A valid zip must pass the precheck and hand off to jadx as before."""
    apk = _real_apk(tmp_path / "a.apk")

    def _run_bounded(*_args: Any, **_kwargs: Any) -> Any:
        raise _Reached

    monkeypatch.setattr(jadx_client, "run_bounded", _run_bounded)
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(_Reached):
        client.export_sources(apk, tmp_path / "out")
