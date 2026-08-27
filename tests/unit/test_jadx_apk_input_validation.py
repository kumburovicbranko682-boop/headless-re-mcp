"""apk.decompile / apk.export_sources refuse a non-zip input before the JVM.

jadx opening an APK needs a zip-format archive. Before the precheck the client
only confirmed the path existed, so a truncated download or a file replaced on
disk after the session opened reached jadx, which started a JVM and only then
failed -- and ``_run`` could only report that as "jadx produced no sources", a
backend_error, after paying the startup cost. The precheck turns that into a
precise invalid_params up front, the same fail-fast guard apktool's decode /
sign already apply. An apk.* session target is always a validated zip, so this
never rejects a real input; it catches the stale/corrupt file.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError


def _executable(path: Path) -> Path:
    # available only checks is_file(), so any real file stands in for the jadx
    # CLI here.
    path.write_text("#!/bin/sh\n", encoding="utf-8")
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


def test_export_sources_rejects_non_zip_input_before_launching_jadx(tmp_path: Path) -> None:
    client = JadxClient(_executable(tmp_path / "jadx"))
    apk = _non_zip(tmp_path / "app.apk")
    calls: list[tuple[Any, ...]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        calls.append((cmd, kwargs))
        raise AssertionError("run_bounded must not be reached")

    with (
        patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run),
        pytest.raises(JadxError) as caught,
    ):
        client.export_sources(apk, tmp_path / "out")

    assert caught.value.code == "invalid_params"
    assert calls == []


def test_decompile_rejects_non_zip_input_before_launching_jadx(tmp_path: Path) -> None:
    client = JadxClient(_executable(tmp_path / "jadx"))
    apk = _non_zip(tmp_path / "app.apk")
    calls: list[tuple[Any, ...]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        calls.append((cmd, kwargs))
        raise AssertionError("run_bounded must not be reached")

    with (
        patch("headless_re_mcp.backends.jadx.client.run_bounded", fake_run),
        pytest.raises(JadxError) as caught,
    ):
        client.decompile(apk, tmp_path / "out", "com.example.Main")

    assert caught.value.code == "invalid_params"
    assert calls == []


def test_export_sources_accepts_a_real_zip_and_reaches_jadx(tmp_path: Path) -> None:
    """A valid zip must pass the precheck and hand off to jadx as before."""
    client = JadxClient(_executable(tmp_path / "jadx"))
    apk = _real_apk(tmp_path / "app.apk")

    def _boom(cmd: list[str], **kwargs: Any) -> Any:
        raise _Reached

    with (
        patch("headless_re_mcp.backends.jadx.client.run_bounded", _boom),
        pytest.raises(_Reached),
    ):
        client.export_sources(apk, tmp_path / "out")
