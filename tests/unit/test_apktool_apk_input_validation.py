"""apk.decode / apk.sign refuse a non-zip input before launching the JVM.

apktool ``d`` and apksigner both require a zip-format APK. Before the precheck
they only confirmed the path existed, so a truncated download, a wrong path, or
a build output that slipped past its own validation reached the tool, which
started a JVM and only then failed with an opaque Java error -- reporting a
parameter mistake as a backend failure after paying the startup cost. The
precheck turns that into a precise invalid_params up front, the same fail-fast
shape as ``build`` validating its own output and the wasm tools checking the
``\\0asm`` magic before launching wabt.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


def _executable(path: Path) -> Path:
    # available / signer_available only check is_file(), so any real file
    # stands in for the apktool / apksigner CLI here.
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
    """Raised by the _run stub to prove control got past the precheck."""


def test_decode_rejects_non_zip_input_before_launching_apktool(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _non_zip(tmp_path / "a.apk")
    calls: list[tuple[Any, ...]] = []

    def _run(*args: Any, **kwargs: Any) -> tuple[str, str, int]:
        calls.append((args, kwargs))
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.decode(apk, tmp_path / "out")
    assert info.value.code == "invalid_params"
    assert calls == []


def test_sign_rejects_non_zip_input_before_launching_apksigner(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _non_zip(tmp_path / "a.apk")
    calls: list[tuple[Any, ...]] = []

    def _run(*args: Any, **kwargs: Any) -> tuple[str, str, int]:
        calls.append((args, kwargs))
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as info:
        client.sign(apk, tmp_path / "signed.apk")
    assert info.value.code == "invalid_params"
    assert calls == []


def test_decode_accepts_a_real_zip_and_reaches_apktool(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A valid zip must pass the precheck and hand off to apktool as before."""
    apk = _real_apk(tmp_path / "a.apk")

    def _boom(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        raise _Reached

    monkeypatch.setattr(apktool_client, "_run", _boom)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(_Reached):
        client.decode(apk, tmp_path / "out")


def test_sign_accepts_a_real_zip_and_reaches_the_signer(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A valid zip must pass the precheck and hand off to apksigner as before."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "debug.keystore"
    keystore.write_bytes(b"ks")

    def _boom(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        raise _Reached

    monkeypatch.setattr(apktool_client, "_run", _boom)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(_Reached):
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password="android",
            key_alias="androiddebugkey",
        )
