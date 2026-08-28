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


def test_decode_validates_the_apk_before_the_capability_gate(tmp_path: Path) -> None:
    """A bad apk reads as its own error even where apktool is not configured.

    decode() used to check the apktool/JRE capability before it looked at the
    apk, so on a host without apktool a missing path or a non-zip surfaced as
    capability_unavailable ("configure apktool") rather than the not_found /
    invalid_params it is -- the same masking web.open, adb._device, jsre and
    jadx reject. The pure apk checks now run first; the capability gate only
    fires once the apk is a real archive. With apktool unconfigured (so the gate
    would fire if reached first), a missing apk is not_found and a non-zip is
    invalid_params.
    """
    client = ApktoolClient(None, None)  # apktool not configured; the gate is live
    assert client.available is False

    with pytest.raises(ApktoolError) as missing:
        client.decode(tmp_path / "absent.apk", tmp_path / "out")
    assert missing.value.code == "not_found"

    with pytest.raises(ApktoolError) as non_zip:
        client.decode(_non_zip(tmp_path / "a.apk"), tmp_path / "out")
    assert non_zip.value.code == "invalid_params"


def test_sign_validates_the_apk_before_the_capability_gate(tmp_path: Path) -> None:
    """The apksigner half of the same guard: a bad apk is not_found /
    invalid_params, not capability_unavailable, even with apksigner absent."""
    client = ApktoolClient(None, None)  # apksigner not configured; the gate is live
    assert client.signer_available is False

    with pytest.raises(ApktoolError) as missing:
        client.sign(tmp_path / "absent.apk", tmp_path / "signed.apk")
    assert missing.value.code == "not_found"

    with pytest.raises(ApktoolError) as non_zip:
        client.sign(_non_zip(tmp_path / "a.apk"), tmp_path / "signed.apk")
    assert non_zip.value.code == "invalid_params"


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
