"""Capability, not-found, and failure arms of the apktool/apksigner client.

The non-zip precheck already lives in ``test_apktool_apk_input_validation.py``.
This file covers what it skips: the ``_run`` timeout/launch-failure mapping, the
per-method capability and not-found guards, the decode ``no_resources`` flag,
and the build/sign failure contracts. A stubbed ``_run`` (and, for the helper
itself, a stubbed ``run_bounded``) stands in for the JVM so no real tool runs.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common.bounded_run import TimedOut


def _executable(path: Path) -> Path:
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


# ---------------------------------------------------------------------------
# _run
# ---------------------------------------------------------------------------


def test_run_maps_a_timeout_to_apktool_timeout(monkeypatch: Any) -> None:
    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [4242])

    monkeypatch.setattr(apktool_client, "run_bounded", boom)
    with pytest.raises(ApktoolError) as raised:
        apktool_client._run(["/opt/apktool", "d"], timeout=5.0)
    assert raised.value.code == "timeout"
    assert raised.value.details["killed_pids"] == [4242]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: Any) -> None:
    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("not marked executable")

    monkeypatch.setattr(apktool_client, "run_bounded", boom)
    with pytest.raises(ApktoolError) as raised:
        apktool_client._run(["/opt/apktool", "d"], timeout=5.0)
    assert raised.value.code == "backend_error"


def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(ApktoolError) as raised:
        apktool_client._run(["/opt/apktool"], timeout=0)
    assert raised.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------


def test_decode_refuses_without_apktool(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as raised:
        client.decode(tmp_path / "a.apk", tmp_path / "out")
    assert raised.value.code == "capability_unavailable"


def test_decode_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as raised:
        client.decode(tmp_path / "missing.apk", tmp_path / "out")
    assert raised.value.code == "not_found"


def test_decode_passes_no_resources_flag_and_reports_the_tree(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    out_dir = tmp_path / "out"
    captured: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        captured.append(args)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("m", encoding="utf-8")
        (out_dir / "smali").mkdir()
        (out_dir / "res").mkdir()
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    result = client.decode(apk, out_dir, no_resources=True)

    assert "-r" in captured[0]
    assert result["smali_dirs"] == ["smali"]
    assert result["has_resources"] is True


def test_decode_wraps_a_tool_failure(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _real_apk(tmp_path / "a.apk")

    def fake_run(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "apktool blew up", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as raised:
        client.decode(apk, tmp_path / "out")
    assert raised.value.code == "backend_error"
    assert raised.value.details["exit_code"] == 1


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def test_build_refuses_without_apktool(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as raised:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert raised.value.code == "capability_unavailable"


def test_build_reports_a_missing_decoded_dir(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as raised:
        client.build(tmp_path / "not-a-dir", tmp_path / "out.apk")
    assert raised.value.code == "not_found"


def test_build_wraps_a_tool_failure(tmp_path: Path, monkeypatch: Any) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("m", encoding="utf-8")

    def fake_run(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "build failed", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as raised:
        client.build(decoded, tmp_path / "out.apk")
    assert raised.value.code == "backend_error"
    assert raised.value.details["exit_code"] == 1


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


def test_sign_refuses_without_apksigner(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as raised:
        client.sign(tmp_path / "a.apk", tmp_path / "signed.apk")
    assert raised.value.code == "capability_unavailable"


def test_sign_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as raised:
        client.sign(tmp_path / "missing.apk", tmp_path / "signed.apk")
    assert raised.value.code == "not_found"


def test_sign_reports_a_missing_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as raised:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=tmp_path / "missing.keystore",
            keystore_password="p",
            key_alias="a",
        )
    assert raised.value.code == "not_found"
    assert raised.value.details["path"].endswith("missing.keystore")


def test_sign_requires_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as raised:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore)
    assert raised.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# ApktoolError
# ---------------------------------------------------------------------------


def test_apktool_error_is_a_runtime_error_carrying_code_and_details() -> None:
    err = ApktoolError("not_found", "gone", path="/x")
    assert isinstance(err, RuntimeError)
    assert err.code == "not_found"
    assert err.details["path"] == "/x"
