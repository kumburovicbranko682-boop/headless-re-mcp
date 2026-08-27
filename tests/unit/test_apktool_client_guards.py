"""ApktoolClient must fail closed around apktool / apksigner subprocesses.

The input-validation suite pins the non-zip precheck. This module covers the
shared ``_run`` error mapping and the per-command guards it protects:

* ``_run`` turning a deadline into ``timeout`` and a launch ``OSError`` into
  ``backend_error``,
* ``decode`` reporting a missing apk and threading the ``-r`` flag through,
* ``build`` reporting an unconfigured tool, a missing decoded tree, and a
  failed rebuild,
* ``sign`` reporting a missing apk, a missing keystore, and a custom keystore
  handed no password or alias.

No JRE is installed; a plain file stands in for each CLI (``available`` only
stats it) and ``run_bounded`` / ``_run`` are monkeypatched so no JVM launches.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut


def _executable(path: Path) -> Path:
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


def _decoded_tree(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# _run error mapping
# --------------------------------------------------------------------------


def test_run_maps_a_deadline_to_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(1800.0, [222])

    monkeypatch.setattr(apktool_client, "run_bounded", fake_run)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apktool.bat", "d"], timeout=10.0)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [222]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("exec format error")

    monkeypatch.setattr(apktool_client, "run_bounded", fake_run)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apktool.bat", "d"], timeout=10.0)
    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------


def test_decode_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "absent.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_threads_the_no_resources_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    out_dir = tmp_path / "out"
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        captured.append(cmd)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    payload = client.decode(apk, out_dir, no_resources=True)
    assert "-r" in captured[0]
    assert payload["decoded_dir"] == str(out_dir)


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------


def test_build_needs_a_configured_tool(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.build(_decoded_tree(tmp_path / "decoded"), tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_reports_a_missing_decoded_tree(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "absent", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_maps_a_failed_rebuild_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        return "", "brut.androlib error", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(_decoded_tree(tmp_path / "decoded"), tmp_path / "out.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1


def test_build_returns_an_unsigned_apk_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_apk = tmp_path / "out.apk"

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        with zipfile.ZipFile(out_apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"rebuilt")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    payload = client.build(_decoded_tree(tmp_path / "decoded"), out_apk)
    assert payload["signed"] is False
    assert payload["size"] > 0
    assert "call apk.sign" in payload["note"]


# --------------------------------------------------------------------------
# sign
# --------------------------------------------------------------------------


def test_sign_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "absent.apk", tmp_path / "signed.apk")
    assert caught.value.code == "not_found"


def test_sign_reports_a_missing_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=tmp_path / "absent.ks")
    assert caught.value.code == "not_found"
    assert "keystore not found" in caught.value.message


def test_sign_requires_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.ks"
    keystore.write_bytes(b"keystore bytes")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"


def _custom_keystore(tmp_path: Path) -> Path:
    keystore = tmp_path / "custom.ks"
    keystore.write_bytes(b"keystore bytes")
    return keystore


def test_sign_signs_and_verifies_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    out_apk = tmp_path / "signed.apk"

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        if cmd[1] == "sign":
            # apksigner reads the password from the child-only env, never argv.
            assert env is not None and env["APKSIGNER_KS_PASS"] == "s3cr3t"
            assert not any("s3cr3t" in part for part in cmd)
            with zipfile.ZipFile(out_apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"signed")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    payload = client.sign(
        apk,
        out_apk,
        keystore=_custom_keystore(tmp_path),
        keystore_password="s3cr3t",
        key_alias="mykey",
    )
    assert payload["signed"] is True
    assert payload["debug_keystore"] is False


def test_sign_scrubs_the_password_from_a_failed_sign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        return "", "keytool: the passphrase s3cr3t was rejected", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=_custom_keystore(tmp_path),
            keystore_password="s3cr3t",
            key_alias="mykey",
        )
    assert caught.value.code == "backend_error"
    assert "s3cr3t" not in str(caught.value.details["stderr"])
    assert "***" in str(caught.value.details["stderr"])


def test_sign_reports_a_failed_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    out_apk = tmp_path / "signed.apk"

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        if cmd[1] == "sign":
            with zipfile.ZipFile(out_apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"signed")
            return "", "", 0
        return "", "DOES NOT VERIFY passphrase s3cr3t", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            out_apk,
            keystore=_custom_keystore(tmp_path),
            keystore_password="s3cr3t",
            key_alias="mykey",
        )
    assert caught.value.code == "backend_error"
    assert "not signed" in caught.value.message
    assert "s3cr3t" not in str(caught.value.details["stderr"])
