"""Guard and subprocess-mapping coverage for the apktool/apksigner adapter.

test_apktool_apk_input_validation.py pins the zip precheck; this file covers
the rest of the error surface that never launches (or must survive) a JVM:
the shared _run's timeout and launch-failure mapping, the not-found and
capability guards on decode/build/sign, the no-resources flag wiring, a build
that fails, and the custom-keystore password/alias requirement. All of it runs
without a real apktool by stubbing run_bounded / _run.
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
    path.mkdir(parents=True, exist_ok=True)
    (path / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# _run: deadline and launch-failure mapping                                   #
# --------------------------------------------------------------------------- #
def test_run_maps_a_timeout_to_an_apktool_timeout_error(monkeypatch: Any) -> None:
    def times_out(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(3.0, [4242])

    monkeypatch.setattr(apktool_client, "run_bounded", times_out)
    with pytest.raises(ApktoolError) as info:
        apktool_client._run(["/opt/apktool", "d"], timeout=30.0)
    assert info.value.code == "timeout"
    assert info.value.message == "apktool timed out"
    assert info.value.details["killed_pids"] == [4242]


def test_run_returns_decoded_streams_on_success(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        apktool_client,
        "run_bounded",
        lambda cmd, **kwargs: Completed(0, b"out-bytes", b"err-bytes"),
    )
    stdout, stderr, code = apktool_client._run(["/opt/apktool", "d"], timeout=30.0)
    assert (stdout, stderr, code) == ("out-bytes", "err-bytes", 0)


def test_run_maps_a_launch_failure_to_a_backend_error(monkeypatch: Any) -> None:
    def cannot_exec(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("exec format error")

    monkeypatch.setattr(apktool_client, "run_bounded", cannot_exec)
    with pytest.raises(ApktoolError) as info:
        apktool_client._run(["/opt/apktool", "d"], timeout=30.0)
    assert info.value.code == "backend_error"
    assert "failed to launch" in info.value.message


def test_run_rejects_an_out_of_range_timeout(monkeypatch: Any) -> None:
    """clamp_cli_timeout raising InvalidTimeout is a parameter error, not a crash."""
    called = False

    def unexpected(cmd: list[str], **kwargs: Any) -> Completed:
        nonlocal called
        called = True
        return Completed(0, b"", b"")

    monkeypatch.setattr(apktool_client, "run_bounded", unexpected)
    with pytest.raises(ApktoolError) as info:
        apktool_client._run(["/opt/apktool", "d"], timeout=float("nan"))
    assert info.value.code == "invalid_params"
    assert called is False, "an invalid timeout must be caught before the subprocess"


# --------------------------------------------------------------------------- #
# decode guards and flag wiring                                               #
# --------------------------------------------------------------------------- #
def test_decode_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as info:
        client.decode(_real_apk(tmp_path / "a.apk"), tmp_path / "out")
    assert info.value.code == "capability_unavailable"


def test_decode_of_a_missing_apk_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.decode(tmp_path / "gone.apk", tmp_path / "out")
    assert info.value.code == "not_found"


def test_decode_passes_the_no_resources_flag_and_reports_its_outputs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    seen: dict[str, list[str]] = {}

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        seen["cmd"] = cmd
        out = Path(cmd[cmd.index("-o") + 1])
        (out / "smali").mkdir(parents=True, exist_ok=True)
        (out / "res").mkdir(parents=True, exist_ok=True)
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    result = client.decode(apk, tmp_path / "out", no_resources=True)

    assert "-r" in seen["cmd"]
    assert result["smali_dirs"] == ["smali"]
    assert result["has_resources"] is True


def test_decode_reports_a_failed_run_with_no_manifest(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _real_apk(tmp_path / "a.apk")

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "boom", 1

    monkeypatch.setattr(apktool_client, "_run", stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.decode(apk, tmp_path / "out")
    assert info.value.code == "backend_error"
    assert info.value.details["exit_code"] == 1


# --------------------------------------------------------------------------- #
# build guards                                                                #
# --------------------------------------------------------------------------- #
def test_build_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as info:
        client.build(_decoded_tree(tmp_path / "decoded"), tmp_path / "out.apk")
    assert info.value.code == "capability_unavailable"


def test_build_of_a_missing_tree_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.build(tmp_path / "no-such-dir", tmp_path / "out.apk")
    assert info.value.code == "not_found"


def test_build_of_a_tree_without_a_manifest_is_invalid_params(tmp_path: Path) -> None:
    empty = tmp_path / "decoded"
    empty.mkdir()
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.build(empty, tmp_path / "out.apk")
    assert info.value.code == "invalid_params"


def test_build_reports_a_failed_run_that_wrote_no_apk(tmp_path: Path, monkeypatch: Any) -> None:
    tree = _decoded_tree(tmp_path / "decoded")

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "gradle failed", 1

    monkeypatch.setattr(apktool_client, "_run", stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.build(tree, tmp_path / "out.apk")
    assert info.value.code == "backend_error"
    assert info.value.details["exit_code"] == 1


def test_build_rejects_a_zero_byte_or_non_zip_output(tmp_path: Path, monkeypatch: Any) -> None:
    tree = _decoded_tree(tmp_path / "decoded")
    out_apk = tmp_path / "out.apk"

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        out_apk.write_bytes(b"")  # exit 0 but a truncated, unusable file
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as info:
        client.build(tree, out_apk)
    assert info.value.code == "backend_error"
    assert "empty or invalid" in info.value.message


def test_build_reports_a_valid_unsigned_rebuild(tmp_path: Path, monkeypatch: Any) -> None:
    tree = _decoded_tree(tmp_path / "decoded")
    out_apk = tmp_path / "out.apk"

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        with zipfile.ZipFile(out_apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"rebuilt")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    result = client.build(tree, out_apk)

    assert result["signed"] is False
    assert result["size"] > 0
    assert "unsigned" in result["note"]


# --------------------------------------------------------------------------- #
# sign guards                                                                 #
# --------------------------------------------------------------------------- #
def test_sign_without_apksigner_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as info:
        client.sign(_real_apk(tmp_path / "a.apk"), tmp_path / "signed.apk")
    assert info.value.code == "capability_unavailable"


def test_sign_of_a_missing_apk_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as info:
        client.sign(tmp_path / "gone.apk", tmp_path / "signed.apk")
    assert info.value.code == "not_found"


def test_sign_with_a_missing_keystore_is_not_found(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as info:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=tmp_path / "absent.keystore",
            keystore_password="pw",
            key_alias="a",
        )
    assert info.value.code == "not_found"


def test_sign_with_a_custom_keystore_requires_password_and_alias(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as info:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore)
    assert info.value.code == "invalid_params"
    assert "key_alias" in info.value.message


def _signing_client(tmp_path: Path) -> tuple[ApktoolClient, Path, Path, Path]:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    out_apk = tmp_path / "signed.apk"
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    return client, apk, keystore, out_apk


def test_sign_signs_then_verifies_and_passes_the_password_by_env(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The happy path: the password rides an env var, never argv, and verify runs."""
    client, apk, keystore, out_apk = _signing_client(tmp_path)
    argvs: list[list[str]] = []
    envs: list[dict[str, str] | None] = []

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        argvs.append(cmd)
        envs.append(kwargs.get("env"))
        if "sign" in cmd:
            with zipfile.ZipFile(out_apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"signed")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", stub)

    result = client.sign(
        apk, out_apk, keystore=keystore, keystore_password="s3cret", key_alias="mykey"
    )

    assert result["signed"] is True
    assert result["debug_keystore"] is False
    sign_argv = argvs[0]
    assert "s3cret" not in sign_argv, "the password must never appear on argv"
    assert f"env:{apktool_client._PASSWORD_ENV}" in sign_argv
    assert envs[0] is not None and envs[0][apktool_client._PASSWORD_ENV] == "s3cret"
    assert any("verify" in argv for argv in argvs), "a signed apk must be verified"


def test_sign_scrubs_the_password_from_a_failed_signer(tmp_path: Path, monkeypatch: Any) -> None:
    client, apk, keystore, out_apk = _signing_client(tmp_path)

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "keytool error: s3cret was rejected", 1

    monkeypatch.setattr(apktool_client, "_run", stub)
    with pytest.raises(ApktoolError) as info:
        client.sign(apk, out_apk, keystore=keystore, keystore_password="s3cret", key_alias="mykey")
    assert info.value.code == "backend_error"
    assert "s3cret" not in str(info.value.details["stderr"])
    assert "***" in str(info.value.details["stderr"])


def test_sign_reports_when_the_output_fails_verification(tmp_path: Path, monkeypatch: Any) -> None:
    client, apk, keystore, out_apk = _signing_client(tmp_path)

    def stub(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        if "sign" in cmd:
            with zipfile.ZipFile(out_apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"signed")
            return "", "", 0
        return "", "DOES NOT VERIFY (s3cret)", 1

    monkeypatch.setattr(apktool_client, "_run", stub)
    with pytest.raises(ApktoolError) as info:
        client.sign(apk, out_apk, keystore=keystore, keystore_password="s3cret", key_alias="mykey")
    assert info.value.code == "backend_error"
    assert "not signed" in info.value.message
    assert "s3cret" not in str(info.value.details["stderr"])
