"""Fail-fast, degradation, and secret-handling contracts of the apktool client.

The non-zip precheck is pinned next door in test_apktool_apk_input_validation.
This covers the rest of the client's refusals -- a missing apk or keystore, a
directory that is not an apktool decode output, a build the tool botched -- and
the two secret-handling contracts the ``sign`` path exists to keep:

* the keystore password reaches apksigner only through an environment variable
  (``env:APKSIGNER_KS_PASS``), never on argv, because a command line is
  world-readable in the process table for as long as the signing JVM runs, and
* a failed sign scrubs the password out of the tool's stderr before it lands in
  the error details.

All of these run without a JRE by stubbing ``_run`` -- they exercise the client's
own guards and argument construction, not apktool or apksigner themselves.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


def _executable(path: Path) -> Path:
    # available / signer_available only check is_file(): any real file stands in
    # for the apktool / apksigner CLI.
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


def test_decode_refuses_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "absent.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_passes_the_no_resources_flag_and_reports_the_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """no_resources=True must reach apktool as ``-r``; the success tail then
    reports the decoded tree it found on disk."""
    apk = _real_apk(tmp_path / "a.apk")
    out = tmp_path / "out"
    recorded: list[list[str]] = []

    def _run_stub(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        recorded.append(list(cmd))
        (out / "smali").mkdir(parents=True)
        (out / "res").mkdir()
        (out / "AndroidManifest.xml").write_text("m", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run_stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    result = client.decode(apk, out, no_resources=True)

    assert "-r" in recorded[0]
    assert result["smali_dirs"] == ["smali"]
    assert result["has_resources"] is True
    assert result["manifest"] == str(out / "AndroidManifest.xml")


def test_build_is_unavailable_without_apktool(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_refuses_a_missing_decoded_directory(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "not-there", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_reports_a_botched_rebuild_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool exiting non-zero (or leaving no output) is a backend_error that
    carries the exit code -- never a silent 'rebuilt' result."""
    decoded = _decoded_tree(tmp_path / "decoded")

    def _run_stub(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        return "", "brut.androlib exploded", 1

    monkeypatch.setattr(apktool_client, "_run", _run_stub)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


def test_sign_refuses_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "absent.apk", tmp_path / "signed.apk")
    assert caught.value.code == "not_found"


def test_sign_refuses_a_missing_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=tmp_path / "absent.ks")
    assert caught.value.code == "not_found"


def test_sign_requires_credentials_for_a_custom_keystore(tmp_path: Path) -> None:
    """A caller-supplied keystore does not inherit the debug password/alias:
    omitting either is an up-front invalid_params, not an apksigner failure."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore, key_alias="")
    assert caught.value.code == "invalid_params"


def test_sign_keeps_the_password_off_argv_and_in_the_child_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The secret must travel to apksigner only through the environment. argv is
    world-readable while the JVM runs, so the password must appear nowhere in the
    command line -- only ``env:APKSIGNER_KS_PASS`` does, resolved from the env."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    out_apk = tmp_path / "signed.apk"
    password = "s3cr3t-passphrase-xyz"
    calls: list[dict[str, Any]] = []

    def _run_stub(
        cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
    ) -> tuple[str, str, int]:
        calls.append({"cmd": list(cmd), "env": dict(env) if env else None})
        # apksigner would write the signed apk; stand in for it so the success
        # tail (and the verify call) proceed.
        out_apk.write_bytes(b"signed")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run_stub)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    result = client.sign(
        apk,
        out_apk,
        keystore=keystore,
        keystore_password=password,
        key_alias="myalias",
    )

    sign_call = calls[0]
    assert password not in " ".join(sign_call["cmd"])
    assert password not in sign_call["cmd"]
    assert "env:APKSIGNER_KS_PASS" in sign_call["cmd"]
    assert sign_call["env"] is not None
    assert sign_call["env"]["APKSIGNER_KS_PASS"] == password
    assert result["signed"] is True


def test_sign_scrubs_the_password_from_stderr_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apksigner may echo the passphrase in its own diagnostics; a failed sign
    must replace it with *** before the stderr lands in the error details."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    password = "s3cr3t-passphrase-xyz"

    def _run_stub(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        return "", f"keytool: the pass {password} was rejected", 1

    monkeypatch.setattr(apktool_client, "_run", _run_stub)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password=password,
            key_alias="myalias",
        )
    assert caught.value.code == "backend_error"
    stderr = str(caught.value.details.get("stderr"))
    assert password not in stderr
    assert "***" in stderr
