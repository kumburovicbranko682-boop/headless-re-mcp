"""apk.decode and apk.build execution: structured output, and no unusable rebuild.

These drive the decode and build bodies past the ``_run`` seam (the input tests
stop before it returns) to pin what the tools actually report and refuse:

  * decode returns the tree's shape -- which ``smali*`` dirs exist, whether
    ``res/`` is present -- and threads ``no_resources`` through as apktool's
    ``-r`` flag, so an agent that asked to skip resources really did.
  * build must never report an unusable file as a rebuilt apk. apktool can exit 0
    yet leave a truncated or empty output (an aborted build, a full disk); since
    an APK is a zip, a zero-byte or non-zip result is a failed rebuild, and
    passing it on to apk.sign/install would only fail later with a worse error.
    The size/zip check turns that into an honest backend_error at the source.
  * build refuses a directory that is not an apktool decode output up front,
    rather than launching the JVM to fail obscurely.

The module-level ``_run`` is scripted with the filesystem side effects apktool
would produce, so the bodies run end to end without a JRE.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


def _executable(path: Path) -> Path:
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


def _out_arg(cmd: list[str]) -> Path:
    return Path(cmd[cmd.index("-o") + 1])


def test_decode_reports_the_smali_dirs_and_resources_and_honours_no_resources(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A successful decode names every smali* dir and whether res/ was extracted.

    An agent editing an app needs to know where the code landed (a large app is
    multidex: smali, smali_classes2, ...) and whether resources are present.
    ``no_resources`` must reach apktool as ``-r`` so the caller's request to skip
    the slow resource decode is actually made.
    """
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        del timeout, env
        captured["cmd"] = list(cmd)
        out = _out_arg(cmd)
        out.mkdir(parents=True, exist_ok=True)
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        (out / "smali").mkdir()
        (out / "smali_classes2").mkdir()
        (out / "res").mkdir()
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    apk = _real_apk(tmp_path / "in.apk")
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    result = client.decode(apk, tmp_path / "out", no_resources=True)

    assert result["smali_dirs"] == ["smali", "smali_classes2"]
    assert result["has_resources"] is True
    assert result["manifest"] == str(tmp_path / "out" / "AndroidManifest.xml")
    assert "-r" in captured["cmd"]


def test_decode_failure_is_a_backend_error_carrying_the_exit_code(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A nonzero exit (or a decode that produced no manifest) is a backend_error.

    The manifest is the proof the decode actually populated the tree; without it,
    a 'success' would hand back an empty directory. The failure carries apktool's
    exit code and (bounded) stderr so the caller can see why.
    """

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        del cmd, timeout, env
        return "", "apktool: brut.androlib error", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    apk = _real_apk(tmp_path / "in.apk")
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    with pytest.raises(ApktoolError) as caught:
        client.decode(apk, tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


def test_build_reports_an_unsigned_apk(tmp_path: Path, monkeypatch: Any) -> None:
    """A clean rebuild returns the apk path, its size, and signed:False.

    build deliberately stops short of signing and says so, so the caller knows to
    call apk.sign before installing rather than pushing an unsigned artifact.
    """

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        del timeout, env
        _real_apk(_out_arg(cmd))
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    result = client.build(decoded, tmp_path / "rebuilt.apk")

    assert result["signed"] is False
    assert result["size"] > 0
    assert "apk.sign" in result["note"]


def test_build_rejects_an_exit_zero_that_left_an_invalid_apk(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apktool exiting 0 while leaving an empty/non-zip file is still a failure.

    This is the guard that stops an unusable rebuild from being reported as a
    real apk and forwarded to apk.sign/install, where it would fail later with a
    more confusing error. An empty output written despite a clean exit must be
    caught here as a backend_error naming the (zero) size.
    """

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        del timeout, env
        _out_arg(cmd).write_bytes(b"")  # exit 0, but not a real apk
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "bad.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("size") == 0


def test_build_refuses_a_directory_that_is_not_an_apktool_decode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A dir with no AndroidManifest.xml is a parameter mistake, caught before the JVM.

    Without the manifest the directory is not an apktool decode output; refusing
    it as invalid_params up front avoids launching the JVM only to fail obscurely.
    """

    def _boom(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        raise AssertionError("apktool must not be launched for a non-decode directory")

    monkeypatch.setattr(apktool_client, "_run", _boom)
    not_a_decode = tmp_path / "empty"
    not_a_decode.mkdir()
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)

    with pytest.raises(ApktoolError) as caught:
        client.build(not_a_decode, tmp_path / "out.apk")
    assert caught.value.code == "invalid_params"


def test_sign_requires_credentials_for_a_custom_keystore(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A custom keystore has no known defaults, so missing creds is invalid_params.

    The debug keystore supplies its own alias and password; a caller-provided
    keystore does not, so signing without a password and alias cannot proceed and
    must be refused before the signer is launched -- not attempted with blanks.
    """

    def _boom(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        raise AssertionError("apksigner must not be launched without credentials")

    monkeypatch.setattr(apktool_client, "_run", _boom)
    apk = _real_apk(tmp_path / "in.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))

    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"
