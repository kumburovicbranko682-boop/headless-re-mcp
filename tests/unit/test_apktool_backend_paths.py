"""ApktoolClient decode/build/sign guards and the shared _run deadline mapping.

The field-shape and password-scrubbing tests pin what a successful call answers
with and how a failure hides the keystore secret. What is covered here is the
guard lattice around those calls -- a missing tool, a missing input, a directory
that is not an apktool decode, a custom keystore with no password -- and the one
place every subprocess funnels through: ``_run`` must turn a launcher that
outran its deadline into ``timeout`` (carrying the pids it killed) and a launch
that could not start into ``backend_error``. No real JVM is ever spawned.
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


# --------------------------------------------------------------------------
# _run deadline / launch mapping
# --------------------------------------------------------------------------
def test_run_maps_a_deadline_to_timeout_with_the_killed_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _timed_out(*args: Any, **kwargs: Any) -> Completed:
        raise TimedOut(30.0, [4242])

    monkeypatch.setattr(apktool_client, "run_bounded", _timed_out)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apktool", "d"], timeout=30.0)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [4242]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_exec(*args: Any, **kwargs: Any) -> Completed:
        raise OSError("No such file or directory")

    monkeypatch.setattr(apktool_client, "run_bounded", _no_exec)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apktool", "d"], timeout=30.0)
    assert caught.value.code == "backend_error"


def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apktool"], timeout=0.0)
    assert caught.value.code == "invalid_params"


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------
def test_decode_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "missing.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_passes_the_no_resources_flag_and_summarises_the_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """no_resources must reach apktool as ``-r`` and the reply names the smali dirs."""
    apk = _real_apk(tmp_path / "a.apk")
    out = tmp_path / "out"
    captured: dict[str, Any] = {}

    def _run(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        captured["args"] = args
        out.mkdir(parents=True, exist_ok=True)
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        (out / "smali").mkdir()
        (out / "smali_classes2").mkdir()
        (out / "res").mkdir()
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    payload = client.decode(apk, out, no_resources=True)
    assert "-r" in captured["args"]
    assert payload["smali_dirs"] == ["smali", "smali_classes2"]
    assert payload["has_resources"] is True


def test_decode_maps_a_tool_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")

    def _run(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "apktool: brut error", 1

    monkeypatch.setattr(apktool_client, "_run", _run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(apk, tmp_path / "out")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------
def test_build_refuses_when_apktool_is_unconfigured(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_reports_a_missing_decoded_directory(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "not-there", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_refuses_a_directory_that_is_not_a_decode_output(tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "invalid_params"


def test_build_maps_a_tool_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

    def _run(args: list[str], **kwargs: Any) -> tuple[str, str, int]:
        return "", "build failed", 1

    monkeypatch.setattr(apktool_client, "_run", _run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# sign guards
# --------------------------------------------------------------------------
def test_sign_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "missing.apk", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_sign_reports_a_missing_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "out.apk", keystore=tmp_path / "absent.keystore")
    assert caught.value.code == "not_found"


def test_sign_requires_a_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    """A caller-supplied keystore gets no debug defaults, so both fields are required."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "out.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"
