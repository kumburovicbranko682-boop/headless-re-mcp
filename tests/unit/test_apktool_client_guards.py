"""Device-free coverage for the apktool/apksigner wrapper's guards and _run.

The APK repack/sign line shells out to two JVM CLIs. The field-shape tests
(test_apk_decode_fields / test_apk_repack_fields / test_apk_sign_fields) drive
the happy paths and the password-scrubbing contract, but they all monkeypatch
``_run`` away, so its own body -- the part that turns a JVM that outran its
deadline into a ``timeout`` (carrying the pids that had to be killed) and a
tool that would not launch into a ``backend_error`` -- was never executed. The
pre-launch input guards (missing apk / decoded tree / keystore, a custom
keystore with no password or alias) were likewise uncovered.

These pin both without a JRE: ``_run`` over a fake ``run_bounded``, and the
guards over fake tool files whose ``.is_file()`` passes so control reaches the
argument checks rather than the capability gate.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError, _run
from headless_re_mcp.backends.common.bounded_run import TimedOut


def _tool(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text("x\n", encoding="utf-8")
    return path


# --- _run: the subprocess boundary ------------------------------------------


def test_run_decodes_stdout_stderr_and_returncode(monkeypatch: pytest.MonkeyPatch) -> None:
    # Invalid UTF-8 must not raise out of the boundary: errors="replace" keeps a
    # tool that emits binary noise on stderr from crashing the wrapper.
    completed = SimpleNamespace(stdout=b"out\xff", stderr=b"err", returncode=3)
    monkeypatch.setattr(apktool_client, "run_bounded", lambda *a, **k: completed)
    stdout, stderr, code = _run(["apktool", "d"], timeout=5.0)
    assert stdout == "out\ufffd"
    assert stderr == "err"
    assert code == 3


def test_run_maps_a_deadline_to_timeout_with_the_killed_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*_a: Any, **_k: Any) -> Any:
        raise TimedOut(30.0, [4242, 4243])

    monkeypatch.setattr(apktool_client, "run_bounded", _boom)
    with pytest.raises(ApktoolError) as caught:
        _run(["/opt/apktool", "b"], timeout=30.0)
    assert caught.value.code == "timeout"
    assert "apktool" in caught.value.message
    assert caught.value.details["timeout"] == 30.0
    # The JVM tree that had to be stopped is reported so a caller can audit it.
    assert caught.value.details["killed_pids"] == [4242, 4243]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(apktool_client, "run_bounded", _boom)
    with pytest.raises(ApktoolError) as caught:
        _run(["/opt/apksigner", "sign"], timeout=5.0)
    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


# --- decode guards ----------------------------------------------------------


def test_decode_reports_not_found_for_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(_tool(tmp_path, "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "gone.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_passes_the_no_resources_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    seen: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **_k: Any) -> tuple[str, str, int]:
        seen["cmd"] = list(cmd)
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_tool(tmp_path, "apktool.bat"), None)
    client.decode(apk, out, no_resources=True)
    assert "-r" in seen["cmd"]


# --- build guards -----------------------------------------------------------


def test_build_degrades_when_apktool_is_absent(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_reports_not_found_for_a_missing_decoded_dir(tmp_path: Path) -> None:
    client = ApktoolClient(_tool(tmp_path, "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "not-there", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_maps_a_nonzero_exit_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

    def fake_run(cmd: list[str], **_k: Any) -> tuple[str, str, int]:
        # apktool prints a stack trace and exits nonzero without writing the apk.
        return "", "brut.androlib error", 1

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_tool(tmp_path, "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1
    assert "brut.androlib error" in caught.value.details["stderr"]


# --- sign guards ------------------------------------------------------------


def test_sign_reports_not_found_for_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(None, _tool(tmp_path, "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "gone.apk", tmp_path / "out.apk", keystore=tmp_path / "ks")
    assert caught.value.code == "not_found"


def test_sign_reports_not_found_for_a_missing_keystore(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
    client = ApktoolClient(None, _tool(tmp_path, "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "out.apk",
            keystore=tmp_path / "missing.keystore",
            keystore_password="pw",
            key_alias="a",
        )
    assert caught.value.code == "not_found"
    assert "keystore" in caught.value.message


def test_sign_requires_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    # A custom keystore gets no debug defaults, so an empty password or alias is
    # a caller error, refused before apksigner is ever launched.
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _tool(tmp_path, "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "out.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"
