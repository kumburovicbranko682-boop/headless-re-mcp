"""Guard and error branches of the apktool / apksigner adapter.

The existing apktool tests pin the non-zip precheck on decode and sign. This
file fills in the branches those step over: the bounded-run timeout and
launch-failure translation, the invalid timeout, decode's missing-apk guard and
its ``-r`` (no resources) flag, build's availability / missing-directory guards
and its failed-rebuild wrap, and sign's missing-apk / missing-keystore /
missing-credential guards. Each test pins one branch; no JVM is spawned --
``run_bounded`` or the module-level ``_run`` is faked at the seam.
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
# _run translation.
# ---------------------------------------------------------------------------
def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apktool", "d"], timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_reports_a_timeout_naming_the_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [88])

    monkeypatch.setattr(apktool_client, "run_bounded", fake_run)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["/opt/bin/apktool", "d"], timeout=5.0)
    assert caught.value.code == "timeout"
    assert caught.value.message == "apktool timed out"
    assert caught.value.details["killed_pids"] == [88]


def test_run_wraps_a_launch_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("not executable")

    monkeypatch.setattr(apktool_client, "run_bounded", fake_run)
    with pytest.raises(ApktoolError) as caught:
        apktool_client._run(["apksigner", "sign"], timeout=5.0)
    assert caught.value.code == "backend_error"
    assert "failed to launch apksigner" in caught.value.message


# ---------------------------------------------------------------------------
# decode.
# ---------------------------------------------------------------------------
def test_decode_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "absent.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_without_resources_passes_dash_r(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    out = tmp_path / "out"
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        calls.append(cmd)
        out.mkdir(parents=True, exist_ok=True)
        (out / "AndroidManifest.xml").write_text("manifest", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool"), None)
    payload = client.decode(apk, out, no_resources=True)
    assert "-r" in calls[0]
    assert payload["has_resources"] is False
    assert payload["smali_dirs"] == []


# ---------------------------------------------------------------------------
# build guards.
# ---------------------------------------------------------------------------
def test_build_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path, tmp_path / "rebuilt.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_reports_a_missing_decoded_directory(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "absent", tmp_path / "rebuilt.apk")
    assert caught.value.code == "not_found"


def test_build_wraps_a_failed_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("manifest", encoding="utf-8")
    monkeypatch.setattr(
        apktool_client, "_run", lambda cmd, **k: ("", "brut.androlib boom", 1)
    )
    client = ApktoolClient(_executable(tmp_path / "apktool"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "rebuilt.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "apktool build failed"
    assert caught.value.details["exit_code"] == 1


# ---------------------------------------------------------------------------
# sign guards.
# ---------------------------------------------------------------------------
def test_sign_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "absent.apk", tmp_path / "signed.apk")
    assert caught.value.code == "not_found"


def test_sign_reports_a_missing_keystore(tmp_path: Path) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=tmp_path / "absent.keystore",
            keystore_password="secret",
            key_alias="alias",
        )
    assert caught.value.code == "not_found"
    assert "keystore" in caught.value.message


def test_sign_requires_credentials_for_a_custom_keystore(tmp_path: Path) -> None:
    """A custom keystore never inherits the debug password or alias."""
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "signed.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"
    assert "keystore_password and key_alias" in caught.value.message
