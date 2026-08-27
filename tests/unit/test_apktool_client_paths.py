"""ApktoolClient guard, error, and honesty branches without a JRE.

The apktool/apksigner CLIs are never launched: ``_run`` is monkeypatched with a
fake that returns a chosen (stdout, stderr, exit code) and writes whatever
output file the real tool would have produced. That exercises the decode/build/
sign success paths and every failure contract, plus ``_run``'s own timeout and
launch-failure mapping, on a machine with no Android toolchain.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apk_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError, _require_apk_zip
from headless_re_mcp.backends.common.bounded_run import Completed, InvalidTimeout, TimedOut


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
    return path


def _tools(tmp_path: Path) -> tuple[Path, Path]:
    apktool = tmp_path / "apktool"
    apksigner = tmp_path / "apksigner"
    apktool.write_text("#!/bin/sh\n", encoding="utf-8")
    apksigner.write_text("#!/bin/sh\n", encoding="utf-8")
    return apktool, apksigner


def _arg(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


# --- _run mapping -----------------------------------------------------------


def test_run_rejects_a_non_positive_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> float:
        raise InvalidTimeout("timeout must be positive")

    monkeypatch.setattr(apk_client, "clamp_cli_timeout", _boom)
    with pytest.raises(ApktoolError) as info:
        apk_client._run(["apktool", "d"], timeout=0.0)
    assert info.value.code == "invalid_params"


def test_run_maps_timeout_to_a_killed_pid_report(monkeypatch: pytest.MonkeyPatch) -> None:
    def _timeout(*_a: Any, **_k: Any) -> Any:
        raise TimedOut(3.0, [4321])

    monkeypatch.setattr(apk_client, "run_bounded", _timeout)
    with pytest.raises(ApktoolError) as info:
        apk_client._run(["apktool", "d"], timeout=5.0)
    assert info.value.code == "timeout"
    assert info.value.details.get("killed_pids") == [4321]


def test_run_maps_a_launch_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _oserror(*_a: Any, **_k: Any) -> Any:
        raise OSError("no such file")

    monkeypatch.setattr(apk_client, "run_bounded", _oserror)
    with pytest.raises(ApktoolError) as info:
        apk_client._run(["apktool", "d"], timeout=5.0)
    assert info.value.code == "backend_error"


def test_run_decodes_streams_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        apk_client,
        "run_bounded",
        lambda *a, **k: Completed(0, b"the-output", b"the-error"),
    )
    stdout, stderr, code = apk_client._run(["apktool", "d"], timeout=5.0)
    assert (stdout, stderr, code) == ("the-output", "the-error", 0)


def test_require_apk_zip_rejects_a_non_zip(tmp_path: Path) -> None:
    blob = tmp_path / "not.apk"
    blob.write_text("definitely not a zip", encoding="utf-8")
    with pytest.raises(ApktoolError) as info:
        _require_apk_zip(blob)
    assert info.value.code == "invalid_params"


# --- decode -----------------------------------------------------------------


def test_decode_requires_a_configured_apktool(tmp_path: Path) -> None:
    client = ApktoolClient(apktool=None)
    with pytest.raises(ApktoolError) as info:
        client.decode(_zip(tmp_path / "a.apk"), tmp_path / "out")
    assert info.value.code == "capability_unavailable"


def test_decode_reports_a_missing_apk(tmp_path: Path) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    with pytest.raises(ApktoolError) as info:
        client.decode(tmp_path / "missing.apk", tmp_path / "out")
    assert info.value.code == "not_found"


def test_decode_success_lists_smali_dirs_and_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        out = Path(_arg(cmd, "-o"))
        out.mkdir(parents=True, exist_ok=True)
        (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        (out / "smali").mkdir()
        (out / "smali_classes2").mkdir()
        (out / "res").mkdir()
        assert "-r" in cmd  # no_resources flag threaded through
        return ("done", "", 0)

    monkeypatch.setattr(apk_client, "_run", _fake_run)
    data = client.decode(_zip(tmp_path / "a.apk"), tmp_path / "out", no_resources=True)
    assert data["smali_dirs"] == ["smali", "smali_classes2"]
    assert data["has_resources"] is True


def test_decode_maps_a_failed_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    monkeypatch.setattr(
        apk_client, "_run", lambda *a, **k: ("", "boom", 1)
    )
    with pytest.raises(ApktoolError) as info:
        client.decode(_zip(tmp_path / "a.apk"), tmp_path / "out")
    assert info.value.code == "backend_error"
    assert info.value.details.get("exit_code") == 1


# --- build ------------------------------------------------------------------


def test_build_requires_a_configured_apktool(tmp_path: Path) -> None:
    client = ApktoolClient(apktool=None)
    with pytest.raises(ApktoolError) as info:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert info.value.code == "capability_unavailable"


def test_build_reports_a_missing_decoded_dir(tmp_path: Path) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    with pytest.raises(ApktoolError) as info:
        client.build(tmp_path / "nope", tmp_path / "out.apk")
    assert info.value.code == "not_found"


def test_build_rejects_a_tree_without_a_manifest(tmp_path: Path) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    with pytest.raises(ApktoolError) as info:
        client.build(decoded, tmp_path / "out.apk")
    assert info.value.code == "invalid_params"


def test_build_maps_a_failed_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    monkeypatch.setattr(apk_client, "_run", lambda *a, **k: ("", "kaboom", 1))
    with pytest.raises(ApktoolError) as info:
        client.build(decoded, tmp_path / "out.apk")
    assert info.value.code == "backend_error"


def test_build_rejects_an_empty_or_non_zip_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        Path(_arg(cmd, "-o")).write_text("not a zip", encoding="utf-8")
        return ("", "", 0)

    monkeypatch.setattr(apk_client, "_run", _fake_run)
    with pytest.raises(ApktoolError) as info:
        client.build(decoded, tmp_path / "out.apk")
    assert info.value.code == "backend_error"
    assert "empty or invalid" in info.value.message


def test_build_success_returns_an_unsigned_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apktool, _ = _tools(tmp_path)
    client = ApktoolClient(apktool=apktool)
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        _zip(Path(_arg(cmd, "-o")))
        return ("", "", 0)

    monkeypatch.setattr(apk_client, "_run", _fake_run)
    data = client.build(decoded, tmp_path / "out.apk")
    assert data["signed"] is False and data["size"] > 0


# --- sign -------------------------------------------------------------------


def test_sign_requires_a_configured_apksigner(tmp_path: Path) -> None:
    client = ApktoolClient(apksigner=None)
    with pytest.raises(ApktoolError) as info:
        client.sign(_zip(tmp_path / "a.apk"), tmp_path / "signed.apk")
    assert info.value.code == "capability_unavailable"


def test_sign_reports_a_missing_apk(tmp_path: Path) -> None:
    _, apksigner = _tools(tmp_path)
    client = ApktoolClient(apksigner=apksigner)
    with pytest.raises(ApktoolError) as info:
        client.sign(tmp_path / "missing.apk", tmp_path / "signed.apk")
    assert info.value.code == "not_found"


def test_sign_reports_a_missing_keystore(tmp_path: Path) -> None:
    _, apksigner = _tools(tmp_path)
    client = ApktoolClient(apksigner=apksigner)
    with pytest.raises(ApktoolError) as info:
        client.sign(
            _zip(tmp_path / "a.apk"),
            tmp_path / "signed.apk",
            keystore=tmp_path / "absent.ks",
            keystore_password="pw",
            key_alias="k",
        )
    assert info.value.code == "not_found"


def test_sign_requires_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    _, apksigner = _tools(tmp_path)
    client = ApktoolClient(apksigner=apksigner)
    keystore = tmp_path / "my.ks"
    keystore.write_bytes(b"keystore")
    with pytest.raises(ApktoolError) as info:
        client.sign(_zip(tmp_path / "a.apk"), tmp_path / "signed.apk", keystore=keystore)
    assert info.value.code == "invalid_params"


def test_sign_scrubs_the_password_from_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, apksigner = _tools(tmp_path)
    client = ApktoolClient(apksigner=apksigner)
    keystore = tmp_path / "my.ks"
    keystore.write_bytes(b"keystore")
    monkeypatch.setattr(
        apk_client, "_run", lambda *a, **k: ("", "auth failed for s3cret", 1)
    )
    with pytest.raises(ApktoolError) as info:
        client.sign(
            _zip(tmp_path / "a.apk"),
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password="s3cret",
            key_alias="k",
        )
    assert info.value.code == "backend_error"
    assert "s3cret" not in str(info.value.details.get("stderr"))
    assert "***" in str(info.value.details.get("stderr"))


def test_sign_reports_when_verify_says_unsigned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, apksigner = _tools(tmp_path)
    client = ApktoolClient(apksigner=apksigner)
    keystore = tmp_path / "my.ks"
    keystore.write_bytes(b"keystore")

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        if "sign" in cmd:
            _zip(Path(_arg(cmd, "--out")))
            return ("", "", 0)
        return ("", "not signed s3cret", 1)  # verify

    monkeypatch.setattr(apk_client, "_run", _fake_run)
    with pytest.raises(ApktoolError) as info:
        client.sign(
            _zip(tmp_path / "a.apk"),
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password="s3cret",
            key_alias="k",
        )
    assert info.value.code == "backend_error"
    assert "s3cret" not in str(info.value.details.get("stderr"))


def test_sign_success_returns_a_signed_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, apksigner = _tools(tmp_path)
    client = ApktoolClient(apksigner=apksigner)
    keystore = tmp_path / "my.ks"
    keystore.write_bytes(b"keystore")
    seen_env: list[Any] = []

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        if "sign" in cmd:
            seen_env.append(env)
            _zip(Path(_arg(cmd, "--out")))
        return ("", "", 0)

    monkeypatch.setattr(apk_client, "_run", _fake_run)
    data = client.sign(
        _zip(tmp_path / "a.apk"),
        tmp_path / "signed.apk",
        keystore=keystore,
        keystore_password="s3cret",
        key_alias="k",
    )
    assert data["signed"] is True and data["debug_keystore"] is False
    # The password reaches apksigner only through the child environment.
    assert seen_env and seen_env[0][apk_client._PASSWORD_ENV] == "s3cret"
