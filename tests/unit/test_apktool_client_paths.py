"""apktool/apksigner paths the input-validation suite does not reach.

The precheck suite pins the non-zip refusal; here the ``_run`` subprocess wrapper
is faked so the decode/build/sign contracts run without a JRE. The focus is the
error mapping (capability/not_found/invalid_params/timeout/backend_error), the
"exit 0 but the artifact is empty or not a zip" honesty checks, and the signing
password never travelling on argv nor leaking through scrubbed stderr.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import (
    _PASSWORD_ENV,
    ApktoolClient,
    ApktoolError,
    _run,
)
from headless_re_mcp.backends.common.bounded_run import TimedOut


def _executable(path: Path) -> Path:
    # available / signer_available only check is_file(), so any real file
    # stands in for the apktool / apksigner CLI here.
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


# ---------------------------------------------------------------------------
# _run wrapper
# ---------------------------------------------------------------------------
def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(ApktoolError) as caught:
        _run(["apktool"], timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_returns_decoded_streams_and_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        apktool_client,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"out\xff", stderr=b"err", returncode=3),
    )
    stdout, stderr, code = _run(["apktool", "d"], timeout=10)
    assert stdout.startswith("out")
    assert stderr == "err"
    assert code == 3


def test_run_maps_timeout_with_killed_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> Any:
        raise TimedOut(5.0, [321])

    monkeypatch.setattr(apktool_client, "run_bounded", _boom)
    with pytest.raises(ApktoolError) as caught:
        _run(["apktool", "d"], timeout=10)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [321]


def test_run_maps_oserror_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(apktool_client, "run_bounded", _boom)
    with pytest.raises(ApktoolError) as caught:
        _run(["apktool", "d"], timeout=10)
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------
def test_decode_requires_apktool(tmp_path: Path) -> None:
    client = ApktoolClient(None, None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_real_apk(tmp_path / "a.apk"), tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_decode_missing_apk_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "ghost.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_success_reports_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    out_dir = tmp_path / "out"
    captured: dict[str, Any] = {}

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        captured["cmd"] = cmd
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("m", encoding="utf-8")
        (out_dir / "smali").mkdir()
        (out_dir / "smali_classes2").mkdir()
        (out_dir / "res").mkdir()
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    result = client.decode(apk, out_dir, no_resources=True)
    assert "-r" in captured["cmd"]
    assert result["smali_dirs"] == ["smali", "smali_classes2"]
    assert result["has_resources"] is True
    assert result["manifest"] == str(out_dir / "AndroidManifest.xml")


def test_decode_failure_when_manifest_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    monkeypatch.setattr(apktool_client, "_run", lambda *a, **k: ("", "kaboom", 0))
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.decode(apk, tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.details["stderr"] == "kaboom"


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def test_build_requires_apktool(tmp_path: Path) -> None:
    with pytest.raises(ApktoolError) as caught:
        ApktoolClient(None, None).build(tmp_path, tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_missing_dir_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "nope", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_rejects_a_non_decode_tree(tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "invalid_params"


def test_build_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("m", encoding="utf-8")
    out_apk = tmp_path / "out.apk"

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        _real_apk(out_apk)
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    result = client.build(decoded, out_apk)
    assert result["signed"] is False
    assert result["size"] > 0
    assert "unsigned" in result["note"]


def test_build_failure_on_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("m", encoding="utf-8")
    monkeypatch.setattr(apktool_client, "_run", lambda *a, **k: ("", "brut error", 1))
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "backend_error"


def test_build_rejects_empty_or_invalid_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("m", encoding="utf-8")
    out_apk = tmp_path / "out.apk"

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        # Exit 0 but the artifact is not a real zip: a rebuild that aborted.
        out_apk.write_bytes(b"not a zip")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", _fake_run)
    client = ApktoolClient(_executable(tmp_path / "apktool.bat"), None)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, out_apk)
    assert caught.value.code == "backend_error"
    assert "empty or invalid" in caught.value.message


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------
def test_sign_requires_apksigner(tmp_path: Path) -> None:
    with pytest.raises(ApktoolError) as caught:
        ApktoolClient(None, None).sign(_real_apk(tmp_path / "a.apk"), tmp_path / "s.apk")
    assert caught.value.code == "capability_unavailable"


def test_sign_missing_apk_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "ghost.apk", tmp_path / "s.apk")
    assert caught.value.code == "not_found"


def test_sign_missing_custom_keystore_is_not_found(tmp_path: Path) -> None:
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            _real_apk(tmp_path / "a.apk"),
            tmp_path / "s.apk",
            keystore=tmp_path / "missing.keystore",
        )
    assert caught.value.code == "not_found"


def test_sign_custom_keystore_requires_password_and_alias(tmp_path: Path) -> None:
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(_real_apk(tmp_path / "a.apk"), tmp_path / "s.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"


def _sign_run_factory(out_apk: Path, calls: list[dict[str, Any]]):
    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        calls.append({"cmd": cmd, "env": env})
        if cmd[1] == "sign":
            _real_apk(out_apk)
        return "", "", 0

    return _fake_run


def test_sign_success_uses_env_password_not_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    out_apk = tmp_path / "s.apk"
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(apktool_client, "_run", _sign_run_factory(out_apk, calls))
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    result = client.sign(
        apk, out_apk, keystore=keystore, keystore_password="s3cret", key_alias="mykey"
    )
    assert result["signed"] is True
    assert result["debug_keystore"] is False
    sign_call = calls[0]
    # The secret rides in the child environment, never on argv.
    assert "s3cret" not in " ".join(sign_call["cmd"])
    assert f"env:{_PASSWORD_ENV}" in sign_call["cmd"]
    assert sign_call["env"][_PASSWORD_ENV] == "s3cret"


def test_sign_defaults_to_the_debug_keystore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    debug_ks = tmp_path / "debug.keystore"
    debug_ks.write_bytes(b"ks")
    monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", debug_ks)
    apk = _real_apk(tmp_path / "a.apk")
    out_apk = tmp_path / "s.apk"
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(apktool_client, "_run", _sign_run_factory(out_apk, calls))
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    result = client.sign(apk, out_apk)
    assert result["debug_keystore"] is True
    assert result["keystore"] == str(debug_ks)
    assert calls[0]["env"][_PASSWORD_ENV] == "android"


def test_sign_scrubs_the_password_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        return "", "keystore password 's3cret' was rejected", 1

    monkeypatch.setattr(apktool_client, "_run", _fake_run)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk, tmp_path / "s.apk", keystore=keystore, keystore_password="s3cret", key_alias="k"
        )
    assert caught.value.code == "backend_error"
    assert "s3cret" not in caught.value.details["stderr"]
    assert "***" in caught.value.details["stderr"]


def test_sign_reports_unverified_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _real_apk(tmp_path / "a.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    out_apk = tmp_path / "s.apk"

    def _fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        if cmd[1] == "sign":
            _real_apk(out_apk)
            return "", "", 0
        # verify fails and echoes the password back.
        return "", "verify failed for s3cret", 1

    monkeypatch.setattr(apktool_client, "_run", _fake_run)
    client = ApktoolClient(None, _executable(tmp_path / "apksigner.bat"))
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk, out_apk, keystore=keystore, keystore_password="s3cret", key_alias="k"
        )
    assert caught.value.code == "backend_error"
    assert "not signed" in caught.value.message
    assert "s3cret" not in caught.value.details["stderr"]
