"""Subprocess-layer coverage for the apktool/apksigner client.

The existing apktool tests stop at the early guards (capability checks, the
non-zip refusal, the "does not look like a decode output" check), so ``_run``
and the decode/build/sign bodies -- including the security-critical parts of
signing -- never ran. These tests drive them with a faked ``run_bounded`` (no
JVM), covering:

* ``_run``: an invalid (non-positive) timeout, a timeout that kills the JVM, and
  a launcher that will not exec (OSError).
* ``decode``: not_found, the ``-r`` no-resources flag, a successful decode
  (smali dirs + resources), and a failed decode.
* ``build``: capability/not_found/not-a-decode-output guards, a successful
  rebuild, a non-zero exit, and a zero exit that left an empty/invalid apk.
* ``sign``: not_found, a missing keystore, a custom keystore missing its
  password/alias, a successful sign that passes the password via ``env:`` (never
  argv) and verifies, a sign failure whose stderr is scrubbed of the password,
  and a verify failure that is likewise scrubbed.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.apktool.client as apktool_mod
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    return path


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"\x00")
    return path


def _client(tmp_path: Path, *, apktool: bool = True, apksigner: bool = True) -> ApktoolClient:
    return ApktoolClient(
        apktool=_executable(tmp_path / "apktool") if apktool else None,
        apksigner=_executable(tmp_path / "apksigner") if apksigner else None,
    )


# --- _run --------------------------------------------------------------------


def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    """A zero/negative deadline is a bad parameter, caught before the JVM."""
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_zip(tmp_path / "app.apk"), tmp_path / "out", timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_maps_a_timeout_to_a_timeout_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timing_out(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(timeout=600.0, killed=[10, 11])

    monkeypatch.setattr(apktool_mod, "run_bounded", timing_out)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_zip(tmp_path / "app.apk"), tmp_path / "out")
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [10, 11]


def test_run_maps_a_launch_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def not_executable(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("exec format error")

    monkeypatch.setattr(apktool_mod, "run_bounded", not_executable)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_zip(tmp_path / "app.apk"), tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


# --- decode ------------------------------------------------------------------


def test_decode_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = _client(tmp_path, apktool=False)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_zip(tmp_path / "app.apk"), tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_decode_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.decode(tmp_path / "gone.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_decode_success_passes_the_no_resources_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "out"
    recorded: list[list[str]] = []

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        recorded.append([str(part) for part in cmd])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        (out_dir / "smali").mkdir(exist_ok=True)
        (out_dir / "smali_classes2").mkdir(exist_ok=True)
        (out_dir / "res").mkdir(exist_ok=True)
        return Completed(0, b"decoded", b"")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)

    payload = client.decode(_zip(tmp_path / "app.apk"), out_dir, no_resources=True)

    assert payload["decoded_dir"] == str(out_dir)
    assert payload["smali_dirs"] == ["smali", "smali_classes2"]
    assert payload["has_resources"] is True
    assert "-r" in recorded[0]
    assert "-f" in recorded[0]


def test_decode_failure_is_a_backend_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-zero exit with no manifest written is a failed decode."""

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"brut.androlib error")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.decode(_zip(tmp_path / "app.apk"), tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "apktool decode failed"


# --- build -------------------------------------------------------------------


def test_build_without_apktool_is_capability_unavailable(tmp_path: Path) -> None:
    client = _client(tmp_path, apktool=False)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert caught.value.code == "capability_unavailable"


def test_build_reports_a_missing_directory_as_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.build(tmp_path / "decoded", tmp_path / "out.apk")
    assert caught.value.code == "not_found"


def test_build_rejects_a_directory_that_is_not_a_decode_output(tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.build(decoded, tmp_path / "out.apk")
    assert caught.value.code == "invalid_params"


def _decoded_dir(tmp_path: Path) -> Path:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    return decoded


def test_build_success_reports_an_unsigned_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_apk = tmp_path / "rebuilt.apk"

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        _zip(out_apk)
        return Completed(0, b"built", b"")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)

    payload = client.build(_decoded_dir(tmp_path), out_apk)

    assert payload["apk"] == str(out_apk)
    assert payload["signed"] is False
    assert payload["size"] > 0
    assert "call apk.sign" in payload["note"]


def test_build_failure_with_no_output_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"build broke")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.build(_decoded_dir(tmp_path), tmp_path / "out.apk")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "apktool build failed"


def test_build_rejects_an_empty_or_invalid_output_on_a_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool can exit 0 yet leave a truncated file; an APK must be a real zip."""
    out_apk = tmp_path / "rebuilt.apk"

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        out_apk.write_bytes(b"not a zip")
        return Completed(0, b"built", b"")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.build(_decoded_dir(tmp_path), out_apk)
    assert caught.value.code == "backend_error"
    assert "empty or invalid apk" in caught.value.message


# --- sign --------------------------------------------------------------------


def test_sign_without_apksigner_is_capability_unavailable(tmp_path: Path) -> None:
    client = _client(tmp_path, apksigner=False)
    with pytest.raises(ApktoolError) as caught:
        client.sign(_zip(tmp_path / "app.apk"), tmp_path / "signed.apk")
    assert caught.value.code == "capability_unavailable"


def test_sign_reports_a_missing_apk_as_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.sign(tmp_path / "gone.apk", tmp_path / "signed.apk")
    assert caught.value.code == "not_found"


def test_sign_reports_a_missing_keystore_as_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            _zip(tmp_path / "app.apk"),
            tmp_path / "signed.apk",
            keystore=tmp_path / "absent.keystore",
            keystore_password="pw",
            key_alias="a",
        )
    assert caught.value.code == "not_found"


def test_sign_requires_password_and_alias_for_a_custom_keystore(tmp_path: Path) -> None:
    keystore = _executable(tmp_path / "custom.keystore")
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.sign(_zip(tmp_path / "app.apk"), tmp_path / "signed.apk", keystore=keystore)
    assert caught.value.code == "invalid_params"


def test_sign_success_passes_the_password_via_env_not_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The keystore password must never reach argv, only the child env."""
    keystore = _executable(tmp_path / "custom.keystore")
    out_apk = tmp_path / "signed.apk"
    secret = "sup3r-secret-pw"
    recorded: list[tuple[list[str], dict[str, Any]]] = []

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        argv = [str(part) for part in cmd]
        recorded.append((argv, kwargs))
        if "sign" in argv:
            _zip(out_apk)
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)

    payload = client.sign(
        _zip(tmp_path / "app.apk"),
        out_apk,
        keystore=keystore,
        keystore_password=secret,
        key_alias="mykey",
    )

    assert payload["signed"] is True
    assert payload["debug_keystore"] is False
    assert payload["keystore"] == str(keystore)
    sign_argv, sign_kwargs = recorded[0]
    assert f"env:{apktool_mod._PASSWORD_ENV}" in sign_argv
    assert secret not in " ".join(sign_argv)
    assert sign_kwargs["env"][apktool_mod._PASSWORD_ENV] == secret
    # A second run_bounded call verifies the signature.
    assert any("verify" in argv for argv, _ in recorded)


def test_sign_uses_the_debug_keystore_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no keystore given, the standard debug keystore and its creds are used."""
    debug_keystore = _executable(tmp_path / "debug.keystore")
    monkeypatch.setattr(apktool_mod, "_DEBUG_KEYSTORE", debug_keystore)
    out_apk = tmp_path / "signed.apk"

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        if "sign" in [str(part) for part in cmd]:
            _zip(out_apk)
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)

    payload = client.sign(_zip(tmp_path / "app.apk"), out_apk)

    assert payload["signed"] is True
    assert payload["debug_keystore"] is True
    assert payload["keystore"] == str(debug_keystore)


def test_sign_failure_scrubs_the_password_from_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keystore = _executable(tmp_path / "custom.keystore")
    secret = "leak-me-not"

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", f"keytool error using {secret}".encode())

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            _zip(tmp_path / "app.apk"),
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password=secret,
            key_alias="mykey",
        )
    assert caught.value.code == "backend_error"
    assert caught.value.message == "apksigner failed"
    assert secret not in str(caught.value.details["stderr"])
    assert "***" in str(caught.value.details["stderr"])


def test_sign_verify_failure_scrubs_the_password_from_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sign that writes an output the verifier then rejects is a backend error."""
    keystore = _executable(tmp_path / "custom.keystore")
    out_apk = tmp_path / "signed.apk"
    secret = "another-secret"

    def fake(cmd: list[str], **kwargs: Any) -> Completed:
        argv = [str(part) for part in cmd]
        if "sign" in argv:
            _zip(out_apk)
            return Completed(0, b"ok", b"")
        return Completed(1, b"", f"not verified {secret}".encode())

    monkeypatch.setattr(apktool_mod, "run_bounded", fake)
    client = _client(tmp_path)
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            _zip(tmp_path / "app.apk"),
            out_apk,
            keystore=keystore,
            keystore_password=secret,
            key_alias="mykey",
        )
    assert caught.value.code == "backend_error"
    assert "not signed" in caught.value.message
    assert secret not in str(caught.value.details["stderr"])
