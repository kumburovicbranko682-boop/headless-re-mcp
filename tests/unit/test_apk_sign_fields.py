"""apk.sign descriptions must name the fields apksigner actually returns."""

from __future__ import annotations

import ast
import zipfile
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.apktool.client as apktool_client
from headless_re_mcp.backends.apktool.client import _PASSWORD_ENV, ApktoolClient, ApktoolError
from headless_re_mcp.tools.apk import build_apk_tools


def _write_apk(path: Path) -> Path:
    """A real (if tiny) zip: apksigner's input must be a zip APK, and the client
    now refuses a non-zip before launching the signing JVM."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_apk_sign_names_apk_not_signed_apk(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said sign and never named the payload.

    Measured: sign keys are apk, debug_keystore, keystore, signed, size.
    output/path/signed_apk are absent. Looking for signed_apk after a
    successful call reads as an unsigned APK, so the agent signs again or
    installs the unsigned rebuild.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    keystore = tmp_path / "debug.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"

    def fake_run(*_args: Any, **_kwargs: Any) -> tuple[str, str, int]:
        out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, signer)
    payload = client.sign(
        apk,
        out,
        keystore=keystore,
        keystore_password="android",
        key_alias="androiddebugkey",
    )
    assert "output" not in payload
    assert "path" not in payload
    assert "signed_apk" not in payload
    assert payload["apk"] == str(out)
    assert payload["signed"] is True
    assert payload["debug_keystore"] is False
    doc = _tool_docstring("apk.sign")
    assert "Answers with apk" in doc
    assert "debug_keystore" in doc
    assert "verify" in doc


def test_a_failed_sign_scrubs_the_keystore_password_from_stderr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """SECURITY.md promises keystore passwords never reach error details.

    apksigner echoes its argument vector (including ``--ks-pass pass:...``) into
    stderr on usage errors, and that stderr is copied into the ApktoolError that
    becomes the tool's error envelope. Both failure paths -- the sign call and
    the verify call -- must scrub the password before it leaves the client.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"
    password = "hunter2-release-pw"

    def failing_sign(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        return "", f"usage: apksigner sign --ks-pass pass:{password} refused", 1

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", failing_sign)
    client = ApktoolClient(fake_tool, signer)
    with pytest.raises(ApktoolError) as sign_failure:
        client.sign(
            apk, out, keystore=keystore, keystore_password=password, key_alias="release"
        )
    sign_stderr = str(sign_failure.value.details["stderr"])
    assert password not in sign_stderr
    assert "***" in sign_stderr

    def failing_verify(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        if "verify" in cmd:
            return "", f"DOES NOT VERIFY (tried pass:{password})", 1
        out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", failing_verify)
    with pytest.raises(ApktoolError) as verify_failure:
        client.sign(
            apk, out, keystore=keystore, keystore_password=password, key_alias="release"
        )
    verify_stderr = str(verify_failure.value.details["stderr"])
    assert password not in verify_stderr
    assert "***" in verify_stderr


# A realistic apksigner failure: the "android" debug password is a substring of
# every com.android.apksig... stack frame, so a blanket scrub mangles it.
_REAL_APKSIGNER_STDERR = (
    "Exception in thread \"main\" "
    "com.android.apksig.apk.MinSdkVersionException: Failed to determine APK's "
    "minimum supported platform version. Use --min-sdk-version to override\n"
    "\tat com.android.apksigner.ApkSignerTool.sign(ApkSignerTool.java:420)\n"
    "\tat com.android.apksig.apk.ApkUtils"
    ".getMinSdkVersionFromBinaryAndroidManifest(ApkUtils.java:297)\n"
)


def _debug_keystore(tmp_path: Path, monkeypatch: Any) -> None:
    """Point the client at an existing debug keystore so the debug path runs."""
    debug = tmp_path / "debug.keystore"
    debug.write_bytes(b"ks")
    monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", debug)


def test_a_debug_sign_failure_keeps_the_public_password_and_diagnostics(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The public debug password ("android") is not scrubbed from stderr.

    It is not a secret (Google publishes it) and it is a substring of
    apksigner's own package path, so scrubbing it turned every
    "com.android.apksig..." frame into "com.***.apksig..." and destroyed the
    diagnostic. With keystore=None (the debug path), the error must come back
    verbatim -- no "***", "com.android.apksig" intact.
    """
    _debug_keystore(tmp_path, monkeypatch)
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    out = tmp_path / "signed.apk"

    def failing_sign(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        return "", _REAL_APKSIGNER_STDERR, 1

    monkeypatch.setattr(apktool_client, "_run", failing_sign)
    client = ApktoolClient(fake_tool, signer)
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, out)  # keystore=None -> public debug password path

    stderr = str(caught.value.details["stderr"])
    assert "***" not in stderr
    assert "com.android.apksig" in stderr
    assert "com.***.apksig" not in stderr


def test_a_debug_verify_failure_also_keeps_the_public_password(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The verify path shares the same rule: the public password stays intact."""
    _debug_keystore(tmp_path, monkeypatch)
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    out = tmp_path / "signed.apk"

    def failing_verify(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        if "verify" in cmd:
            return "", "DOES NOT VERIFY: com.android.apksig.ApkVerifier said no", 1
        out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr(apktool_client, "_run", failing_verify)
    client = ApktoolClient(fake_tool, signer)
    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, out)

    stderr = str(caught.value.details["stderr"])
    assert "***" not in stderr
    assert "com.android.apksig" in stderr


def test_a_caller_supplied_password_that_equals_android_is_still_scrubbed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Only the debug default is public: a custom keystore's password is secret.

    If a caller supplies their own keystore whose password happens to be
    "android", that is their secret, not the published debug constant, so it is
    redacted like any other -- the exemption is keyed on the debug path, not on
    the literal string.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"

    def failing_sign(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        return "", "refused with pass:android on the command line", 1

    monkeypatch.setattr(apktool_client, "_run", failing_sign)
    client = ApktoolClient(fake_tool, signer)
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk, out, keystore=keystore, keystore_password="android", key_alias="release"
        )

    stderr = str(caught.value.details["stderr"])
    assert "pass:***" in stderr
    assert "pass:android" not in stderr


def test_sign_keeps_the_keystore_password_off_the_command_line(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """SECURITY.md treats a signing password on any observable channel as a leak.

    ``--ks-pass pass:<pw>`` used to put the password into apksigner's argv, and
    argv is world-readable in the process table (``/proc/<pid>/cmdline`` on
    Linux, process listings on Windows) for as long as the signing JVM runs.
    apksigner reads ``env:NAME`` natively, so the password must travel in the
    child's copied environment and appear in no argument of either the sign or
    the verify invocation.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"
    password = "hunter2-release-pw"
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_run(
        cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
    ) -> tuple[str, str, int]:
        calls.append((list(cmd), env))
        if "verify" not in cmd:
            out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, signer)
    payload = client.sign(
        apk, out, keystore=keystore, keystore_password=password, key_alias="release"
    )
    assert payload["signed"] is True

    assert len(calls) == 2
    sign_cmd, sign_env = calls[0]
    assert all(password not in arg for arg in sign_cmd)
    # Both password sources point at the child-only variable that carries it.
    assert sign_cmd.count(f"env:{_PASSWORD_ENV}") == 2
    assert sign_env is not None
    assert sign_env[_PASSWORD_ENV] == password
    # verify needs no password: nothing secret in its argv, no injected env.
    verify_cmd, verify_env = calls[1]
    assert all(password not in arg for arg in verify_cmd)
    assert verify_env is None


def test_apk_sign_does_not_claim_signed_when_verify_fails(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = _write_apk(tmp_path / "a.apk")
    keystore = tmp_path / "debug.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"

    def fake_run(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        if "verify" in cmd:
            return "", "DOES NOT VERIFY", 1
        out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, signer)
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            out,
            keystore=keystore,
            keystore_password="android",
            key_alias="androiddebugkey",
        )
    assert caught.value.code == "backend_error"
    assert "not signed" in caught.value.message
