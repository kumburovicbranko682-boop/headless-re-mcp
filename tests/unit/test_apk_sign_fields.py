"""apk.sign descriptions must name the fields apksigner actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool.client import (
    _KEY_PASSWORD_ENV,
    _PASSWORD_ENV,
    ApktoolClient,
    ApktoolError,
)
from headless_re_mcp.tools.apk import build_apk_tools


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
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
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
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
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
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
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


def test_sign_uses_a_distinct_key_password_when_the_caller_gives_one(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A release keystore can guard its key with its own password.

    When key_password differs from the store password, --key-pass must point at
    a second child-only variable carrying that key password, while --ks-pass
    keeps carrying the store password. Neither secret may appear on argv.
    """
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"
    store_pw = "store-pw"
    key_pw = "key-pw-different"
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
        apk,
        out,
        keystore=keystore,
        keystore_password=store_pw,
        key_alias="release",
        key_password=key_pw,
    )
    assert payload["signed"] is True

    sign_cmd, sign_env = calls[0]
    assert all(store_pw not in arg for arg in sign_cmd)
    assert all(key_pw not in arg for arg in sign_cmd)
    # The store password stays on --ks-pass; the key password rides its own var.
    assert sign_cmd.count(f"env:{_PASSWORD_ENV}") == 1
    assert f"env:{_KEY_PASSWORD_ENV}" in sign_cmd
    assert sign_env is not None
    assert sign_env[_PASSWORD_ENV] == store_pw
    assert sign_env[_KEY_PASSWORD_ENV] == key_pw


def test_sign_scrubs_a_distinct_key_password_from_stderr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A leaked key password in tool output must be masked like the store one."""
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
    keystore = tmp_path / "release.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"
    store_pw = "store-pw"
    key_pw = "key-pw-secret"

    def failing_sign(cmd: list[str], **_kwargs: Any) -> tuple[str, str, int]:
        return "", f"error near env:{key_pw} and {store_pw}", 1

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", failing_sign)
    client = ApktoolClient(fake_tool, signer)
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            out,
            keystore=keystore,
            keystore_password=store_pw,
            key_alias="release",
            key_password=key_pw,
        )
    stderr = str(caught.value.details["stderr"])
    assert store_pw not in stderr
    assert key_pw not in stderr
    assert "***" in stderr


def test_apk_sign_does_not_claim_signed_when_verify_fails(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake_tool = tmp_path / "apktool.bat"
    fake_tool.write_text("x\n", encoding="utf-8")
    signer = tmp_path / "apksigner.bat"
    signer.write_text("x\n", encoding="utf-8")
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK")
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
