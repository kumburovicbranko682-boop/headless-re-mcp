"""apk.sign descriptions must name the fields apksigner actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
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


def test_apk_sign_keeps_the_keystore_password_out_of_argv(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A password on the command line is world-readable while apksigner runs.

    ``--ks-pass pass:<secret>`` puts the keystore password in the process
    argument vector, which any local user can read from /proc/<pid>/cmdline for
    the life of the process -- the same leak class SECURITY.md treats as a
    vulnerability and the stderr scrubbing already guards. The client must feed
    the secret through the environment (env:NAME) instead: the argv names only
    the variable, and the value rides in the child env (/proc/<pid>/environ is
    owner-only).
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

    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(cmd: list[str], *, timeout: float, env: Any = None) -> tuple[str, str, int]:
        del timeout
        calls.append((list(cmd), dict(env) if env else {}))
        out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", fake_run)
    client = ApktoolClient(fake_tool, signer)
    client.sign(apk, out, keystore=keystore, keystore_password=password, key_alias="release")

    sign_cmd, sign_env = next((cmd, env) for cmd, env in calls if "sign" in cmd)
    # The secret is nowhere in the argument vector...
    assert password not in " ".join(sign_cmd)
    assert f"pass:{password}" not in sign_cmd
    # ...the password args now point at environment variables...
    ks_pass = sign_cmd[sign_cmd.index("--ks-pass") + 1]
    key_pass = sign_cmd[sign_cmd.index("--key-pass") + 1]
    assert ks_pass.startswith("env:")
    assert key_pass.startswith("env:")
    # ...and the value actually rides in the child environment under them.
    assert sign_env.get(ks_pass.split(":", 1)[1]) == password
    assert sign_env.get(key_pass.split(":", 1)[1]) == password


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
