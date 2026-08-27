"""apk.sign must keep the keystore password out of the apksigner argv."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apktool.client import _KS_PASS_ENV, ApktoolClient


def test_the_keystore_password_rides_the_environment_not_argv(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """SECURITY.md counts a signing password leaving the client as a leak.

    Measured before the fix: apksigner ran with ``--ks-pass pass:<password>``
    and ``--key-pass pass:<password>`` in its argument vector, so any local
    process could read the password from /proc/<pid>/cmdline (or ps output)
    for the life of the sign. apksigner supports ``env:<name>``, so the
    password now travels in the child's environment instead: the argv carries
    only the variable name, the child env carries the secret on top of the
    inherited environment the JVM launcher needs, and this process's own
    os.environ is never touched.
    """
    monkeypatch.delenv(_KS_PASS_ENV, raising=False)
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

    def capture_run(cmd: list[str], **kwargs: Any) -> tuple[str, str, int]:
        calls.append((list(cmd), kwargs.get("env")))
        out.write_bytes(b"PKSIGN")
        return "", "", 0

    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._run", capture_run)
    client = ApktoolClient(fake_tool, signer)
    payload = client.sign(
        apk, out, keystore=keystore, keystore_password=password, key_alias="release"
    )
    assert payload["signed"] is True
    assert len(calls) == 2

    sign_cmd, sign_env = calls[0]
    assert all(password not in token for token in sign_cmd)
    assert sign_cmd[sign_cmd.index("--ks-pass") + 1] == f"env:{_KS_PASS_ENV}"
    assert sign_cmd[sign_cmd.index("--key-pass") + 1] == f"env:{_KS_PASS_ENV}"
    assert sign_env is not None
    assert sign_env[_KS_PASS_ENV] == password
    # apksigner is a JVM launcher; the child still needs everything it would
    # have inherited (PATH, JAVA_HOME, ...), just with the secret added.
    assert set(os.environ) <= set(sign_env)
    assert _KS_PASS_ENV not in os.environ

    verify_cmd, verify_env = calls[1]
    assert "verify" in verify_cmd
    assert all(password not in token for token in verify_cmd)
    assert verify_env is None
