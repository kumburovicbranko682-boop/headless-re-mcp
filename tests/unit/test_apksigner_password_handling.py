"""apk.sign must keep the keystore password off argv and out of error details.

A command line is world-readable for as long as the process runs -- any local
user can read ``/proc/<pid>/cmdline`` (or a Windows process listing) -- so a
signing JVM invoked as ``apksigner ... --ks-pass pass:hunter2 ...`` leaks the
keystore password to every account on the box for the whole (JVM-startup-slow)
run. apksigner reads ``env:NAME`` natively, and a child's environment is not
world-readable the way its argv is, so this backend passes the password in
``APKSIGNER_KS_PASS`` and hands apksigner ``env:APKSIGNER_KS_PASS`` for both
``--ks-pass`` and ``--key-pass``. On failure it also scrubs the password out of
the tool's stderr before that text enters the error envelope, as defense in
depth against a diagnostic that echoes it back.

This is the most security-sensitive contract in the apktool backend and nothing
pinned it: the existing apktool test only covers zip-input validation. A refactor
to the shorter, very common ``pass:<password>`` argv idiom -- or dropping the
stderr scrub -- would reintroduce the leak silently. These tests fix it in place
with a fake ``_run`` that captures argv and env: the password appears in neither
the sign nor the verify argv, it does reach the child environment, both pass
arguments are the ``env:`` form, and a failing sign/verify never carries the
secret in its stderr detail.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import (
    _DEBUG_PASSWORD,
    _PASSWORD_ENV,
    ApktoolClient,
    ApktoolError,
)

_SECRET = "S3cr3t-KeystorePass!"


def _executable(path: Path) -> Path:
    # signer_available only checks is_file(), so any real file stands in.
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


class _RunSpy:
    """Captures every _run invocation's argv and env, scripting exit codes.

    apk.sign calls _run twice on the happy path -- ``sign`` then ``verify`` --
    so the spy answers by subcommand and records both so the test can assert the
    password never appears on either command line.
    """

    def __init__(self, *, sign_code: int = 0, sign_stderr: str = "",
                 verify_code: int = 0, verify_stderr: str = "") -> None:
        self.calls: list[dict[str, Any]] = []
        self._sign = (sign_stderr, sign_code)
        self._verify = (verify_stderr, verify_code)

    def __call__(
        self, cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
    ) -> tuple[str, str, int]:
        del timeout
        self.calls.append({"cmd": list(cmd), "env": dict(env or {})})
        if "verify" in cmd:
            return "", self._verify[0], self._verify[1]
        # A successful sign leaves a real signed APK behind; sign() checks
        # out_apk.is_file() before it will move on to verify, so a spy that
        # returned 0 without writing the file would be indistinguishable from a
        # failed sign. Write a valid zip to the --out path so the happy path and
        # the verify-failure path are actually reachable.
        if self._sign[1] == 0 and "--out" in cmd:
            out = Path(cmd[cmd.index("--out") + 1])
            with zipfile.ZipFile(out, "w") as archive:
                archive.writestr("META-INF/CERT.RSA", b"sig")
        return "", self._sign[0], self._sign[1]

    @property
    def sign_argv(self) -> list[str]:
        return self.calls[0]["cmd"]


def _client_signing(
    tmp_path: Path, monkeypatch: Any, spy: _RunSpy
) -> tuple[ApktoolClient, Path, Path]:
    monkeypatch.setattr(apktool_client, "_run", spy)
    apk = _real_apk(tmp_path / "app.apk")
    keystore = tmp_path / "custom.keystore"
    keystore.write_bytes(b"ks")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner"))
    return client, apk, keystore


def test_custom_keystore_password_never_lands_on_argv(
    tmp_path: Path, monkeypatch: Any
) -> None:
    spy = _RunSpy()
    client, apk, keystore = _client_signing(tmp_path, monkeypatch, spy)

    client.sign(
        apk,
        tmp_path / "signed.apk",
        keystore=keystore,
        keystore_password=_SECRET,
        key_alias="mykey",
    )

    # Not on the sign argv, and not on the verify argv either.
    for call in spy.calls:
        assert all(_SECRET not in str(token) for token in call["cmd"]), call["cmd"]
    # It did reach the child environment under the documented variable.
    sign_call = spy.calls[0]
    assert sign_call["env"].get(_PASSWORD_ENV) == _SECRET
    # Both credential arguments are the env: form apksigner reads natively.
    argv = spy.sign_argv
    assert argv[argv.index("--ks-pass") + 1] == f"env:{_PASSWORD_ENV}"
    assert argv[argv.index("--key-pass") + 1] == f"env:{_PASSWORD_ENV}"


def test_debug_keystore_default_password_is_not_on_argv(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The debug-keystore path fills in the well-known ``android`` password; it
    must go through the same env channel, not onto argv."""
    spy = _RunSpy()
    monkeypatch.setattr(apktool_client, "_run", spy)
    # Point the debug keystore at a real file so the is_file() gate passes.
    debug_ks = tmp_path / "debug.keystore"
    debug_ks.write_bytes(b"ks")
    monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", debug_ks)
    apk = _real_apk(tmp_path / "app.apk")
    client = ApktoolClient(None, _executable(tmp_path / "apksigner"))

    client.sign(apk, tmp_path / "signed.apk")

    # Target the leak idiom directly rather than a naive substring: the public
    # alias ``androiddebugkey`` legitimately contains ``android`` (the debug
    # password), so "password nowhere in argv" would false-positive here. What
    # must never appear is any ``pass:<password>`` source token; the credentials
    # must ride the ``env:`` source instead.
    argv = spy.sign_argv
    assert all(not str(token).startswith("pass:") for token in argv), argv
    assert f"pass:{_DEBUG_PASSWORD}" not in argv
    assert spy.calls[0]["env"].get(_PASSWORD_ENV) == _DEBUG_PASSWORD
    assert argv[argv.index("--ks-pass") + 1] == f"env:{_PASSWORD_ENV}"
    assert argv[argv.index("--key-pass") + 1] == f"env:{_PASSWORD_ENV}"


def test_a_failed_sign_scrubs_the_password_from_stderr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    spy = _RunSpy(sign_code=1, sign_stderr=f"keytool error: password {_SECRET} was rejected")
    client, apk, keystore = _client_signing(tmp_path, monkeypatch, spy)

    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password=_SECRET,
            key_alias="mykey",
        )

    detail = str(caught.value.details.get("stderr", ""))
    assert _SECRET not in detail
    assert "***" in detail


def test_a_failed_verify_scrubs_the_password_from_stderr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Sign succeeds, verify fails and echoes the password: still scrubbed."""
    spy = _RunSpy(
        verify_code=1, verify_stderr=f"not verified; check password {_SECRET}"
    )
    client, apk, keystore = _client_signing(tmp_path, monkeypatch, spy)

    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password=_SECRET,
            key_alias="mykey",
        )

    detail = str(caught.value.details.get("stderr", ""))
    assert _SECRET not in detail
    assert "***" in detail
