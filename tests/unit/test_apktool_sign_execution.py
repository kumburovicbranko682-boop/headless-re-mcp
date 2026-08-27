"""apk.sign must keep the keystore password off argv and out of error details.

The signing contract is a security one, and it lives entirely past the point the
input-validation tests stop at (they raise from the ``_run`` stub before it
returns, so the sign body never ran). Two guarantees have to hold on the real
execution path:

  * the password reaches apksigner through a child-only environment variable and
    the ``--ks-pass env:NAME`` / ``--key-pass env:NAME`` source, never as
    ``pass:<secret>`` on argv -- a command line is world-readable in the process
    table (``/proc/<pid>/cmdline``) for as long as the signing JVM runs.
  * when apksigner fails -- signing *or* the follow-up verify -- its stderr is
    scrubbed of the password before it lands in the error details, defense in
    depth in case the tool ever echoes what it was given.

And the happy path must actually verify the output and report it signed. These
script the module-level ``_run`` (the same seam the validation tests monkeypatch)
so the sign body runs end to end without a JRE.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import client as apktool_client
from headless_re_mcp.backends.apktool.client import (
    _DEBUG_ALIAS,
    _DEBUG_PASSWORD,
    _PASSWORD_ENV,
    ApktoolClient,
    ApktoolError,
)

_PASSWORD = "s3cr3t-pw-\u00a1123"


def _executable(path: Path) -> Path:
    # signer_available only checks is_file(), so any real file stands in.
    path.write_text("x\n", encoding="utf-8")
    return path


def _real_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


class _ScriptedRun:
    """A ``_run`` double that scripts the sign call and the verify call apart.

    apktool.sign runs two subprocesses -- ``apksigner sign`` then ``apksigner
    verify`` -- distinguished by argv[1]. This records both invocations (argv,
    timeout, env) and returns the configured (stderr, exit) for each, optionally
    materialising the ``--out`` file so the ``out_apk.is_file()`` success check
    passes without a real signer.
    """

    def __init__(
        self,
        *,
        sign_code: int = 0,
        sign_stderr: str = "",
        verify_code: int = 0,
        verify_stderr: str = "",
        write_output: bool = True,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._sign_code = sign_code
        self._sign_stderr = sign_stderr
        self._verify_code = verify_code
        self._verify_stderr = verify_stderr
        self._write_output = write_output

    def __call__(
        self, cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
    ) -> tuple[str, str, int]:
        self.calls.append({"cmd": list(cmd), "timeout": timeout, "env": env})
        if cmd[1] == "sign":
            if self._write_output:
                out = Path(cmd[cmd.index("--out") + 1])
                out.write_bytes(b"signed-bytes")
            return "", self._sign_stderr, self._sign_code
        return "", self._verify_stderr, self._verify_code

    @property
    def sign_call(self) -> dict[str, Any]:
        return self.calls[0]


def _client_with(monkeypatch: Any, tmp_path: Path, run: _ScriptedRun) -> ApktoolClient:
    monkeypatch.setattr(apktool_client, "_run", run)
    signer = _executable(tmp_path / "apksigner.bat")
    return ApktoolClient(None, signer)


def test_sign_success_keeps_the_password_off_argv_and_in_the_child_env(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The secret travels by env var, not argv, and the output is verified signed.

    This is the whole reason the backend uses ``env:NAME`` instead of
    ``pass:<secret>``: the password must never appear in any argv element (which
    the process table exposes), only in the child-only environment under
    ``_PASSWORD_ENV``. The follow-up verify is a separate ``_run`` that is not
    handed that environment at all, and a clean pass reports ``signed: True``.
    """
    apk = _real_apk(tmp_path / "in.apk")
    keystore = tmp_path / "my.keystore"
    keystore.write_bytes(b"ks")
    out = tmp_path / "signed.apk"
    run = _ScriptedRun()
    client = _client_with(monkeypatch, tmp_path, run)

    result = client.sign(
        apk, out, keystore=keystore, keystore_password=_PASSWORD, key_alias="myalias"
    )

    assert result["signed"] is True
    assert result["debug_keystore"] is False
    assert result["keystore"] == str(keystore)
    assert result["apk"] == str(out)

    sign_cmd = run.sign_call["cmd"]
    # The password is nowhere on the command line...
    assert not any(_PASSWORD in str(arg) for arg in sign_cmd)
    # ...it is only in the child's environment, read via the env: source.
    assert run.sign_call["env"][_PASSWORD_ENV] == _PASSWORD
    assert sign_cmd.count(f"env:{_PASSWORD_ENV}") == 2  # --ks-pass and --key-pass
    assert "myalias" in sign_cmd

    # A second _run verified the output, and it was not given the password env.
    assert len(run.calls) == 2
    verify_cmd = run.calls[1]["cmd"]
    assert verify_cmd[1] == "verify"
    assert run.calls[1]["env"] is None


def test_a_failed_sign_scrubs_the_password_from_stderr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apksigner's own diagnostics must not carry the secret into error details.

    Even though argv no longer holds the password, a tool that echoes it into
    stderr would leak it through the error the caller sees. The failure path
    replaces the password with ``***`` before it reaches ``details['stderr']``.
    """
    apk = _real_apk(tmp_path / "in.apk")
    keystore = tmp_path / "my.keystore"
    keystore.write_bytes(b"ks")
    run = _ScriptedRun(
        sign_code=1,
        sign_stderr=f"error: keystore password {_PASSWORD} was rejected",
        write_output=False,
    )
    client = _client_with(monkeypatch, tmp_path, run)

    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password=_PASSWORD,
            key_alias="myalias",
        )
    assert caught.value.code == "backend_error"
    stderr = str(caught.value.details.get("stderr"))
    assert _PASSWORD not in stderr
    assert "***" in stderr


def test_a_failed_verify_scrubs_the_password_and_reports_unsigned(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A sign that 'succeeds' but does not verify is a failure, still scrubbed.

    The verify step is what stops an unusable file from being reported as signed
    and passed on to install. When it fails, the error names the unsigned output
    and -- like the sign failure -- scrubs the password from the verify stderr.
    """
    apk = _real_apk(tmp_path / "in.apk")
    keystore = tmp_path / "my.keystore"
    keystore.write_bytes(b"ks")
    run = _ScriptedRun(
        sign_code=0,
        verify_code=1,
        verify_stderr=f"DOES NOT VERIFY (pass={_PASSWORD})",
    )
    client = _client_with(monkeypatch, tmp_path, run)

    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "signed.apk",
            keystore=keystore,
            keystore_password=_PASSWORD,
            key_alias="myalias",
        )
    assert caught.value.code == "backend_error"
    assert "not signed" in caught.value.message
    stderr = str(caught.value.details.get("stderr"))
    assert _PASSWORD not in stderr
    assert "***" in stderr


def test_sign_defaults_to_the_android_debug_keystore(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """With no keystore given, the standard debug keystore and its creds are used.

    The convenience path an agent hits most: no keystore means the Android debug
    keystore with its well-known alias and password ``android``. The debug
    password must still travel by env var (never argv), the debug alias must be
    on the command line, and the result must flag ``debug_keystore: True`` so the
    caller knows it was signed with the shared debug key, not a private one.
    """
    apk = _real_apk(tmp_path / "in.apk")
    debug_keystore = tmp_path / "debug.keystore"
    debug_keystore.write_bytes(b"ks")
    monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", debug_keystore)
    out = tmp_path / "signed.apk"
    run = _ScriptedRun()
    client = _client_with(monkeypatch, tmp_path, run)

    result = client.sign(apk, out)  # no keystore / password / alias

    assert result["debug_keystore"] is True
    assert result["keystore"] == str(debug_keystore)
    sign_cmd = run.sign_call["cmd"]
    assert _DEBUG_ALIAS in sign_cmd
    # The debug password is used, but through the env var -- not on argv.
    assert run.sign_call["env"][_PASSWORD_ENV] == _DEBUG_PASSWORD
    # Exact-token membership, not substring: 'android' is legitimately inside the
    # alias 'androiddebugkey' and the keystore path, but must never appear as its
    # own credential token or a pass:<secret> source.
    assert _DEBUG_PASSWORD not in sign_cmd
    assert f"pass:{_DEBUG_PASSWORD}" not in sign_cmd
