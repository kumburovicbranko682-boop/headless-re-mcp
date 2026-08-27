"""apksigner live gate: real sign -> real verify. skip != pass when tools absent.

Every apksigner test so far drives a fake ``_run``; nothing launches the real
apksigner, so ``ApktoolClient.sign`` -- the ``env:`` password hand-off, the
post-sign verify call, and the signed envelope -- has never been proven against
the actual tool. This gate builds a real (pyaxml) APK, signs it with a
keytool-generated keystore through the real apksigner, and independently
re-verifies the output, for both the caller-supplied keystore and the built-in
debug keystore.

apksigner and keytool both need a JRE; the fixture needs pyaxml. With any of
them missing the gate skips loudly rather than passing silently (skip != pass).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILDER = _PROJECT_ROOT / "fixtures" / "android" / "build_signable_apk.py"
_SKIP_NO_APKSIGNER = (
    "apksigner not configured (HEADLESS_RE_APKSIGNER/PATH) — live gate not run (skip != pass)"
)
_DEBUG_ALIAS = "androiddebugkey"
_DEBUG_PASSWORD = "android"


def _discover_apksigner() -> Path | None:
    candidate = os.environ.get("HEADLESS_RE_APKSIGNER")
    if candidate and Path(candidate).is_file():
        return Path(candidate)
    for name in ("apksigner", "apksigner.bat"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _client_or_skip() -> tuple[ApktoolClient, Path]:
    apksigner = _discover_apksigner()
    if apksigner is None:
        pytest.skip(_SKIP_NO_APKSIGNER)
    keytool = shutil.which("keytool")
    if keytool is None:
        pytest.skip("keytool not on PATH (needs a JDK) — live gate not run (skip != pass)")
    client = ApktoolClient(None, apksigner)
    if not client.signer_available:
        pytest.skip(f"apksigner path is not a file: {apksigner} (skip != pass)")
    return client, Path(keytool)


def _build_signable_apk(tmp_path: Path) -> Path:
    spec = importlib.util.spec_from_file_location("_signable_apk_builder", _BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    apk = tmp_path / "unsigned.apk"
    try:
        module.build_apk(apk)
    except ModuleNotFoundError as exc:  # pyaxml / lxml absent
        pytest.skip(f"{exc.name} not installed; cannot build AXML fixture (skip != pass)")
    assert apk.is_file() and apk.stat().st_size > 0
    return apk


def _make_keystore(keytool: Path, path: Path, *, storepass: str, alias: str, keypass: str) -> None:
    subprocess.run(
        [
            str(keytool),
            "-genkeypair",
            "-keystore",
            str(path),
            "-storepass",
            storepass,
            "-keypass",
            keypass,
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Sign Gate, O=Test, C=US",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )


def _assert_independently_verified(apksigner: Path, apk: Path) -> None:
    verify = subprocess.run(
        [str(apksigner), "verify", str(apk)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert verify.returncode == 0, verify.stderr or verify.stdout


@pytest.mark.integration
def test_apksigner_signs_and_verifies_with_a_custom_keystore(tmp_path: Path) -> None:
    client, keytool = _client_or_skip()
    apk = _build_signable_apk(tmp_path)

    keystore = tmp_path / "release.keystore"
    _make_keystore(
        keytool,
        keystore,
        storepass="release-store-pw",
        alias="releasekey",
        keypass="release-store-pw",
    )
    out = tmp_path / "signed-custom.apk"
    result = client.sign(
        apk,
        out,
        keystore=keystore,
        keystore_password="release-store-pw",
        key_alias="releasekey",
        timeout=200.0,
    )
    assert result["signed"] is True, result
    assert result["debug_keystore"] is False, result
    assert result["keystore"] == str(keystore), result
    assert Path(result["apk"]).is_file()
    # The client already ran apksigner verify internally (it would have raised
    # otherwise); re-verify from outside to prove the artifact stands alone.
    _assert_independently_verified(client.apksigner, out)  # type: ignore[arg-type]


@pytest.mark.integration
def test_apksigner_signs_with_the_default_debug_keystore(tmp_path: Path, monkeypatch: Any) -> None:
    """The keystore=None path must sign against the built-in debug keystore.

    Point the module's debug-keystore constant at a temp keystore carrying the
    standard debug alias/password so the test never touches ``~/.android``, then
    sign with ``keystore=None`` -- the default an analyst gets -- and confirm the
    envelope reports the debug keystore and the output actually verifies.
    """
    client, keytool = _client_or_skip()
    apk = _build_signable_apk(tmp_path)

    debug_keystore = tmp_path / "debug.keystore"
    _make_keystore(
        keytool,
        debug_keystore,
        storepass=_DEBUG_PASSWORD,
        alias=_DEBUG_ALIAS,
        keypass=_DEBUG_PASSWORD,
    )
    monkeypatch.setattr("headless_re_mcp.backends.apktool.client._DEBUG_KEYSTORE", debug_keystore)
    out = tmp_path / "signed-debug.apk"
    result = client.sign(apk, out, timeout=200.0)
    assert result["signed"] is True, result
    assert result["debug_keystore"] is True, result
    assert result["keystore"] == str(debug_keystore), result
    _assert_independently_verified(client.apksigner, out)  # type: ignore[arg-type]


@pytest.mark.integration
def test_apksigner_rejects_a_wrong_keystore_password(tmp_path: Path) -> None:
    """A wrong password is a structured backend_error, and never leaks the secret.

    apksigner exits non-zero when the store password is wrong; the client must
    surface that as ApktoolError, not a crash, and the caller-supplied password
    must not appear anywhere in the error details.
    """
    client, keytool = _client_or_skip()
    apk = _build_signable_apk(tmp_path)

    keystore = tmp_path / "release.keystore"
    _make_keystore(
        keytool,
        keystore,
        storepass="correct-horse-battery",
        alias="releasekey",
        keypass="correct-horse-battery",
    )
    wrong = "totally-wrong-password"
    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "nope.apk",
            keystore=keystore,
            keystore_password=wrong,
            key_alias="releasekey",
            timeout=200.0,
        )
    assert caught.value.code == "backend_error", caught.value.code
    assert wrong not in str(caught.value.details), caught.value.details
