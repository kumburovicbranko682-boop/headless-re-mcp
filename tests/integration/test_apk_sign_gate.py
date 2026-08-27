"""apk.sign gate: real apksigner diagnostics survive the password scrub.

The signing client scrubs keystore passwords from apksigner's stderr before
they enter an error envelope. The Android debug keystore password is the
published constant ``android``, which is also a substring of every
``com.android.apksig...`` stack frame apksigner prints -- so a blanket scrub
turned a real failure diagnostic into ``com.***.apksig...`` noise. Nothing
launched the real apksigner, so that corruption was invisible to the unit
suite; this gate signs with the actual tool and asserts the diagnostic comes
back readable. skip != pass: it runs for real when apksigner + keytool are
present and only skips when they are absent.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import headless_re_mcp.backends.apktool.client as apktool_client
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.config import Settings

_SKIP_NO_TOOLS = "apksigner/keytool not configured — APK sign gate not run (skip != pass)"


def _apksigner() -> Path | None:
    configured = Settings.load().apksigner
    if configured is not None and configured.is_file():
        return configured
    found = shutil.which("apksigner")
    return Path(found) if found else None


def _keytool() -> Path | None:
    found = shutil.which("keytool")
    return Path(found) if found else None


def _make_debug_keystore(dest: Path, keytool: Path) -> None:
    subprocess.run(
        [
            str(keytool),
            "-genkeypair",
            "-v",
            "-keystore",
            str(dest),
            "-storepass",
            "android",
            "-keypass",
            "android",
            "-alias",
            "androiddebugkey",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Android Debug,O=Android,C=US",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )


def _invalid_apk(path: Path) -> Path:
    """A zip APK whose manifest is not real AXML: apksigner rejects it, printing
    a genuine com.android.apksig diagnostic -- exactly the text the scrub mangled."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00not-real-axml")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
    return path


@pytest.mark.integration
def test_debug_sign_failure_keeps_apksigner_diagnostic_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apksigner = _apksigner()
    keytool = _keytool()
    if apksigner is None or keytool is None:
        pytest.skip(_SKIP_NO_TOOLS)

    keystore = tmp_path / "debug.keystore"
    _make_debug_keystore(keystore, keytool)
    # Route the client's debug path at our temp keystore instead of ~/.android,
    # so the public-password exemption is exercised without touching real HOME.
    monkeypatch.setattr(apktool_client, "_DEBUG_KEYSTORE", keystore)

    apk = _invalid_apk(tmp_path / "invalid.apk")
    client = ApktoolClient(apksigner=apksigner)

    with pytest.raises(ApktoolError) as caught:
        client.sign(apk, tmp_path / "out.apk")  # keystore=None -> debug path

    stderr = str(caught.value.details.get("stderr", ""))
    # The real tool must have actually run and failed on the manifest.
    assert stderr, "apksigner produced no diagnostic"
    assert caught.value.code == "backend_error"
    # The published debug password is not redacted, so the package path in every
    # frame stays intact rather than becoming com.***.apksig.
    assert "com.android.apksig" in stderr, stderr[:400]
    assert "com.***.apksig" not in stderr
    assert "***" not in stderr


@pytest.mark.integration
def test_custom_keystore_secret_is_scrubbed_from_a_real_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller-supplied password is still redacted even from real tool output.

    apksigner takes the password by env, so its own stderr will not echo it; to
    prove the scrub still fires for a genuine secret we surface a line that does
    contain it and assert the redaction. This guards the exemption from being
    widened into "never scrub".
    """
    apksigner = _apksigner()
    keytool = _keytool()
    if apksigner is None or keytool is None:
        pytest.skip(_SKIP_NO_TOOLS)

    keystore = tmp_path / "release.keystore"
    secret = "s3cr3t-release-pw"
    subprocess.run(
        [
            str(keytool),
            "-genkeypair",
            "-keystore",
            str(keystore),
            "-storepass",
            secret,
            "-keypass",
            secret,
            "-alias",
            "release",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Release,O=Test,C=US",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )

    # Force a failure whose stderr contains the secret, so the scrub has
    # something real to redact on the actual code path.
    real_run = apktool_client._run

    def run_with_secret_leak(
        cmd: list[str], *, timeout: float, env: dict[str, str] | None = None
    ) -> tuple[str, str, int]:
        out, err, code = real_run(cmd, timeout=timeout, env=env)
        if "verify" not in cmd:
            return out, err + f"\nleaked pass:{secret} in a log line", max(code, 1)
        return out, err, code

    monkeypatch.setattr(apktool_client, "_run", run_with_secret_leak)

    apk = _invalid_apk(tmp_path / "invalid.apk")
    client = ApktoolClient(apksigner=apksigner)

    with pytest.raises(ApktoolError) as caught:
        client.sign(
            apk,
            tmp_path / "out.apk",
            keystore=keystore,
            keystore_password=secret,
            key_alias="release",
        )

    stderr = str(caught.value.details.get("stderr", ""))
    assert secret not in stderr
    assert "pass:***" in stderr
