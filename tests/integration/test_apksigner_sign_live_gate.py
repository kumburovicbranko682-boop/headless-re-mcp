"""apksigner sign live gate: really sign an APK and verify the signature.

``apk.sign`` (the apksigner side of the apktool line) only ran against mocks, so
nothing proved the backend actually produces a validly signed APK -- and this is
security-sensitive code: the keystore password is passed to apksigner through an
environment variable rather than argv, and a failure scrubs it from stderr. A
live gate that signs a real APK and then verifies the signature is the only way
to prove the functional path works against the real tool.

The gate creates its own throwaway keystore with ``keytool`` (JDK only), signs
the committed fixture APK through ``ApktoolClient.sign`` (the custom-keystore
path), and then independently runs ``apksigner verify`` on the output, so the
assertion is a real, externally-checked signature -- not just the client's own
return value.

Skip != pass: the gate skips with a reason when apksigner, a JRE or keytool is
absent, and runs for real when present. CI installs them, so a skip there is a
genuine regression rather than a bare machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "gate_sample.apk"


def _apksigner_path() -> Path | None:
    found = os.environ.get("HEADLESS_RE_APKSIGNER") or shutil.which("apksigner")
    if not found:
        return None
    path = Path(found)
    return path if path.is_file() else None


def _make_keystore(tmp_path: Path, *, password: str, alias: str) -> Path | None:
    keytool = shutil.which("keytool")
    if keytool is None:
        return None
    keystore = tmp_path / "gate.jks"
    result = subprocess.run(
        [
            keytool,
            "-genkeypair",
            "-keystore",
            str(keystore),
            "-storepass",
            password,
            "-keypass",
            password,
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "30",
            "-dname",
            "CN=Gate,O=Test,C=US",
        ],
        capture_output=True,
        timeout=120,
    )
    return keystore if result.returncode == 0 and keystore.is_file() else None


@pytest.mark.integration
def test_apksigner_signs_and_the_signature_verifies(tmp_path: Path) -> None:
    apksigner = _apksigner_path()
    if apksigner is None:
        pytest.skip("apksigner not installed/configured — sign Gate not run (skip != pass)")
    if shutil.which("java") is None:
        pytest.skip("no JRE for apksigner — sign Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    password, alias = "gatepass", "gatekey"
    keystore = _make_keystore(tmp_path, password=password, alias=alias)
    if keystore is None:
        pytest.skip("no keytool to build a keystore — sign Gate not run (skip != pass)")

    client = ApktoolClient(apksigner=apksigner)
    assert client.signer_available

    signed = tmp_path / "signed.apk"
    result = client.sign(
        _FIXTURE,
        signed,
        keystore=keystore,
        keystore_password=password,
        key_alias=alias,
        timeout=180.0,
    )
    # The client signs and then verifies internally, so a signed result already
    # means apksigner accepted it; assert the shape and that a real file exists.
    assert result["signed"] is True
    assert result["debug_keystore"] is False
    assert result["size"] > 0
    assert signed.is_file()
    assert zipfile.is_zipfile(signed)

    # Independently verify the signature so the gate does not lean on the
    # client's own verify step: this is an external check that it really signed.
    verify = subprocess.run(
        [str(apksigner), "verify", str(signed)],
        capture_output=True,
        timeout=120,
    )
    assert verify.returncode == 0, verify.stderr.decode("utf-8", "replace")[:400]
