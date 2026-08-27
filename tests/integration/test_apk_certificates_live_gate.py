"""apk.certificates live gate: real v1 signer parsed from a real signed APK.

``apk.certificates`` was only ever run against a fake APK whose certificate
objects were plain strings, so nothing exercised androguard's real
``get_certificates()``. That mock hid a defect: androguard returns
``asn1crypto.x509.Name`` objects for subject/issuer, and the client rendered them
with ``str()`` -- which is an object repr carrying a memory address
(``<asn1crypto.x509.Name 0x.. b'..'>``), not a readable distinguished name. An
agent asking "who signed this APK" got an unstable repr instead of the signer.
The client now renders the ``human_friendly`` DN; this gate pins that against a
real signature.

It builds a real v1 (JAR) signed APK with the JDK's own keytool/jarsigner -- no
Android SDK needed -- with a known distinguished name, then drives
``ApkClient.certificates`` and asserts:

  * the v1 signature is seen (``v1_signed`` True, a ``META-INF/*.RSA`` file); and
  * the certificate's subject/issuer are the readable DN carrying the CN and O we
    signed with -- and specifically not the ``asn1crypto`` object repr the mock
    never caught -- with a decimal serial and a 64-hex-char SHA-256 fingerprint.

Skip != pass: the gate skips with a reason when androguard or the JDK signing
tools are absent. CI installs both, so a skip there is a real regression.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

try:  # androguard logs a warning per parse; keep the gate output clean.
    from loguru import logger as _loguru_logger

    _loguru_logger.disable("androguard")
except Exception:  # noqa: BLE001 - loguru is androguard's dep, absent when it is
    pass

_STOREPASS = "changeit"
# The distinguished name we sign with; the gate asserts these survive into the
# parsed subject as a readable DN rather than an object repr.
_CN = "Headless RE Gate"
_ORG = "HeadlessRE"
_DNAME = f"CN={_CN}, O={_ORG}, C=US"


@pytest.fixture(scope="module")
def signed_apk(tmp_path_factory: pytest.TempPathFactory) -> Path:
    keytool = shutil.which("keytool")
    jarsigner = shutil.which("jarsigner")
    if keytool is None or jarsigner is None:
        pytest.skip("keytool/jarsigner (JDK) missing — cert gate not run (skip != pass)")

    workdir = tmp_path_factory.mktemp("apk-cert")
    apk = workdir / "app.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("resources.arsc", b"\x00\x00\x00\x00")

    keystore = workdir / "gate.jks"
    keytool_result = subprocess.run(
        [
            keytool, "-genkeypair", "-keystore", str(keystore),
            "-storepass", _STOREPASS, "-keypass", _STOREPASS,
            "-alias", "gatekey", "-dname", _DNAME,
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if keytool_result.returncode != 0:
        pytest.skip(f"keytool could not make a keystore: {keytool_result.stderr.strip()[:200]}")

    jarsigner_result = subprocess.run(
        [
            jarsigner, "-keystore", str(keystore),
            "-storepass", _STOREPASS, "-keypass", _STOREPASS,
            "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
            str(apk), "gatekey",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if jarsigner_result.returncode != 0:
        pytest.skip(f"jarsigner could not sign the apk: {jarsigner_result.stderr.strip()[:200]}")
    return apk


@pytest.mark.integration
def test_certificates_reads_the_v1_signer_as_a_readable_dn(signed_apk: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — apk certificates gate not run (skip != pass)")

    result = client.certificates(signed_apk)

    assert result["v1_signed"] is True
    assert result["has_more"] is False
    signature_files = result["signature_files"]
    assert isinstance(signature_files, list) and signature_files
    assert any(name.endswith(".RSA") for name in signature_files), signature_files

    certificates = result["certificates"]
    assert isinstance(certificates, list) and certificates, "no certificates parsed"
    cert = certificates[0]

    # The fix: subject/issuer are the human-readable DN, not the asn1crypto
    # object repr the mock-only test never exercised.
    subject = cert["subject"]
    assert _CN in subject, subject
    assert _ORG in subject, subject
    assert "asn1crypto" not in subject and "0x" not in subject, subject
    # This APK is self-signed, so the issuer is the same authority as the subject.
    assert cert["issuer"] == subject

    # Serial is a decimal integer string; parsing it must succeed.
    serial = cert["serial"]
    assert serial and int(serial)

    # The SHA-256 fingerprint is 32 bytes -> 64 hex chars once separators are
    # stripped, and every remaining character is a hex digit.
    compact = cert["sha256"].replace(" ", "").replace(":", "")
    assert len(compact) == 64, cert["sha256"]
    int(compact, 16)
