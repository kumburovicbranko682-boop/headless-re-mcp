"""Live androguard gate: signer-certificate triage over a real signed APK.

The signing gate proves ApktoolClient.sign produces an APK that ``apksigner
verify`` accepts, but never asks androguard *who* signed it -- the certificate
identity and fingerprint an analyst pivots on ("is this the same signer as that
other sample?"). That path (androguard parsing the v1 JAR signature block and
the certificate DER) is unproven, so a regression in ApkClient.certificates or
androguard's PKCS#7 handling would misreport the signer while the sign gate
stayed green.

This gate builds a framework-free APK, signs it through ApktoolClient.sign with
a keytool keystore whose distinguished name is known, then asserts androguard
recovers exactly one v1 signer certificate whose subject/issuer carry that DN
and whose SHA-256 fingerprint equals the one ``apksigner verify --print-certs``
reports independently -- two tools agreeing on the signer identity, byte for
byte.

Skips honestly when apktool, apksigner, keytool (JDK) or androguard is missing.
skip != pass.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings

_PACKAGE = "com.headlessre.certgate"
# Distinctive RDN values so the parsed DN can be matched unambiguously; the
# certificate is self-signed, so subject and issuer carry the same name.
_DN = "CN=gatecert, O=HeadlessRE, C=US"
_DN_TOKENS = ("gatecert", "HeadlessRE", "US")
_ALIAS = "gatekey"
_STOREPASS = "gatepass"

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"


def _make_keystore(dest: Path) -> Path | None:
    keytool = shutil.which("keytool")
    if keytool is None:
        return None
    keystore = dest / "gate.keystore"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local keytool
            [
                keytool,
                "-genkeypair",
                "-keystore",
                str(keystore),
                "-storepass",
                _STOREPASS,
                "-keypass",
                _STOREPASS,
                "-alias",
                _ALIAS,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "365",
                "-dname",
                _DN,
            ],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return keystore if keystore.is_file() else None


def _apksigner_cert_sha256(apksigner: Path, apk: Path) -> str | None:
    """The signer certificate SHA-256 as apksigner reports it (hex, no spaces)."""
    proc = subprocess.run(  # noqa: S603 - fixed args, configured apksigner
        [str(apksigner), "verify", "--print-certs", "--verbose", str(apk)],
        capture_output=True,
        timeout=60.0,
    )
    if proc.returncode != 0:
        return None
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        match = re.search(r"certificate SHA-?256 digest:\s*([0-9A-Fa-f]+)", line)
        if match:
            return match.group(1).lower()
    return None


@pytest.mark.integration
def test_android_signer_certificate_identity_matches_apksigner(tmp_path: Path) -> None:
    settings = Settings.load()
    client = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not client.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    if not client.signer_available or settings.apksigner is None:
        pytest.skip("apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — skip != pass")
    apk_client = ApkClient()
    if not apk_client.available:
        pytest.skip("androguard not installed — cert Gate not run (skip != pass)")

    skeleton = tmp_path / "skeleton"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    built = client.build(skeleton, tmp_path / "built.apk")

    keystore = _make_keystore(tmp_path)
    if keystore is None:
        pytest.skip("no keytool (JDK) to make a keystore — cert Gate not run (skip != pass)")

    signed_apk = tmp_path / "signed.apk"
    signed = client.sign(
        Path(built["apk"]),
        signed_apk,
        keystore=keystore,
        keystore_password=_STOREPASS,
        key_alias=_ALIAS,
    )
    assert signed["signed"] is True, signed

    # androguard parses the signature block and DER certificate.
    certs = apk_client.certificates(signed_apk)
    assert certs["v1_signed"] is True, certs
    # The v1 signature file is named after the key alias (GATEKEY.RSA).
    assert any(
        name.upper().endswith(".RSA") and _ALIAS.upper() in name.upper()
        for name in certs["signature_files"]
    ), certs["signature_files"]

    assert len(certs["certificates"]) == 1, certs
    cert = certs["certificates"][0]

    # Subject and issuer carry the DN we minted (self-signed -> identical), so
    # the parsed identity is the one we control, not a default debug key.
    for token in _DN_TOKENS:
        assert token in cert["subject"], cert["subject"]
        assert token in cert["issuer"], cert["issuer"]
    assert cert["serial"].isdigit() and int(cert["serial"]) > 0, cert

    # The decisive cross-check: androguard's parsed fingerprint equals the one
    # apksigner computes independently, normalised to bare lowercase hex.
    andro_sha256 = cert["sha256"].replace(" ", "").replace(":", "").lower()
    assert len(andro_sha256) == 64, cert["sha256"]
    apksigner_sha256 = _apksigner_cert_sha256(Path(str(settings.apksigner)), signed_apk)
    assert apksigner_sha256 is not None, "apksigner verify --print-certs did not report a digest"
    assert andro_sha256 == apksigner_sha256, (andro_sha256, apksigner_sha256)
