"""APK signing gate: apk.certificates over a *signed* APK, real cert fields.

The manifest gate can only assert the unsigned path (``v1_signed == False``,
empty cert list) because ``fixtures/android/fixture.apk`` carries no signature.
That leaves the whole certificate-parsing surface -- ``get_signature_names`` /
``get_certificates`` and the subject / issuer / serial / sha256 it yields --
unverified against a real signature block. androguard wraps each cert as an
``asn1crypto.x509.Certificate``; ``str(cert.subject)`` is the Name object's repr
(a live memory address plus raw DER), so the readable DN only appears when the
code renders ``.human_friendly`` -- a version-sensitive detail no fake-based test
touched, since none had a real signed APK.

This gate uses ``fixtures/android/fixture-signed.apk`` (the same fixture v1-signed
with a throwaway self-signed key) and drives the full ``AnalysisService`` stack,
pinning that the cert comes back with a readable subject/issuer and a real
fingerprint -- and that the object-repr leak (memory address / raw DER) is gone.
Skips (skip != pass) when the ``android`` extra is absent.

The signed fixture was produced from the unsigned one with the JDK toolchain::

    keytool -genkeypair -keystore ks.jks -storepass fixture123 -keypass fixture123 \\
        -alias fixturekey -keyalg RSA -keysize 2048 -validity 10000 \\
        -dname "CN=Fixture Test, OU=RE, O=Example, L=City, ST=State, C=US"
    cp fixtures/android/fixture.apk fixtures/android/fixture-signed.apk
    jarsigner -keystore ks.jks -storepass fixture123 -keypass fixture123 \\
        -sigalg SHA256withRSA -digestalg SHA-256 \\
        fixtures/android/fixture-signed.apk fixturekey
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.core.service import AnalysisService

_SIGNED_APK = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "fixture-signed.apk"


@pytest.mark.integration
def test_apk_certificates_over_a_signed_apk() -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK signing Gate not run (skip != pass)")
    if not _SIGNED_APK.is_file():
        pytest.skip(f"signed fixture missing: {_SIGNED_APK}")

    service = AnalysisService()
    try:
        created = service.create_session(str(_SIGNED_APK))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        certificates = service.apk_certificates(session_id)
        assert certificates.ok, certificates.error
        data = certificates.data

        # A v1 (JAR) signature must be recognised and its META-INF block named.
        assert data["v1_signed"] is True
        assert data["signature_files"], "no signature files surfaced"
        assert any(name.upper().endswith(".RSA") for name in data["signature_files"])

        # Exactly one signer, and its fields must be the parsed, readable values.
        assert len(data["certificates"]) == 1
        cert = data["certificates"][0]

        # subject / issuer are the human-friendly DN, not the Name object repr.
        assert "Fixture Test" in cert["subject"]
        assert "Example" in cert["subject"]
        assert cert["issuer"], "issuer empty"
        # the exact object-repr leak this fixed must not reappear
        assert "asn1crypto" not in cert["subject"]
        assert "b'" not in cert["subject"]

        # serial is a real integer rendered as text; sha256 a real fingerprint.
        assert cert["serial"].lstrip("-").isdigit()
        assert cert["sha256"]
        hex_chars = set("0123456789ABCDEFabcdef :")
        assert set(cert["sha256"]) <= hex_chars, cert["sha256"]
        assert sum(ch in "0123456789ABCDEFabcdef" for ch in cert["sha256"]) == 64
    finally:
        service.close_all()
