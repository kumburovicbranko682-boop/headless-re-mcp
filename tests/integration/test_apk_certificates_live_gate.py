"""apk.certificates live gate: subject/issuer come back as readable DNs.

androguard's ``APK.get_certificates()`` returns ``asn1crypto.x509.Certificate``
objects whose ``subject`` and ``issuer`` are ``asn1crypto.x509.Name`` instances.
``str()`` on one of those yields the object repr --
``<asn1crypto.x509.Name 0x... b'0\\x81...'>``, a memory address and the raw DER
bytes -- not a distinguished name a caller can read. The client used to emit
exactly that ``str()``; the fix renders ``name.human_friendly`` instead. Every
existing apk.certificates test used a fake cert whose ``subject`` was a plain
string, so ``str()`` looked fine and the divergence only showed against real
asn1crypto objects -- the same mock-vs-reality gap the other Android gates close.

The fixture ``fixtures/android/signed_sample.apk`` is a real, v1 (JAR) signed
APK built once and committed (signing needs the JDK tools). It was produced by
taking a binary-AXML sample APK and signing it with::

    keytool -genkeypair -keystore gate.keystore -alias gatekey -keyalg RSA \\
        -dname "CN=Gate Signer, O=Headless RE MCP, C=US" ...
    jarsigner -keystore gate.keystore -sigalg SHA256withRSA \\
        -digestalg SHA-256 signed_sample.apk gatekey

so the signer's distinguished name is known. The gate parses it through real
androguard and pins that the recorded subject/issuer contain that DN in
human-readable form and never the asn1crypto repr, and that the serial comes
back in hexadecimal (``31036c42597f680c``) -- the spelling keytool, apksigner
and openssl print -- not the decimal of asn1crypto's raw int
(``3531785565013764108``), which no signer tool would ever match. It depends
only on androguard -- no Android SDK, no signing tools at test time.

Skip != pass: the gate skips with a reason when androguard is absent and runs
for real when present. CI installs it, so a skip there is a real regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "signed_sample.apk"

_CN = "Gate Signer"
_ORG = "Headless RE MCP"


def _quiet_androguard() -> None:
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - quieting logs is best-effort
        pass


@pytest.mark.integration
def test_certificate_subject_and_issuer_are_human_readable() -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — certificates Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    _quiet_androguard()

    payload = client.certificates(_FIXTURE)

    # The v1 signature the fixture carries is seen, and its .RSA block is listed.
    assert payload["v1_signed"] is True
    assert any(name.endswith(".RSA") for name in payload["signature_files"])
    assert payload["certificates"], "no certificates parsed from a signed APK"

    cert = payload["certificates"][0]
    subject = cert["subject"]
    issuer = cert["issuer"]

    # The known signer DN survives as readable text ...
    assert _CN in subject
    assert _ORG in subject
    assert _CN in issuer  # self-signed: issuer == subject
    # ... rendered as a friendly distinguished name, not the asn1crypto repr.
    assert "Common Name" in subject
    assert "asn1crypto" not in subject
    assert "asn1crypto" not in issuer
    assert not subject.startswith("<")

    # The committed fixture's serial, in the hex spelling keytool/apksigner/
    # openssl print -- never the decimal 3531785565013764108 the raw int gives.
    assert cert["serial"] == "31036c42597f680c"
    # The fingerprint stayed populated.
    assert cert["sha256"]
