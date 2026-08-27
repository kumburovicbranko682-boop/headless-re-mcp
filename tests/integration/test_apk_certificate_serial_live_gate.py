"""apk.certificates live gate: the cert serial is hex, matching the real cert.

androguard hands a certificate's serial back as a Python ``int``. The backend
rendered it with ``str(int)`` -- decimal -- while the ``sha256`` fingerprint
beside it is hex, and openssl, keytool, apksigner and threat-intel feeds all
print certificate serials in hex. An analyst matching a published serial (always
hex) against a decimal string silently fails. ``apk.certificates`` now emits a
``0x``-prefixed hex serial.

Every unit test drives a hand-written cert object, so only real androguard proves
that its own ``get_certificates()`` still yields an integer serial the backend
renders as hex. The fixture ``fixtures/apk/cert_sample.apk`` is a minimal
v1-signed APK (rebuildable from ``cert_sample_gen.py`` beside it) whose
self-signed certificate carries a known serial ``0x0abc123456789def``.

Skip != pass: the gate skips with a reason only when androguard is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, _hex_serial

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "apk" / "cert_sample.apk"

# The serial baked into the fixture by cert_sample_gen.py.
_EXPECTED_SERIAL_HEX = "0xabc123456789def"


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
        from androguard.core.apk import APK  # noqa: F401
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_apk_certificate_serial_is_hex_matching_the_real_cert() -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — cert-serial Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    client = ApkClient()
    payload = client.certificates(_FIXTURE)
    certs = payload["certificates"]
    assert certs, "androguard reported no certificates; fixture/parser changed"

    cert = certs[0]
    serial = cert["serial"]

    # The fix: hex, not decimal. It must parse back to the same integer androguard
    # itself reports, and equal the known serial the fixture was signed with.
    assert isinstance(serial, str)
    assert serial.startswith("0x"), serial
    assert serial == _EXPECTED_SERIAL_HEX, serial
    assert int(serial, 16) == 0x0ABC123456789DEF

    # Guard the guard: read androguard's own integer serial and confirm the
    # backend rendered exactly that, and that it is genuinely not the decimal
    # form the code used to emit.
    from androguard.core.apk import APK

    raw_certs = APK(str(_FIXTURE)).get_certificates()
    assert raw_certs, "androguard get_certificates() returned nothing"
    raw_serial = int(raw_certs[0].serial_number)
    assert serial == _hex_serial(raw_serial)
    assert serial != str(raw_serial)  # the decimal form is what we moved away from

    # The sha256 fingerprint is hex too, so the two identifiers now agree in radix.
    assert cert["sha256"]
