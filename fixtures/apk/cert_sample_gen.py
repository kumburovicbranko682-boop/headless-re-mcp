"""Generate ``cert_sample.apk`` for the apk.certificates serial-hex live gate.

A minimal v1 (JAR) signed APK: a self-signed RSA certificate with a **known,
non-trivial serial** wraps a detached PKCS#7 over ``CERT.SF``, exactly the
META-INF layout androguard's ``APK.get_certificates()`` reads. The gate does not
pin the RSA key or the fingerprint (both vary per run); it only needs a real
certificate whose integer serial androguard reports, so this stays reproducible.

The serial is chosen with a high bit set and a leading zero nibble so the hex
rendering is unmistakably not the decimal ``str(int)`` the backend used to emit.

Rebuild (needs the ``cryptography`` package):
    python fixtures/apk/cert_sample_gen.py fixtures/apk/cert_sample.apk
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import sys
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

# Known serial: 0x0abc123456789def == 773513251999227375. Decimal and hex look
# nothing alike, which is the whole point of the gate.
SERIAL = 0x0ABC123456789DEF


def build(out_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "re-mcp-cert-gate")])
    not_before = datetime.datetime(2024, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(SERIAL)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )

    manifest = b"Manifest-Version: 1.0\r\n\r\n"
    digest = base64.b64encode(hashlib.sha256(manifest).digest()).decode()
    cert_sf = (
        f"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: {digest}\r\n\r\n"
    ).encode()
    signature = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(cert_sf)
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("META-INF/MANIFEST.MF", manifest)
        archive.writestr("META-INF/CERT.SF", cert_sf)
        archive.writestr("META-INF/CERT.RSA", signature)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("cert_sample.apk")
    build(target)
    print(f"wrote {target} with serial {SERIAL:#x}")
