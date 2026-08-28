"""PE signer-identity gate: a real Authenticode signer signs, the reader names it.

A session over a signed PE now answers *who* signed it: ``signers`` carries the
SHA-256 of each signing certificate's DER, resolved by matching every
SignerInfo's issuer+serial against the certificates embedded in the PKCS#7
SignedData, and ``certificate_count`` counts the chain that came along. That
DER walk and its unit fixtures are both ours, so nothing proved it reads what a
real code-signing implementation writes. osslsigncode is exactly that -- an
independent, production Authenticode signer and verifier that runs on Linux,
the Windows analogue of the rcodesign referee in the Mach-O codesign gate.

The gate builds a signing identity with openssl, signs the committed managed
fixture with osslsigncode, has osslsigncode verify its own signature (so the
blob under test is a structurally valid signature, not a lucky parse), and
then requires the reader to recover, from inside the PE alone, the SHA-256 of
the very certificate file the signer used -- and osslsigncode's printed signer
serial must be the serial of that same certificate, closing the loop on the
issuer+serial matching. The chained arm embeds a CA alongside the leaf: the
census must count both and name only the leaf as the signer -- the exact
discrimination the APK gate gets from apksigner --print-certs.

openssl ships with the runner; osslsigncode comes from the workflow's apt
step. skip != pass: each test skips only when its own referee is missing.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"

_SERIAL_RE = re.compile(r"^\s*Serial\s*:\s*([0-9A-Fa-f]+)\s*$", re.M)


def _cert_der(pem: Path) -> bytes:
    """The certificate's DER bytes -- what the census hashes -- from its PEM."""
    body = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        pem.read_text(),
        re.S,
    )
    assert body is not None, pem
    return base64.b64decode(body.group(1))


def _make_self_signed(openssl: str, tmp_path: Path, name: str, cn: str) -> tuple[Path, Path]:
    key = tmp_path / f"{name}.key"
    cert = tmp_path / f"{name}.pem"
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return key, cert


def _osslsigncode_sign(
    osslsigncode: str, tmp_path: Path, key: Path, certs: Path, extra: list[str]
) -> Path:
    unsigned = tmp_path / "unsigned.exe"
    unsigned.write_bytes(_FIXTURE.read_bytes())
    signed = tmp_path / "signed.exe"
    subprocess.run(
        [
            osslsigncode, "sign", "-certs", str(certs), "-key", str(key),
            "-h", "sha256", *extra, "-in", str(unsigned), "-out", str(signed),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return signed


def _osslsigncode_verify(osslsigncode: str, signed: Path, cafile: Path) -> str:
    result = subprocess.run(
        [osslsigncode, "verify", "-CAfile", str(cafile), "-in", str(signed)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "Signature verification: ok" in result.stdout, result.stdout + result.stderr
    return result.stdout


def _session_authenticode(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        info = created.data["session"]["metadata"]["pe"]["authenticode"]
        assert isinstance(info, dict)
        return info
    finally:
        service.close_all()


@pytest.mark.integration
def test_a_real_signature_names_the_signing_certificate(tmp_path: Path) -> None:
    osslsigncode = shutil.which("osslsigncode")
    if osslsigncode is None:
        pytest.skip("osslsigncode not installed — PE signer gate not run (skip != pass)")
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl not installed — identity builder missing (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")

    key, cert = _make_self_signed(openssl, tmp_path, "signer", "Probe Signer")
    signed = _osslsigncode_sign(osslsigncode, tmp_path, key, cert, [])
    # osslsigncode accepts its own signature: the blob the reader is about to
    # walk is a structurally valid Authenticode signature, not a lucky parse.
    report = _osslsigncode_verify(osslsigncode, signed, cert)

    info = _session_authenticode(signed)
    assert info["signed"] is True
    assert info["authenticode"] is True
    assert info["within_file"] is True
    # The reader recovered, from inside the PE alone, the SHA-256 of the very
    # certificate file the signer used -- the pinnable "who".
    expected = hashlib.sha256(_cert_der(cert)).hexdigest()
    assert info["signers"] == [{"certificate_sha256": expected}]
    assert info["certificate_count"] == 1
    # And the signer osslsigncode itself prints is that same certificate: its
    # reported serial equals the serial openssl minted into the cert.
    serials = {serial.lower().lstrip("0") for serial in _SERIAL_RE.findall(report)}
    minted = subprocess.run(
        [openssl, "x509", "-in", str(cert), "-serial", "-noout"],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.strip().removeprefix("serial=")
    assert minted.lower().lstrip("0") in serials


@pytest.mark.integration
def test_a_chained_signature_names_the_leaf_not_the_ca(tmp_path: Path) -> None:
    osslsigncode = shutil.which("osslsigncode")
    if osslsigncode is None:
        pytest.skip("osslsigncode not installed — PE signer gate not run (skip != pass)")
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl not installed — identity builder missing (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")

    ca_key, ca_cert = _make_self_signed(openssl, tmp_path, "ca", "Probe CA")
    leaf_key = tmp_path / "leaf.key"
    leaf_csr = tmp_path / "leaf.csr"
    subprocess.run(
        [
            openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(leaf_key), "-out", str(leaf_csr), "-subj", "/CN=Probe Leaf",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    leaf_cert = tmp_path / "leaf.pem"
    subprocess.run(
        [
            openssl, "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(leaf_cert), "-days", "1",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )

    signed = _osslsigncode_sign(
        osslsigncode, tmp_path, leaf_key, leaf_cert, ["-ac", str(ca_cert)]
    )
    _osslsigncode_verify(osslsigncode, signed, ca_cert)

    info = _session_authenticode(signed)
    leaf_digest = hashlib.sha256(_cert_der(leaf_cert)).hexdigest()
    ca_digest = hashlib.sha256(_cert_der(ca_cert)).hexdigest()
    # Both certificates ride in the SignedData; only the leaf signed. The
    # issuer+serial match must pick it -- never the CA, never both.
    assert info["certificate_count"] == 2
    assert info["signers"] == [{"certificate_sha256": leaf_digest}]
    assert ca_digest != leaf_digest


@pytest.mark.integration
def test_the_unsigned_fixture_claims_no_identity() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    info = _session_authenticode(_FIXTURE)
    assert info == {"signed": False}
