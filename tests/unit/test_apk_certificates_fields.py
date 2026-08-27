"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
import datetime
import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Cert:
    def __init__(self, index: int) -> None:
        self.subject = f"CN={index}"
        self.issuer = "CN=i"
        self.serial_number = index
        self.sha256_fingerprint = "aa"


class _FakeApk:
    def get_signature_names(self) -> list[str]:
        return [f"META-INF/C{index}.RSA" for index in range(40)]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(index) for index in range(40)]


class _V2OnlyApk:
    """A modern APK signed only with schemes v2/v3, carrying no v1 JAR files."""

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]

    def is_signed(self) -> bool:
        return True

    def is_signed_v1(self) -> bool:
        return False

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True


class _RaisingSchemeApk:
    """v1 present, but the v2/v3 predicates blow up parsing the signing block."""

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]

    def is_signed(self) -> bool:
        return True

    def is_signed_v2(self) -> bool:
        raise ValueError("malformed signing block")

    def is_signed_v3(self) -> bool:
        raise ValueError("malformed signing block")


def test_apk_certificates_names_signature_files_not_certs() -> None:
    """The catalog never named the payload.

    Measured: 40 certificates, cap 32 -> 32 certificates, 32 signature_files,
    has_more True, v1_signed True. certs/signatures/v1_signature_files are
    absent. Looking for certs after a successful call reads as unsigned, and
    a full 32 list with no has_more reads as every signer.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert "certs" not in payload
    assert "signatures" not in payload
    assert "v1_signature_files" not in payload
    assert len(payload["certificates"]) == 32
    assert len(payload["signature_files"]) == 32
    assert payload["has_more"] is True
    assert payload["v1_signed"] is True
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc


def test_apk_certificates_reports_v2_v3_only_signing() -> None:
    """A v2/v3-only APK carries no v1 JAR files but is still signed.

    Reading v1_signed False alone would call this unsigned; the scheme flags
    keep that from happening. is_signed True with v1_signed False is exactly the
    modern APK the field set exists to describe.
    """
    client = ApkClient()
    client._apk = lambda _path: _V2OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is True
    assert payload["signed"] is True
    assert len(payload["certificates"]) == 1


def test_apk_certificates_scheme_flag_none_when_predicate_raises() -> None:
    """A raising predicate reads as null (unknown), never as False (not signed).

    Collapsing a parse failure to False would tell an analyst the APK lacks v2/v3
    protection when the truth is the tool could not tell; null keeps the two
    apart so v1-only-looking output is trusted only when it is actually known.
    """
    client = ApkClient()
    client._apk = lambda _path: _RaisingSchemeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is True
    assert payload["v2_signed"] is None
    assert payload["v3_signed"] is None
    assert payload["signed"] is True


def test_apk_certificates_scheme_flag_none_when_predicate_absent() -> None:
    """An older androguard without the predicate reports null, not a crash.

    The original fake apk defines none of the is_signed* methods, so every new
    flag must degrade to null while the established fields keep their values.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is True
    assert payload["v2_signed"] is None
    assert payload["v3_signed"] is None
    assert payload["signed"] is None


def test_apk_certificates_validity_none_when_absent() -> None:
    """A cert shape without validity attributes reports null, never a crash.

    The _Cert stub defines no not_valid_before/after, so both bounds must
    degrade to null while json.dumps still serializes the whole payload.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["not_before"] is None
    assert cert["not_after"] is None
    json.dumps(payload)


def test_apk_certificates_reports_validity_from_real_cert() -> None:
    """Real asn1crypto certs must render validity as ISO-8601 strings.

    The whole reason for _cert_datetime is that androguard hands back asn1crypto
    x509 certs whose not_valid_before/after are tz-aware datetimes the JSON
    serializer cannot encode. Build a genuine self-signed cert, load it through
    asn1crypto exactly as androguard would, and assert the bounds come back as
    the expected ISO strings and that json.dumps does not choke on a datetime.
    """
    pytest.importorskip("cryptography")
    from asn1crypto import x509 as ax
    from cryptography import x509 as cx
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, "HeadlessRE Gate")])
    not_before = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    not_after = datetime.datetime(2047, 1, 1, tzinfo=datetime.UTC)
    built = (
        cx.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1234567890)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    asn1_cert = ax.Certificate.load(built.public_bytes(serialization.Encoding.DER))

    class _RealCertApk:
        def get_signature_names(self) -> list[str]:
            return ["META-INF/CERT.RSA"]

        def get_certificates(self) -> list[object]:
            return [asn1_cert]

    client = ApkClient()
    client._apk = lambda _path: _RealCertApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    json.dumps(payload)
    cert = payload["certificates"][0]
    assert cert["not_before"] == "2020-01-01T00:00:00+00:00"
    assert cert["not_after"] == "2047-01-01T00:00:00+00:00"
    assert "HeadlessRE Gate" in cert["subject"]
