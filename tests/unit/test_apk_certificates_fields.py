"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

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
        self.sha1_fingerprint = f"S1:{index}"
        self.sha256_fingerprint = "aa"


class _FakeApk:
    def get_signature_names(self) -> list[str]:
        return [f"META-INF/C{index}.RSA" for index in range(40)]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(index) for index in range(40)]

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True

    def is_signed_v31(self) -> bool:
        return False


class _V2OnlyApk:
    """A modern APK that dropped the v1 JAR signature for scheme v2/v3."""

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True

    def is_signed_v31(self) -> bool:
        return False


class _BadCert:
    @property
    def subject(self) -> str:
        # A malformed/hostile cert asn1crypto cannot serialize: accessing a
        # field raises something other than AttributeError, so it propagates
        # past getattr's default and trips the append.
        raise ValueError("malformed certificate")


class _MixedCertApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[object]:
        return [_Cert(0), _BadCert(), _Cert(1)]


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
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is True
    assert payload["v31_signed"] is False
    assert payload["signed"] is True
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc
    assert "v2_signed" in doc
    assert "sha1" in doc


def test_apk_certificates_reports_v2_v3_when_v1_is_absent() -> None:
    """A v2/v3-only APK must not read as unsigned just because v1 is gone.

    v1_signed is False (no JAR signature files), but v2_signed/v3_signed and the
    combined signed are True, so the modern APK is distinguished from a genuinely
    unsigned one.
    """
    client = ApkClient()
    client._apk = lambda _path: _V2OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["signature_files"] == []
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is True
    assert payload["v31_signed"] is False
    assert payload["signed"] is True


def test_apk_certificates_reports_both_sha1_and_sha256_fingerprints() -> None:
    """Each cert carries sha1 (the threat-intel pivot) alongside sha256.

    A signer-identification tool that only gave sha256 could not be
    cross-referenced against VirusTotal/Koodous/AndroZoo, which index Android
    signing certs by SHA-1. Both must be present and populated.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    first = payload["certificates"][0]
    assert first["sha1"] == "S1:0"
    assert first["sha256"] == "aa"
    doc = _tool_docstring("apk.certificates")
    assert "sha1" in doc


def test_apk_certificates_counts_unparseable_certs_instead_of_dropping_them() -> None:
    """A cert that fails to serialize is counted, not silently dropped.

    get_certificates yields three certs but the middle one raises while being
    read. The two good certs must still come back, and cert_parse_errors must
    say one signer went missing -- otherwise the signer list reads as complete
    when a (often adversarial) cert vanished.
    """
    client = ApkClient()
    client._apk = lambda _path: _MixedCertApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert len(payload["certificates"]) == 2
    assert payload["cert_parse_errors"] == 1
    doc = _tool_docstring("apk.certificates")
    assert "cert_parse_errors" in doc


def test_apk_certificates_omits_the_error_field_when_every_cert_parses() -> None:
    """The signal is additive: a clean parse never carries cert_parse_errors."""
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert "cert_parse_errors" not in payload
