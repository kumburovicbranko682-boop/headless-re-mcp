"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
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
        self.sha256_fingerprint = "aa"


class _FakeApk:
    def get_signature_names(self) -> list[str]:
        return [f"META-INF/C{index}.RSA" for index in range(40)]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(index) for index in range(40)]


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
    # An APK with no v2/v3 predicates on the object reports those schemes false
    # rather than raising -- a v1-only signer is still fully described.
    assert payload["v2_signed"] is False
    assert payload["v3_signed"] is False
    assert payload["signed"] is True
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc


class _PubKey:
    def __init__(self, algorithm: str, bit_size: int) -> None:
        self.algorithm = algorithm
        self.bit_size = bit_size


class _RichCert:
    subject = "CN=app"
    issuer = "CN=ca"
    serial_number = 7
    sha1_fingerprint = "11:22"
    sha256_fingerprint = "aa:bb"
    hash_algo = "sha256"
    signature_algo = "rsassa_pkcs1v15"
    public_key = _PubKey("rsa", 2048)
    not_valid_before = datetime(2020, 1, 1, tzinfo=UTC)
    not_valid_after = datetime(2045, 1, 1, tzinfo=UTC)


class _SignedApk:
    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_RichCert]:
        return [_RichCert()]

    def is_signed_v1(self) -> bool:
        return False

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True


def test_apk_certificates_reports_scheme_versions_and_cert_detail() -> None:
    """A v2/v3-only app was signed, and the cert's fingerprint/validity matter.

    Measured: no META-INF files yet v2_signed/v3_signed True and signed True
    (so a v1-only heuristic no longer reads it as unsigned), and the certificate
    carries sha1, hash_algo, and ISO 8601 validity dates for triage.
    """
    client = ApkClient()
    client._apk = lambda _path: _SignedApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is True
    assert payload["signed"] is True
    (cert,) = payload["certificates"]
    assert cert["sha1"] == "11:22"
    assert cert["sha256"] == "aa:bb"
    assert cert["hash_algo"] == "sha256"
    assert cert["signature_algo"] == "rsassa_pkcs1v15"
    assert cert["key_algo"] == "rsa"
    assert cert["key_size"] == 2048
    assert cert["not_before"].startswith("2020-01-01")
    assert cert["not_after"].startswith("2045-01-01")
    doc = _tool_docstring("apk.certificates")
    assert "v2_signed" in doc
    assert "sha1" in doc
    assert "key_size" in doc


class _WeakCert:
    subject = "CN=weak"
    issuer = "CN=weak"
    serial_number = 1
    sha1_fingerprint = "de:ad"
    sha256_fingerprint = "be:ef"
    hash_algo = "sha1"
    signature_algo = "rsassa_pkcs1v15"
    public_key = _PubKey("rsa", 1024)


class _NoKeyApk:
    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[object]:
        # One weak signer plus a bare cert whose public_key access raises, to
        # prove the key helper degrades without dropping the certificate.
        class _Broken:
            subject = "CN=broken"
            issuer = "CN=broken"
            serial_number = 2

            @property
            def public_key(self) -> object:
                raise RuntimeError("unreadable key")

        return [_WeakCert(), _Broken()]


def test_apk_certificates_surfaces_weak_signing_and_degrades_on_a_bad_key() -> None:
    """A 1024-bit RSA / SHA1 signer is the weak-signing tell; a bad key never drops a cert."""
    client = ApkClient()
    client._apk = lambda _path: _NoKeyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    weak, broken = payload["certificates"]
    assert weak["key_algo"] == "rsa"
    assert weak["key_size"] == 1024
    assert weak["hash_algo"] == "sha1"
    # The cert whose key raised still appears, with an empty/None key rather
    # than being dropped from the list.
    assert broken["subject"] == "CN=broken"
    assert broken["key_algo"] == ""
    assert broken["key_size"] is None
