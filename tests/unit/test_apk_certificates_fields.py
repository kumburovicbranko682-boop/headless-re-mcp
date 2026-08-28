"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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
    # This fixture has v1 files and no v2/v3 methods, so the scheme flags read
    # False and signed collapses to the v1 evidence -- the flags are additive
    # and never fabricate a scheme this APK did not carry.
    assert payload["v2_signed"] is False
    assert payload["v3_signed"] is False
    assert payload["signed"] is True
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc
    assert "v2_signed" in doc
    assert "v3_signed" in doc
    assert "signed" in doc


class _V2V3OnlyApk:
    """A modern APK signed only with APK Signature Scheme v2/v3.

    apksigner can disable v1, and Android has not required it since API 24, so a
    contemporary release leaves no META-INF signature files at all: get_signature_names
    returns nothing, yet the app is validly signed and get_certificates() still returns
    its v2/v3 signers. This is the shape the scheme flags exist to report honestly.
    """

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True


def test_apk_certificates_reports_a_v2_v3_only_apk_as_signed() -> None:
    """A v2/v3-only APK must read as signed, not as an unsigned one with certs.

    Before the scheme flags this exact shape -- no signature_files, v1_signed
    False -- was the whole failure: an agent scanning v1_signed saw False and an
    empty signature_files and concluded the APK was unsigned, even though its v2/v3
    signers sat right there in certificates. signed now answers the real question.
    """
    client = ApkClient()
    client._apk = lambda _path: _V2V3OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is True
    assert payload["signed"] is True
    assert len(payload["certificates"]) == 1


class _UnparsableCertApk:
    """A parsed APK whose signature block androguard cannot decode.

    get_signature_names lists the META-INF entries fine; the raise is deferred
    to get_certificates(), which is where androguard fails on a malformed or
    unusual PKCS7/X.509 block -- the hostile-APK case this line targets.
    """

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[object]:
        raise ValueError("asn1crypto: invalid certificate structure")


def test_apk_certificates_maps_a_signature_parse_failure_to_backend_error() -> None:
    """A certificate that will not parse is a backend outcome, not an incident.

    Unwrapped, get_certificates() raising reached the service's BaseException
    arm as internal_error plus a logged incident -- a malformed signer read as
    a fault in this process.
    """
    client = ApkClient()
    client._apk = lambda _path: _UnparsableCertApk()  # type: ignore[method-assign]

    with pytest.raises(ApkError) as caught:
        client.certificates(Path("dummy.apk"))

    assert caught.value.code == "backend_error"
    assert "failed to parse certificates" in caught.value.message
