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
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc


class _NameLikeAsn1:
    """Stands in for ``asn1crypto.x509.Name``: ``str()`` is an object repr
    carrying a memory address and raw DER; the readable DN is on
    ``human_friendly``."""

    def __init__(self, human: str) -> None:
        self.human_friendly = human

    def __str__(self) -> str:  # what the old code emitted for a real cert
        return "<asn1crypto.x509.Name 140637888198176 b'0b1\\x0b0\\t\\x06'>"


class _NamedCert:
    def __init__(self) -> None:
        self.subject = _NameLikeAsn1("Common Name: Fixture Test, Organization: Example")
        self.issuer = _NameLikeAsn1("Common Name: Issuer CA")
        self.serial_number = 296028018442173800
        self.sha256_fingerprint = "30 79 D7 51"


class _SignedFakeApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/FIXTUREK.RSA"]

    def get_certificates(self) -> list[_NamedCert]:
        return [_NamedCert()]


def test_apk_certificate_subject_is_readable_not_object_repr() -> None:
    """subject/issuer must be the human-friendly DN, never the Name object repr.

    ``APK.get_certificates()`` returns ``asn1crypto.x509.Certificate`` whose
    ``subject`` is an ``x509.Name``; ``str()`` on one is
    ``<asn1crypto.x509.Name 0x.. b'..'>`` -- a live process memory address plus
    raw DER, non-deterministic and useless to the caller. Only a *signed* APK
    reaches this path, and every prior cert test used plain-string stand-ins, so
    the repr leak went unseen until a real signature was parsed (verified live
    against a jarsigner-signed APK on androguard 4.1.4). Rendering
    ``.human_friendly`` fixes it; this guards the render without needing
    androguard or a signed fixture on disk.
    """
    client = ApkClient()
    client._apk = lambda _path: _SignedFakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["subject"] == "Common Name: Fixture Test, Organization: Example"
    assert cert["issuer"] == "Common Name: Issuer CA"
    # the exact symptoms of the object-repr leak must be gone
    assert "asn1crypto" not in cert["subject"]
    assert "b'" not in cert["subject"]
    assert cert["serial"] == "296028018442173800"
    assert cert["sha256"] == "30 79 D7 51"
