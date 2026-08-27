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


class _V2OnlyApk:
    """A modern APK: no v1 JAR signature, signed under scheme v2 only."""

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return False


class _OldAndroguardApk:
    """androguard too old to answer the scheme question at all."""

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]


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
    assert "v2_signed" in doc
    assert "v3_signed" in doc


def test_a_v2_only_signed_apk_is_not_read_as_unsigned() -> None:
    """v1_signed False but v2_signed True: signed under scheme v2, not unsigned."""
    client = ApkClient()
    client._apk = lambda _path: _V2OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is False
    # It really is signed -- one certificate came back despite no v1 JAR files.
    assert payload["signature_files"] == []
    assert len(payload["certificates"]) == 1


def test_scheme_flags_are_none_when_androguard_cannot_tell() -> None:
    """Older androguard lacks the probes; unknown must not masquerade as False."""
    client = ApkClient()
    client._apk = lambda _path: _OldAndroguardApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is True
    assert payload["v2_signed"] is None
    assert payload["v3_signed"] is None
