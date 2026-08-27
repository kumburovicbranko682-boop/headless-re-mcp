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

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True

    def is_signed_v31(self) -> bool:
        return False


class _V2OnlyApk:
    """A modern APK signed only with scheme v2/v3, no v1 JAR signature."""

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
    assert "v3_signed" in doc


def test_apk_certificates_reports_v2_v3_when_v1_is_absent() -> None:
    """A v2/v3-only APK must not read as unsigned.

    get_signature_names is empty (no META-INF JAR signature), so v1_signed is
    False; without the scheme flags that alone read as an unsigned app. signed
    stays True because v2/v3 are in force.
    """
    client = ApkClient()
    client._apk = lambda _path: _V2OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["v2_signed"] is True
    assert payload["v3_signed"] is True
    assert payload["signed"] is True
