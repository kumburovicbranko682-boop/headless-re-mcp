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


class _ManyFilesOneCertApk:
    """A pathological v1 APK: many signature files, a single certificate."""

    def get_signature_names(self) -> list[str]:
        return [f"META-INF/C{index}.RSA" for index in range(40)]

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
    # Both lists overflowed the cap here, so both flags are set.
    assert payload["signature_files_truncated"] is True
    assert payload["certificates_truncated"] is True
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc


def test_apk_certificates_flags_the_truncated_list_independently() -> None:
    """The two flags move independently: files can be short while certs are whole.

    A single combined has_more said only "something is short". An APK with 40
    signature files but one certificate now reports signature_files_truncated
    while certificates_truncated stays False, so a signer audit reading the
    lone certificate knows it is the whole set, not a truncated one.
    """
    client = ApkClient()
    client._apk = lambda _path: _ManyFilesOneCertApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))

    assert payload["has_more"] is True
    assert payload["signature_files_truncated"] is True
    assert payload["certificates_truncated"] is False
    assert len(payload["certificates"]) == 1
    assert payload["has_more"] == (
        payload["signature_files_truncated"] or payload["certificates_truncated"]
    )
    doc = _tool_docstring("apk.certificates")
    assert "signature_files_truncated" in doc
    assert "certificates_truncated" in doc
