"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _hex_serial
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
        # asn1crypto hands the serial back as a Python int; big serials are the
        # norm, so use one that renders differently in decimal and hex.
        self.serial_number = 0xA0000 + index
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
    # The serial is rendered as 0x-hex (like the sha256 beside it and every cert
    # tool), not the old decimal str(int). Index 0 -> 0xa0000, not "655360".
    first = payload["certificates"][0]
    assert first["serial"] == "0xa0000"
    assert first["serial"] != str(0xA0000)
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc
    assert "hex" in doc


def test_hex_serial_renders_ints_as_hex_and_passes_other_types_through() -> None:
    """asn1crypto returns an int; str(int) was decimal, which no cert tool prints."""
    assert _hex_serial(773513251999227375) == "0xabc123456789def"
    assert _hex_serial(0) == "0x0"
    # A negative (should never happen for X.509) keeps its sign rather than
    # wrapping to a huge unsigned value.
    assert _hex_serial(-255) == "-0xff"
    # A bool is not a serial; do not render it as 0x1.
    assert _hex_serial(True) == "True"
    # A missing/blank serial stays empty, not "0x0".
    assert _hex_serial("") == ""
    assert _hex_serial(None) == ""
