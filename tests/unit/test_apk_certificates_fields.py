"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _dn_text
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


class _Asn1Name:
    """Mimics asn1crypto.x509.Name: str() is a repr with a live object id.

    That default repr -- ``<asn1crypto.x509.Name 140300673974496 b'...'>`` --
    is what androguard actually hands back, so a str() of it leaked a memory
    address into the payload (unreadable and different every run). The client
    must reach for human_friendly instead.
    """

    def __init__(self, human: str, native: dict[str, str]) -> None:
        self.human_friendly = human
        self.native = native

    def __str__(self) -> str:
        return f"<asn1crypto.x509.Name {id(self)} b'0710\\x0b0\\t'>"


class _Asn1NameNoHuman:
    """A Name-like object without human_friendly: fall back to the native map."""

    def __init__(self, native: dict[str, str]) -> None:
        self.native = native

    def __str__(self) -> str:
        return f"<asn1crypto.x509.Name {id(self)} b'raw'>"


class _RealisticCert:
    def __init__(self) -> None:
        self.subject = _Asn1Name(
            "Common Name: Android Debug, Organization: Android, Country: US",
            {"common_name": "Android Debug"},
        )
        self.issuer = _Asn1Name(
            "Common Name: Android Debug, Organization: Android, Country: US",
            {"common_name": "Android Debug"},
        )
        self.serial_number = 363361081637669504
        self.sha256_fingerprint = "73 96 E5 36"


class _RealisticApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/ANDROIDD.RSA"]

    def get_certificates(self) -> list[object]:
        return [_RealisticCert()]


def test_certificate_subject_is_a_readable_dn_not_an_object_repr() -> None:
    """subject/issuer come back human-readable, deterministic, repr-free.

    The old code did str(cert.subject) on an asn1crypto Name, so the payload
    carried "<asn1crypto.x509.Name 140300673974496 b'...'>" -- unreadable and a
    fresh memory address each run.
    """
    client = ApkClient()
    client._apk = lambda _path: _RealisticApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]

    assert cert["subject"] == "Common Name: Android Debug, Organization: Android, Country: US"
    assert cert["issuer"] == cert["subject"]
    assert "asn1crypto" not in cert["subject"]
    assert "0x" not in cert["subject"]
    # No bare digits run that would betray a leaked object id / DER dump.
    assert "b'" not in cert["subject"]
    assert cert["serial"] == "363361081637669504"


def test_dn_text_renders_and_never_leaks_an_object_repr() -> None:
    # A plain string (older androguard / a test double) passes through.
    assert _dn_text("CN=Example") == "CN=Example"
    # None and empty become "".
    assert _dn_text(None) == ""
    # human_friendly wins over the repr-y __str__.
    named = _Asn1Name("Common Name: X", {"common_name": "X"})
    assert _dn_text(named) == "Common Name: X"
    # No human_friendly -> parsed native mapping, still no repr.
    from_native = _dn_text(_Asn1NameNoHuman({"common_name": "Y", "country_name": "US"}))
    assert "common_name=Y" in from_native
    assert "asn1crypto" not in from_native


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
