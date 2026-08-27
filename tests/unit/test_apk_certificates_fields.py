"""apk.certificates descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, _hex_serial, _readable_name
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


class _FriendlyName:
    """Stand-in for asn1crypto.x509.Name.

    ``str()`` yields the useless object repr the bug shipped, while the readable
    distinguished name lives on ``.human_friendly`` -- exactly the shape the fix
    has to reach for.
    """

    def __init__(self, friendly: str) -> None:
        self._friendly = friendly

    @property
    def human_friendly(self) -> str:
        return self._friendly

    def __str__(self) -> str:
        return "<asn1crypto.x509.Name 0x7f00 b'0\\x81...'>"


class _FriendlyCert:
    def __init__(self) -> None:
        self.subject = _FriendlyName("Common Name: Example Signer, Organization: Acme Co")
        self.issuer = _FriendlyName("Common Name: Example CA, Country: US")
        self.serial_number = 12345
        self.sha256_fingerprint = "ab"


class _FriendlyApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_FriendlyCert]:
        return [_FriendlyCert()]


def test_readable_name_prefers_human_friendly_over_object_repr() -> None:
    name = _FriendlyName("Common Name: Acme, Organization: Co, Country: US")
    rendered = _readable_name(name)
    assert rendered == "Common Name: Acme, Organization: Co, Country: US"
    # The object repr (memory address, raw DER) must never leak through.
    assert "asn1crypto" not in rendered


def test_readable_name_falls_back_to_str_and_handles_none() -> None:
    # A plain string (older/other cert shape) is returned as-is, not dropped.
    assert _readable_name("CN=plain") == "CN=plain"
    assert _readable_name(None) == ""


def test_certificates_render_subject_and_issuer_as_readable_dns() -> None:
    """subject/issuer come back as readable DNs, never the <asn1crypto...> repr."""
    client = ApkClient()
    client._apk = lambda _path: _FriendlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["subject"] == "Common Name: Example Signer, Organization: Acme Co"
    assert cert["issuer"] == "Common Name: Example CA, Country: US"
    assert "asn1crypto" not in cert["subject"]
    assert "asn1crypto" not in cert["issuer"]


def test_hex_serial_renders_ints_as_hex_like_keytool() -> None:
    """The serial must match what keytool/apksigner/openssl print: hex, not decimal.

    asn1crypto stores the serial as an int; ``str(int)`` gave a decimal that
    never lines up with any signer tool's output. 12345 must read ``3039``.
    """
    assert _hex_serial(12345) == "3039"
    assert _hex_serial(3531785565013764108) == "31036c42597f680c"
    # Non-int shapes (older/other certificate objects) pass through unchanged.
    assert _hex_serial("already-a-string") == "already-a-string"
    assert _hex_serial(None) == ""
    # bool is an int subclass but never a serial; it must not become "1"/"0".
    assert _hex_serial(True) == "True"


def test_certificates_render_serial_in_hex() -> None:
    """apk.certificates emits the serial in hex and the docstring says so."""
    client = ApkClient()
    client._apk = lambda _path: _FriendlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["serial"] == "3039"  # 12345 decimal -> hex, never "12345"
    doc = _tool_docstring("apk.certificates")
    assert "hexadecimal" in doc


def test_readable_name_on_a_real_asn1crypto_name() -> None:
    """Pin the fix against the exact type androguard returns, not just a fake.

    Builds a real X.509 Name with cryptography, reloads it through asn1crypto
    (what ``APK.get_certificates()`` hands back), and proves ``_readable_name``
    yields the human-friendly DN rather than ``str(Name)``'s object repr.
    """
    cryptography = pytest.importorskip("cryptography")
    asn1_x509 = pytest.importorskip("asn1crypto.x509")
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Example Signer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme Co"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    real_name = asn1_x509.Certificate.load(der).subject

    rendered = _readable_name(real_name)
    assert "Example Signer" in rendered
    assert "asn1crypto" not in rendered
    assert rendered != str(real_name)
    assert cryptography is not None
