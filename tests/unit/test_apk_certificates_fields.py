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


class _V3OnlyApk:
    """A modern APK signed only with the v3 APK Signature Scheme.

    No META-INF signature files and no v1 certificate objects, exactly what
    ``apksigner --v1-signing-enabled false`` produces for an app targeting a
    recent API level. Its signed-ness lives entirely in ``is_signed_v3``.
    """

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return []

    def is_signed_v2(self) -> bool:
        return False

    def is_signed_v3(self) -> bool:
        return True


class _V31OnlyApk:
    """A key-rotation APK carrying only an APK Signature Scheme v3.1 block.

    Scheme v3.1 (Android 13+) holds the rotated signing key; a package that
    rotates its key with SDK targeting can present a v3.1 block without a v3
    one. Its signed-ness lives entirely in ``is_signed_v31``, and older
    androguard builds without that predicate must still read as "not v3.1"
    rather than raise.
    """

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]

    def is_signed_v2(self) -> bool:
        return False

    def is_signed_v3(self) -> bool:
        return False

    def is_signed_v31(self) -> bool:
        return True


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
    # A build of androguard without the v2/v3/v3.1 predicates must not raise;
    # the scheme flags default to false and the overall flag falls back to v1.
    assert payload["signed_v2"] is False
    assert payload["signed_v3"] is False
    assert payload["signed_v31"] is False
    assert payload["signed"] is True
    doc = _tool_docstring("apk.certificates")
    assert "Answers with certificates" in doc
    assert "signature_files" in doc
    assert "has_more" in doc
    assert "signed" in doc


class _Name:
    """Mimics an asn1crypto x509.Name: str() is an opaque, id-bearing repr."""

    def __init__(self, friendly: str) -> None:
        self.human_friendly = friendly

    def __str__(self) -> str:
        return "<asn1crypto.x509.Name 140081758512496 b'061\\x0b0...raw der...'>"


class _NamedCert:
    def __init__(self) -> None:
        self.subject = _Name("Common Name: Acme Debug, Organization: Acme Corp")
        self.issuer = _Name("Common Name: Acme CA, Organization: Acme Corp")
        self.serial_number = 123456789
        self.sha256_fingerprint = "AA BB CC"


class _NamedApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_NamedCert]:
        return [_NamedCert()]


def test_apk_certificates_render_readable_subject_and_issuer() -> None:
    """subject/issuer must be the human-readable DN, not the Name object repr.

    androguard returns asn1crypto Name objects; str() on one yields
    ``<asn1crypto.x509.Name <id> b'...'>`` -- unreadable, and unstable across runs
    because it embeds the Python object id. The certificate view now renders the
    human_friendly DN so a signer is identifiable and the field is deterministic.
    """
    client = ApkClient()
    client._apk = lambda _path: _NamedApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["subject"] == "Common Name: Acme Debug, Organization: Acme Corp"
    assert cert["issuer"] == "Common Name: Acme CA, Organization: Acme Corp"
    # The opaque object repr (and the object id it carries) must not leak through.
    assert "asn1crypto" not in cert["subject"]
    assert "<" not in cert["subject"] and "<" not in cert["issuer"]
    assert cert["sha256"] == "AA BB CC"


def test_apk_certificates_reports_a_v3_only_apk_as_signed() -> None:
    """A v2/v3-only APK must not read as unsigned.

    v1 JAR signing is optional for apps targeting API 24+, so a package signed
    only with the v3 scheme has no META-INF signature files and no v1 certificate
    objects. Reporting only v1_signed (false here) made a properly signed APK
    look unsigned; the scheme flags and the overall ``signed`` fix that.
    """
    client = ApkClient()
    client._apk = lambda _path: _V3OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["signed_v2"] is False
    assert payload["signed_v3"] is True
    assert payload["signed_v31"] is False
    assert payload["signed"] is True
    assert payload["signature_files"] == []
    assert payload["certificates"] == []


def test_apk_certificates_reports_a_v31_only_apk_as_signed() -> None:
    """A v3.1-only key-rotation APK must not read as unsigned.

    Signature Scheme v3.1 (Android 13+) carries the rotated key, and an app that
    rotates its signing key with SDK targeting can present a v3.1 block without a
    v3 one. Leaving v3.1 out of the overall ``signed`` OR reported such a package
    as unsigned even though get_certificates() surfaced the signer; the new
    signed_v31 flag and its inclusion in ``signed`` fix that.
    """
    client = ApkClient()
    client._apk = lambda _path: _V31OnlyApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["signed_v2"] is False
    assert payload["signed_v3"] is False
    assert payload["signed_v31"] is True
    assert payload["signed"] is True
    assert len(payload["certificates"]) == 1


class _SchemeCert:
    """A signer cert whose sha256 digest is the join key across scheme blocks."""

    def __init__(self, tag: str) -> None:
        self.subject = f"CN={tag}"
        self.issuer = "CN=ca"
        self.serial_number = 1
        self.sha256_fingerprint = tag
        self.sha256 = tag.encode("ascii")


class _RotationApk:
    """A key-rotation APK: the old key sits in v3, the rotated key in v3.1.

    ``get_certificates()`` unions and dedupes both, so without per-cert scheme
    labels an analyst cannot tell which identity is current.
    """

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_SchemeCert]:
        return [_SchemeCert("old"), _SchemeCert("new")]

    def is_signed_v2(self) -> bool:
        return False

    def is_signed_v3(self) -> bool:
        return True

    def is_signed_v31(self) -> bool:
        return True

    def get_certificates_v1(self) -> list[_SchemeCert]:
        return []

    def get_certificates_v2(self) -> list[_SchemeCert]:
        return []

    def get_certificates_v3(self) -> list[_SchemeCert]:
        return [_SchemeCert("old")]

    def get_certificates_v31(self) -> list[_SchemeCert]:
        return [_SchemeCert("new")]


class _MultiSchemeApk:
    """One key signed into v1, v2 and v3 at once -- the common modern case."""

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_SchemeCert]:
        return [_SchemeCert("k")]

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True

    def get_certificates_v1(self) -> list[_SchemeCert]:
        return [_SchemeCert("k")]

    def get_certificates_v2(self) -> list[_SchemeCert]:
        return [_SchemeCert("k")]

    def get_certificates_v3(self) -> list[_SchemeCert]:
        return [_SchemeCert("k")]

    def get_certificates_v31(self) -> list[_SchemeCert]:
        return []


def test_apk_certificates_tag_each_cert_with_its_signing_schemes() -> None:
    """A key rotation must show which cert is v3.1 (new) and which is v3 (old).

    The flat, sha256-deduped union from get_certificates() hides the lineage.
    Keying each scheme's certs by digest lets the view label the rotated key as
    v3.1 and the retained key as v3, so the current signer is identifiable.
    """
    client = ApkClient()
    client._apk = lambda _path: _RotationApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    by_subject = {c["subject"]: c for c in payload["certificates"]}
    assert by_subject["CN=old"]["schemes"] == ["v3"]
    assert by_subject["CN=new"]["schemes"] == ["v3.1"]
    assert payload["signed_v3"] is True
    assert payload["signed_v31"] is True


def test_apk_certificates_list_every_scheme_a_shared_key_signs() -> None:
    """A key present in v1, v2 and v3 is labelled with all three, in order."""
    client = ApkClient()
    client._apk = lambda _path: _MultiSchemeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["schemes"] == ["v1", "v2", "v3"]


def test_apk_certificates_omit_schemes_when_the_build_cannot_report_them() -> None:
    """Older androguard without per-scheme getters must not grow an empty label.

    _FakeApk exposes only get_certificates()/get_signature_names(), like a build
    predating the v2/v3 accessors. The scheme index is then empty, so the cert
    entries carry no schemes key rather than a misleading empty list.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert all("schemes" not in cert for cert in payload["certificates"])
