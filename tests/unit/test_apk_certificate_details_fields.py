"""apk.certificates surfaces key strength, validity and the debug-cert flag.

These are the cryptographic triage signals an analyst reaches for first: a weak
signing key (RSA under 2048 bits is forgeable), a cert outside its validity
window, and the stock Android debug certificate an app should never ship under.
The tests drive _cert_details with asn1crypto-shaped fakes so nothing here
needs a real keystore.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _cert_details
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


class _PubKey:
    def __init__(self, algorithm: str, bit_size: int) -> None:
        self.algorithm = algorithm
        self.bit_size = bit_size


class _Name:
    def __init__(self, common_name: str) -> None:
        self.native = {"common_name": common_name, "organization_name": "O"}


class _RichCert:
    """An asn1crypto-x509.Certificate look-alike, only the bits we read."""

    def __init__(
        self,
        *,
        common_name: str = "App",
        algorithm: str = "rsa",
        bit_size: int = 2048,
        signature_algo: str = "rsassa_pkcs1v15",
        hash_algo: str = "sha256",
        not_before: datetime | None = None,
        not_after: datetime | None = None,
    ) -> None:
        now = datetime.now(UTC)
        self.subject = _Name(common_name)
        self.issuer = _Name(common_name)
        self.serial_number = 7
        self.sha256_fingerprint = "aa"
        self.public_key = _PubKey(algorithm, bit_size)
        self.signature_algo = signature_algo
        self.hash_algo = hash_algo
        self.not_valid_before = not_before or (now - timedelta(days=1))
        self.not_valid_after = not_after or (now + timedelta(days=365))


def test_cert_details_reports_key_and_signature() -> None:
    """A healthy RSA-2048 cert: algorithm, size and Java-style sig algorithm."""
    details = _cert_details(_RichCert())
    assert details["key_algorithm"] == "rsa"
    assert details["key_size"] == 2048
    assert details["signature_algorithm"] == "SHA256withRSA"
    assert details["expired"] is False
    assert details["not_yet_valid"] is False
    assert details["is_debug_certificate"] is False
    assert "not_valid_before" in details and "not_valid_after" in details


def test_cert_details_flags_weak_key_and_ecdsa() -> None:
    """key_size passes through untouched; ECDSA renders with the EC family."""
    details = _cert_details(
        _RichCert(algorithm="ec", bit_size=256, signature_algo="ecdsa", hash_algo="sha256")
    )
    assert details["key_algorithm"] == "ec"
    assert details["key_size"] == 256
    assert details["signature_algorithm"] == "SHA256withECDSA"

    weak = _cert_details(_RichCert(bit_size=1024))
    assert weak["key_size"] == 1024  # RSA-1024: the analyst's cue, not hidden


def test_cert_details_derives_expired_and_not_yet_valid() -> None:
    """expired and not_yet_valid come from comparing the window to now."""
    now = datetime.now(UTC)
    past = _cert_details(
        _RichCert(not_before=now - timedelta(days=30), not_after=now - timedelta(days=1))
    )
    assert past["expired"] is True
    assert past["not_yet_valid"] is False

    future = _cert_details(
        _RichCert(not_before=now + timedelta(days=1), not_after=now + timedelta(days=30))
    )
    assert future["not_yet_valid"] is True
    assert future["expired"] is False


def test_cert_details_handles_naive_datetimes() -> None:
    """A tz-naive validity window is treated as UTC, not a crash."""
    naive_before = datetime(2020, 1, 1)  # noqa: DTZ001 - deliberately naive
    naive_after = datetime(2020, 6, 1)  # noqa: DTZ001 - deliberately naive
    details = _cert_details(_RichCert(not_before=naive_before, not_after=naive_after))
    assert details["expired"] is True
    assert details["not_yet_valid"] is False


def test_cert_details_flags_android_debug_certificate() -> None:
    """CN=Android Debug is the stock debug key; case-insensitive match."""
    assert _cert_details(_RichCert(common_name="Android Debug"))["is_debug_certificate"] is True
    assert _cert_details(_RichCert(common_name="ANDROID DEBUG"))["is_debug_certificate"] is True
    assert _cert_details(_RichCert(common_name="My Release Key"))["is_debug_certificate"] is False


def test_cert_details_omits_unreadable_fields() -> None:
    """A bare object exposes no key/validity, so those keys are simply absent."""

    class _Bare:
        pass

    details = _cert_details(_Bare())
    for absent in (
        "key_algorithm",
        "key_size",
        "signature_algorithm",
        "not_valid_before",
        "expired",
        "is_debug_certificate",
    ):
        assert absent not in details


def test_certificates_merges_details_and_docstring_names_them() -> None:
    """certificates() folds the details into each item; the tool doc lists them."""

    class _FakeApk:
        def get_signature_names(self) -> list[str]:
            return ["META-INF/CERT.RSA"]

        def get_certificates(self) -> list[_RichCert]:
            return [_RichCert(common_name="Android Debug", bit_size=1024)]

    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    cert = payload["certificates"][0]
    assert cert["key_size"] == 1024
    assert cert["is_debug_certificate"] is True
    assert cert["signature_algorithm"] == "SHA256withRSA"

    doc = _tool_docstring("apk.certificates")
    for field in ("key_size", "signature_algorithm", "not_valid_after", "is_debug_certificate"):
        assert field in doc
