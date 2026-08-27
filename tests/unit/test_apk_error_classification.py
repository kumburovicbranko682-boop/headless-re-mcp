"""apk static reads classify hostile-APK failures instead of leaking them.

manifest/permissions/certificates each parse attacker-controlled bytes through
androguard, whose calls raise a wide, version-dependent set of exceptions on
malformed input. Left raw, those reach the service's BaseException arm as an
internal_error with a logged incident -- casting a bad APK (exactly the input
these tools exist to look at) as a server defect. These pin the classification:
a decode that fails is a backend_error, a per-version API gap falls back, and a
single unparseable entry is skipped rather than sinking the whole read.

Each drives the method body with a fake parsed APK injected through ``_apk``, so
no real APK or androguard parse is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


def _client_with_apk(fake_apk: Any) -> ApkClient:
    client = ApkClient()
    client._apk = lambda path: fake_apk  # type: ignore[method-assign]
    return client


class _AxmlThatWillNotDecode:
    def get_xml(self) -> bytes:
        raise ValueError("bad AXML chunk header")


class _ManifestApk:
    def get_package(self) -> str:
        return "com.example"

    def get_android_manifest_axml(self) -> _AxmlThatWillNotDecode:
        return _AxmlThatWillNotDecode()


def test_manifest_decode_failure_is_a_backend_error(tmp_path: Path) -> None:
    """A manifest whose AXML will not decode is a backend outcome, not a crash.

    Malformed AndroidManifest AXML is a common hostile-APK trait; the raise from
    androguard's decoder must be classified as backend_error naming the decode,
    not surfaced as an internal_error incident.
    """
    client = _client_with_apk(_ManifestApk())
    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"
    assert "manifest" in caught.value.message


class _OlderAndroguardApk:
    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        raise AttributeError("get_requested_permissions not in this androguard")


def test_permissions_falls_back_when_requested_permissions_is_unavailable(
    tmp_path: Path,
) -> None:
    """An androguard without get_requested_permissions still answers cleanly.

    The requested set is a newer API; when it is absent the read must fall back
    to the declared permissions rather than raising, so the tool works across
    the androguard versions operators actually have installed.
    """
    client = _client_with_apk(_OlderAndroguardApk())
    result = client.permissions(tmp_path / "app.apk")
    assert result["permissions"] == ["android.permission.INTERNET"]
    assert result["requested_permissions"] == ["android.permission.INTERNET"]


class _NoSignatureNamesApk:
    def get_signature_names(self) -> list[str]:
        raise RuntimeError("signature block unreadable")

    def get_certificates(self) -> list[Any]:
        return []


def test_certificates_tolerates_a_signature_name_listing_that_raises(
    tmp_path: Path,
) -> None:
    """A signing block whose names will not list still returns, unsigned.

    get_signature_names can raise on an odd META-INF layout; the read falls back
    to no names (v1_signed False) and proceeds to certificate parsing rather
    than failing the whole call over the listing step.
    """
    client = _client_with_apk(_NoSignatureNamesApk())
    result = client.certificates(tmp_path / "app.apk")
    assert result["signature_files"] == []
    assert result["v1_signed"] is False
    assert result["certificates"] == []


class _UnrenderableSubject:
    def __str__(self) -> str:
        raise ValueError("subject DN will not render")


class _BadCert:
    subject = _UnrenderableSubject()
    issuer = ""
    serial_number = 0


class _GoodCert:
    subject = "CN=Good"
    issuer = "CN=GoodCA"
    serial_number = 42
    sha256_fingerprint = "ab" * 32


class _MixedCertApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[Any]:
        return [_BadCert(), _GoodCert()]


def test_certificates_skips_an_unparseable_cert_and_keeps_the_rest(
    tmp_path: Path,
) -> None:
    """One certificate that will not render must not sink the whole listing.

    Certificate objects vary by androguard version and signing scheme; a single
    entry whose fields raise on access is skipped so the readable certificates
    still come back, rather than the read failing entirely on the worst entry.
    """
    client = _client_with_apk(_MixedCertApk())
    result = client.certificates(tmp_path / "app.apk")
    assert result["v1_signed"] is True
    assert result["signature_files"] == ["META-INF/CERT.RSA"]
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["subject"] == "CN=Good"
