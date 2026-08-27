"""ApkClient manifest-level reads: fault mapping, version fallbacks, honesty.

The manifest-level reads (manifest / permissions / certificates) parse only the
APK container, but they still go through androguard's APK object, so on a box
without androguard their fault and version-compat branches never ran. _apk
caches the parsed APK and returns it on a cache hit *before* importing
androguard, so seeding the light cache with a fake APK drives these methods
dependency-free -- the same fake-injection seam the frida device tests use.

What matters to an unattended agent, pinned here: a missing file is not_found
(not a later, more confusing parse error); a manifest that will not decode is a
precise backend_error rather than a leaked exception; the reads tolerate the
androguard-version differences they were written to absorb (an older build
lacking get_requested_permissions, an APK with no v1 signature block, a
certificate object whose fields vary); and the certificate lists cap with an
honest has_more rather than materialising an unbounded signing history.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_CERTIFICATES,
    _MAX_MANIFEST_CHARS,
    ApkClient,
    ApkError,
    _dotted_to_smali,
)


@pytest.fixture(autouse=True)
def _clear_apk_caches() -> Iterator[None]:
    """The parse caches are process-wide class state; clear them after each test
    so a seeded fake never leaks into an unrelated test's lookup."""
    yield
    with ApkClient._cache_lock:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()


def _raise(exc: BaseException) -> Any:
    def _fn(*_args: Any, **_kwargs: Any) -> Any:
        raise exc

    return _fn


def _client() -> ApkClient:
    client = ApkClient()
    # Force the capability flag so _require passes on a box without androguard;
    # the seeded cache means no androguard code is imported or run.
    client._available = True
    return client


def _apk_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.apk"
    path.write_bytes(b"PK\x03\x04 not really a zip, never parsed")
    return path


def _seed_light(client: ApkClient, path: Path, apk: Any) -> None:
    resolved = path.expanduser().resolve()
    key = (str(resolved), int(resolved.stat().st_mtime_ns))
    with ApkClient._cache_lock:
        ApkClient._light_cache[key] = apk


def test_a_missing_apk_is_not_found_before_any_parse(tmp_path: Path) -> None:
    """_require gates on file existence: a path that is not a file is not_found,
    the cheap local fact, rather than surfacing later as a parse backend_error."""
    with pytest.raises(ApkError) as caught:
        _client().manifest(tmp_path / "absent.apk")
    assert caught.value.code == "not_found"


def test_manifest_decodes_and_is_not_labelled_truncated_when_it_fits(tmp_path: Path) -> None:
    path = _apk_file(tmp_path)
    xml = "<manifest package='com.example.app'></manifest>"
    apk = SimpleNamespace(
        get_package=lambda: "com.example.app",
        get_android_manifest_axml=lambda: SimpleNamespace(get_xml=lambda: xml.encode("utf-8")),
    )
    _seed_light(client := _client(), path, apk)
    result = client.manifest(path)
    assert result["package"] == "com.example.app"
    assert result["manifest_xml"] == xml
    assert result["truncated"] is False


def test_manifest_is_capped_and_labelled_truncated_when_oversized(tmp_path: Path) -> None:
    path = _apk_file(tmp_path)
    xml = "<m>" + ("a" * (_MAX_MANIFEST_CHARS + 100)) + "</m>"
    apk = SimpleNamespace(
        get_package=lambda: "com.example.app",
        get_android_manifest_axml=lambda: SimpleNamespace(get_xml=lambda: xml.encode("utf-8")),
    )
    _seed_light(client := _client(), path, apk)
    result = client.manifest(path)
    assert len(result["manifest_xml"]) == _MAX_MANIFEST_CHARS
    assert result["truncated"] is True


def test_manifest_maps_a_decode_failure_to_backend_error(tmp_path: Path) -> None:
    path = _apk_file(tmp_path)
    apk = SimpleNamespace(
        get_package=lambda: "com.example.app",
        get_android_manifest_axml=_raise(RuntimeError("axml is malformed")),
    )
    _seed_light(client := _client(), path, apk)
    with pytest.raises(ApkError) as caught:
        client.manifest(path)
    assert caught.value.code == "backend_error"
    assert "failed to decode manifest" in caught.value.message


def test_permissions_fall_back_to_declared_when_requested_is_unavailable(
    tmp_path: Path,
) -> None:
    """Older androguard builds lack get_requested_permissions; the read must fall
    back to the declared set rather than fail. Declared names come back sorted."""
    path = _apk_file(tmp_path)
    apk = SimpleNamespace(
        get_permissions=lambda: [
            "android.permission.INTERNET",
            "android.permission.CAMERA",
        ],
        get_requested_permissions=_raise(AttributeError("no such method on this build")),
    )
    _seed_light(client := _client(), path, apk)
    result = client.permissions(path)
    assert result["permissions"] == [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]
    assert result["requested_permissions"] == result["permissions"]
    assert result["count"] == 2
    assert result["has_more"] is False


def test_certificates_tolerate_no_v1_block_and_a_field_varying_cert(tmp_path: Path) -> None:
    """An APK with no v1 signature block (get_signature_names unavailable) reports
    v1_signed False rather than raising, and a certificate object whose fields
    blow up on access is skipped, not fatal -- androguard cert objects vary."""
    path = _apk_file(tmp_path)

    class _ExplodingCert:
        @property
        def subject(self) -> str:
            raise RuntimeError("this cert object cannot be read")

    good = SimpleNamespace(
        subject="CN=Example",
        issuer="CN=Example",
        serial_number=42,
        sha256_fingerprint="ab" * 32,
    )
    apk = SimpleNamespace(
        get_signature_names=_raise(RuntimeError("no v1 signature")),
        get_certificates=lambda: [_ExplodingCert(), good],
    )
    _seed_light(client := _client(), path, apk)
    result = client.certificates(path)
    assert result["signature_files"] == []
    assert result["v1_signed"] is False
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["subject"] == "CN=Example"
    assert result["has_more"] is False


def test_certificates_cap_both_lists_and_report_has_more(tmp_path: Path) -> None:
    """Signing history is bounded: more signature files or certificates than the
    cap are truncated and flagged has_more, never materialised whole."""
    path = _apk_file(tmp_path)
    overflow = _MAX_CERTIFICATES + 5
    certs = [
        SimpleNamespace(
            subject=f"CN=c{index}",
            issuer="CN=ca",
            serial_number=index,
            sha256_fingerprint="00",
        )
        for index in range(overflow)
    ]
    apk = SimpleNamespace(
        get_signature_names=lambda: [f"META-INF/CERT{index}.RSA" for index in range(overflow)],
        get_certificates=lambda: certs,
    )
    _seed_light(client := _client(), path, apk)
    result = client.certificates(path)
    assert len(result["signature_files"]) == _MAX_CERTIFICATES
    assert len(result["certificates"]) == _MAX_CERTIFICATES
    assert result["v1_signed"] is True
    assert result["has_more"] is True


def test_dotted_to_smali_leaves_an_already_smali_name_untouched() -> None:
    """A caller may pass either com.example.Foo or Lcom/example/Foo;. The already
    -smali form must pass through unchanged so both resolve the same class."""
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
