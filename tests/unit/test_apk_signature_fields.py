"""Unit tests for apk.signature (signing scheme detection).

These pin the scheme booleans, the overall signed verdict, per-scheme signer
certificate rows (subject + sha256, deduped within a scheme), graceful handling
when a scheme getter raises, and the certificate cap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import _MAX_CERTIFICATES, ApkClient


class _FakeCert:
    def __init__(self, subject: str, sha256: str) -> None:
        self.subject = subject
        self.sha256_fingerprint = sha256


class _FakeApk:
    def __init__(
        self,
        *,
        v1: bool = False,
        v2: bool = False,
        v3: bool = False,
        v31: bool = False,
        certs_v1: list[_FakeCert] | None = None,
        certs_v2: list[_FakeCert] | None = None,
        certs_v3: list[_FakeCert] | None = None,
        certs_v31: list[_FakeCert] | None = None,
        raise_v3_certs: bool = False,
    ) -> None:
        self._v1, self._v2, self._v3, self._v31 = v1, v2, v3, v31
        self._certs_v1 = certs_v1 or []
        self._certs_v2 = certs_v2 or []
        self._certs_v3 = certs_v3 or []
        self._certs_v31 = certs_v31 or []
        self._raise_v3_certs = raise_v3_certs

    def is_signed(self) -> bool:
        return self._v1 or self._v2 or self._v3 or self._v31

    def is_signed_v1(self) -> bool:
        return self._v1

    def is_signed_v2(self) -> bool:
        return self._v2

    def is_signed_v3(self) -> bool:
        return self._v3

    def is_signed_v31(self) -> bool:
        return self._v31

    def get_certificates_v1(self) -> list[_FakeCert]:
        return self._certs_v1

    def get_certificates_v2(self) -> list[_FakeCert]:
        return self._certs_v2

    def get_certificates_v3(self) -> list[_FakeCert]:
        if self._raise_v3_certs:
            raise ValueError("malformed v3 block")
        return self._certs_v3

    def get_certificates_v31(self) -> list[_FakeCert]:
        return self._certs_v31


def _client_with(apk: _FakeApk, monkeypatch: Any) -> ApkClient:
    monkeypatch.setattr(
        ApkClient,
        "_apk",
        lambda self, path: apk,  # type: ignore[method-assign, assignment, return-value]
    )
    return ApkClient()


def test_signature_reports_schemes_and_certs(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(
        v2=True,
        v3=True,
        certs_v2=[_FakeCert("CN=Dev", "AA:BB")],
        certs_v3=[_FakeCert("CN=Dev", "AA:BB")],
    )
    client = _client_with(apk, monkeypatch)

    payload = client.signature(tmp_path / "app.apk")

    assert payload["signed"] is True
    assert payload["schemes"] == {"v1": False, "v2": True, "v3": True, "v31": False}
    assert payload["certificates"] == [
        {"scheme": "v2", "subject": "CN=Dev", "sha256": "AA:BB"},
        {"scheme": "v3", "subject": "CN=Dev", "sha256": "AA:BB"},
    ]
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_signature_v1_only_downgrade(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(v1=True, certs_v1=[_FakeCert("CN=Legacy", "11:22")])
    client = _client_with(apk, monkeypatch)

    payload = client.signature(tmp_path / "app.apk")

    assert payload["schemes"] == {"v1": True, "v2": False, "v3": False, "v31": False}
    assert payload["certificates"] == [
        {"scheme": "v1", "subject": "CN=Legacy", "sha256": "11:22"}
    ]


def test_signature_unsigned(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk()
    client = _client_with(apk, monkeypatch)

    payload = client.signature(tmp_path / "app.apk")

    assert payload["signed"] is False
    assert payload["schemes"] == {"v1": False, "v2": False, "v3": False, "v31": False}
    assert payload["certificates"] == []
    assert payload["count"] == 0


def test_signature_dedupes_within_scheme(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(
        v2=True,
        certs_v2=[_FakeCert("CN=Dev", "AA:BB"), _FakeCert("CN=Dev", "AA:BB")],
    )
    client = _client_with(apk, monkeypatch)

    payload = client.signature(tmp_path / "app.apk")

    assert payload["certificates"] == [
        {"scheme": "v2", "subject": "CN=Dev", "sha256": "AA:BB"}
    ]


def test_signature_tolerates_raising_getter(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(
        v2=True,
        v3=True,
        certs_v2=[_FakeCert("CN=Dev", "AA:BB")],
        raise_v3_certs=True,
    )
    client = _client_with(apk, monkeypatch)

    payload = client.signature(tmp_path / "app.apk")

    assert payload["schemes"]["v3"] is True
    assert payload["certificates"] == [
        {"scheme": "v2", "subject": "CN=Dev", "sha256": "AA:BB"}
    ]


def test_signature_caps_certificates(tmp_path: Path, monkeypatch: Any) -> None:
    many = [_FakeCert(f"CN=D{index}", f"{index:02d}") for index in range(_MAX_CERTIFICATES + 5)]
    apk = _FakeApk(v2=True, certs_v2=many)
    client = _client_with(apk, monkeypatch)

    payload = client.signature(tmp_path / "app.apk")

    assert payload["count"] == _MAX_CERTIFICATES
    assert payload["has_more"] is True


def test_signature_docstring_names_shape() -> None:
    doc = ApkClient.signature.__doc__ or ""
    assert "signing schemes" in doc
    assert "v1-only downgrade" in doc
    assert "sha256" in doc
