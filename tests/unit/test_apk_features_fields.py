"""Unit tests for apk.features (<uses-feature> census).

These pin the sorted feature list, the cap/has_more contract, the empty and
raising-getter paths, and the docstring shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import _MAX_FEATURES, ApkClient


class _FakeApk:
    def __init__(self, features: list[str] | None, *, raise_it: bool = False) -> None:
        self._features = features
        self._raise = raise_it

    def get_features(self) -> list[str] | None:
        if self._raise:
            raise ValueError("no features element")
        return self._features


def _client_with(apk: _FakeApk, monkeypatch: Any) -> ApkClient:
    monkeypatch.setattr(
        ApkClient,
        "_apk",
        lambda self, path: apk,  # type: ignore[method-assign, assignment, return-value]
    )
    return ApkClient()


def test_features_sorted_and_counted(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(
        [
            "android.hardware.telephony",
            "android.hardware.camera",
            "android.software.webview",
        ]
    )
    client = _client_with(apk, monkeypatch)

    payload = client.features(tmp_path / "app.apk")

    assert payload["features"] == [
        "android.hardware.camera",
        "android.hardware.telephony",
        "android.software.webview",
    ]
    assert payload["count"] == 3
    assert payload["has_more"] is False


def test_features_empty(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client_with(_FakeApk([]), monkeypatch)

    payload = client.features(tmp_path / "app.apk")

    assert payload["features"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_features_none_is_empty(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client_with(_FakeApk(None), monkeypatch)

    payload = client.features(tmp_path / "app.apk")

    assert payload["features"] == []
    assert payload["count"] == 0


def test_features_getter_raising_is_empty(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client_with(_FakeApk(None, raise_it=True), monkeypatch)

    payload = client.features(tmp_path / "app.apk")

    assert payload["features"] == []
    assert payload["has_more"] is False


def test_features_caps_and_marks_has_more(tmp_path: Path, monkeypatch: Any) -> None:
    many = [f"android.hardware.f{index:04d}" for index in range(_MAX_FEATURES + 7)]
    client = _client_with(_FakeApk(many), monkeypatch)

    payload = client.features(tmp_path / "app.apk")

    assert payload["count"] == _MAX_FEATURES
    assert payload["has_more"] is True


def test_features_docstring_names_shape() -> None:
    doc = ApkClient.features.__doc__ or ""
    assert "<uses-feature> census" in doc
    assert "no DEX analysis" in doc
