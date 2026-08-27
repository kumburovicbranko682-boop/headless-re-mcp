"""apk.resource_strings reads res/values/strings.xml via androguard's ARSC.

apk.strings covers the DEX string pool; resource strings (hardcoded URLs,
endpoints, keys, config) live in resources.arsc and used to require a full
apktool decode to see. These pin the in-process path: name/value pairs parsed
and sorted, pagination honesty, the no-resources case, and that styled-span
text is not dropped. The androguard APK/ARSC is faked, so no device or real
sample is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient

_STRINGS_XML = (
    b"<?xml version='1.0' encoding='utf-8'?>\n"
    b"<resources>\n"
    b'  <string name="zeta_url">https://api.example.com/v2</string>\n'
    b'  <string name="alpha_key">sk_live_abc123</string>\n'
    b'  <string name="styled">Hello <b>bold</b> world</string>\n'
    b"</resources>\n"
)


class _FakeArsc:
    def __init__(self, xml: bytes, packages: list[str]) -> None:
        self._xml = xml
        self._packages = packages

    def get_packages_names(self) -> list[str]:
        return list(self._packages)

    def get_string_resources(self, package_name: str, locale: str = "\x00\x00") -> bytes:
        assert package_name in self._packages
        return self._xml


class _FakeApk:
    def __init__(self, arsc: Any, package: str = "com.example.app") -> None:
        self._arsc = arsc
        self._package = package

    def get_android_resources(self) -> Any:
        return self._arsc

    def get_package(self) -> str:
        return self._package


def _client_for(apk: _FakeApk, monkeypatch: Any) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    return client


def test_resource_strings_parses_sorted_name_value_pairs(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(_FakeArsc(_STRINGS_XML, ["com.example.app"]))
    client = _client_for(apk, monkeypatch)
    payload = client.resource_strings(tmp_path / "app.apk")
    assert payload["has_resources"] is True
    assert payload["package"] == "com.example.app"
    assert payload["total"] == 3
    names = [entry["name"] for entry in payload["strings"]]
    assert names == ["alpha_key", "styled", "zeta_url"]
    by_name = {entry["name"]: entry["value"] for entry in payload["strings"]}
    assert by_name["zeta_url"] == "https://api.example.com/v2"
    # itertext keeps text inside styled spans that element.text alone drops.
    assert by_name["styled"] == "Hello bold world"


def test_resource_strings_pagination_is_honest(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(_FakeArsc(_STRINGS_XML, ["com.example.app"]))
    client = _client_for(apk, monkeypatch)
    page = client.resource_strings(tmp_path / "app.apk", offset=0, limit=2)
    assert page["count"] == 2
    assert page["total"] == 3
    assert page["has_more"] is True
    assert [entry["name"] for entry in page["strings"]] == ["alpha_key", "styled"]
    tail = client.resource_strings(tmp_path / "app.apk", offset=2, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False
    assert [entry["name"] for entry in tail["strings"]] == ["zeta_url"]


def test_resource_strings_no_arsc_is_honest_empty(tmp_path: Path, monkeypatch: Any) -> None:
    apk = _FakeApk(None)
    client = _client_for(apk, monkeypatch)
    payload = client.resource_strings(tmp_path / "app.apk")
    assert payload["has_resources"] is False
    assert payload["strings"] == []
    assert payload["total"] == 0
    assert payload["package"] is None


def test_resource_strings_prefers_the_app_package(tmp_path: Path, monkeypatch: Any) -> None:
    """A table can carry several packages; the app's own is chosen, not the first."""
    arsc = _FakeArsc(_STRINGS_XML, ["com.other.lib", "com.example.app"])
    client = _client_for(_FakeApk(arsc, package="com.example.app"), monkeypatch)
    payload = client.resource_strings(tmp_path / "app.apk")
    assert payload["package"] == "com.example.app"
    assert payload["total"] == 3
