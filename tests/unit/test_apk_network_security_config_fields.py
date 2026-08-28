"""apk.network_security_config resolves and distills the app's NSC policy.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the resolution (numeric resource id via
a fake ARSC resolver, and the named-reference path fallback) and the policy
parser on hand-written config XML: base/domain configs, trust anchors, pin sets,
cleartext domains, the trusts_user_ca aggregation (excluding debug-overrides),
graceful gaps when the file is unreadable, malformed-XML truncation, the
compiled-AXML decode fallback, the decode error, plus the tool docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _decode_axml_or_text,
    _nsc_named_ref_path,
    _nsc_reference_to_id,
)
from headless_re_mcp.tools.apk import build_apk_tools

_RICH_NSC = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">insecure.example.com</domain>
    <trust-anchors>
      <certificates src="user"/>
      <certificates src="system"/>
    </trust-anchors>
    <pin-set expiration="2025-12-31">
      <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
    </pin-set>
  </domain-config>
  <domain-config>
    <domain>secure.example.com</domain>
  </domain-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>
"""

_DEBUG_ONLY_USER = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>
"""


def _manifest(reference: str | None) -> bytes:
    attr = f' android:networkSecurityConfig="{reference}"' if reference is not None else ""
    return (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application' + attr.encode() + b"/></manifest>"
    )


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


class _Axml:
    def __init__(self, xml: bytes, *, raise_exc: bool = False) -> None:
        self._xml = xml
        self._raise = raise_exc

    def get_xml(self) -> bytes:
        if self._raise:
            raise RuntimeError("axml decode failed")
        return self._xml


class _Resolver:
    def __init__(self, mapping: dict[int, str]) -> None:
        self._m = mapping

    def get_resolved_res_configs(self, rid: int) -> list[tuple[object, str]]:
        path = self._m.get(rid)
        return [(None, path)] if path is not None else []


class _FakeApk:
    def __init__(
        self,
        reference: str | None,
        *,
        files: list[str] | None = None,
        res_files: dict[str, bytes] | None = None,
        resolver_map: dict[int, str] | None = None,
        raise_axml: bool = False,
        raise_get_file: bool = False,
    ) -> None:
        self._manifest = _manifest(reference)
        self._files = files or []
        self._res_files = res_files or {}
        self._resolver_map = resolver_map
        self._raise_axml = raise_axml
        self._raise_get_file = raise_get_file

    def get_package(self) -> str:
        return "com.example.app"

    def get_android_manifest_axml(self) -> _Axml:
        return _Axml(self._manifest, raise_exc=self._raise_axml)

    def get_android_resources(self) -> _Resolver | None:
        return _Resolver(self._resolver_map) if self._resolver_map is not None else None

    def get_files(self) -> list[str]:
        return list(self._files)

    def get_file(self, name: str) -> bytes:
        if self._raise_get_file:
            raise RuntimeError("read failed")
        if name not in self._res_files:
            raise KeyError(name)
        return self._res_files[name]


def _client(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def _numeric_apk(xml: bytes) -> _FakeApk:
    return _FakeApk(
        "@7F0F0000",
        resolver_map={0x7F0F0000: "res/xml/nsc.xml"},
        res_files={"res/xml/nsc.xml": xml},
    )


def test_not_configured_returns_empty_policy() -> None:
    payload = _client(_FakeApk(None)).network_security_config(Path("d.apk"))
    assert payload["configured"] is False
    assert payload["reference"] is None
    assert payload["xml_available"] is False
    assert payload["domain_configs"] == []
    assert payload["trusts_user_ca"] is False
    assert payload["has_pinning"] is False


def test_numeric_reference_resolves_and_parses_full_policy() -> None:
    payload = _client(_numeric_apk(_RICH_NSC)).network_security_config(Path("d"))
    assert payload["configured"] is True
    assert payload["reference"] == "@7F0F0000"
    assert payload["resource_path"] == "res/xml/nsc.xml"
    assert payload["xml_available"] is True
    assert payload["truncated"] is False

    assert payload["base_config"]["cleartext_permitted"] is False
    assert payload["base_config"]["trust_anchors"] == [{"src": "system", "override_pins": False}]

    assert payload["domain_config_count"] == 2
    first, second = payload["domain_configs"]
    assert first["domains"] == [{"name": "insecure.example.com", "include_subdomains": True}]
    assert first["cleartext_permitted"] is True
    assert first["trust_anchors"] == [
        {"src": "user", "override_pins": False},
        {"src": "system", "override_pins": False},
    ]
    assert first["pin_set"]["expiration"] == "2025-12-31"
    assert first["pin_set"]["pins"] == [
        {"digest": "SHA-256", "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    ]
    assert second["cleartext_permitted"] is None
    assert second["pin_set"] is None

    assert payload["debug_overrides"] == {
        "trust_anchors": [{"src": "user", "override_pins": False}]
    }
    assert payload["cleartext_permitted_domains"] == ["insecure.example.com"]
    assert payload["trusts_user_ca"] is True
    assert payload["has_pinning"] is True


def test_trusts_user_ca_excludes_debug_overrides() -> None:
    payload = _client(_numeric_apk(_DEBUG_ONLY_USER)).network_security_config(Path("d"))
    # Only debug-overrides trusts the user store, which is normal for debug builds.
    assert payload["trusts_user_ca"] is False
    assert payload["debug_overrides"]["trust_anchors"] == [{"src": "user", "override_pins": False}]
    assert payload["cleartext_permitted_domains"] == []


def test_named_reference_falls_back_to_res_path_convention() -> None:
    apk = _FakeApk(
        "@xml/network_security_config",
        files=["res/xml/network_security_config.xml", "AndroidManifest.xml"],
        res_files={"res/xml/network_security_config.xml": _RICH_NSC},
    )
    payload = _client(apk).network_security_config(Path("d"))
    assert payload["configured"] is True
    assert payload["resource_path"] == "res/xml/network_security_config.xml"
    assert payload["xml_available"] is True
    assert payload["has_pinning"] is True


def test_configured_but_unresolvable_reports_xml_unavailable() -> None:
    # Resolver returns nothing for the id and there is no named fallback path.
    apk = _FakeApk("@7F0F0000", resolver_map={})
    payload = _client(apk).network_security_config(Path("d"))
    assert payload["configured"] is True
    assert payload["resource_path"] is None
    assert payload["xml_available"] is False
    assert payload["domain_configs"] == []


def test_configured_but_file_read_fails_reports_xml_unavailable() -> None:
    apk = _FakeApk(
        "@7F0F0000",
        resolver_map={0x7F0F0000: "res/xml/nsc.xml"},
        raise_get_file=True,
    )
    payload = _client(apk).network_security_config(Path("d"))
    assert payload["configured"] is True
    assert payload["resource_path"] == "res/xml/nsc.xml"
    assert payload["xml_available"] is False


def test_malformed_config_xml_sets_truncated() -> None:
    apk = _numeric_apk(b"<network-security-config><base-config")
    payload = _client(apk).network_security_config(Path("d"))
    assert payload["xml_available"] is True
    assert payload["truncated"] is True
    assert payload["domain_configs"] == []
    assert payload["base_config"] is None


def test_manifest_decode_failure_is_backend_error() -> None:
    with pytest.raises(ApkError) as info:
        _client(_FakeApk("@7F0F0000", raise_axml=True)).network_security_config(Path("d"))
    assert info.value.code == "backend_error"


def test_reference_id_parsing() -> None:
    assert _nsc_reference_to_id("@7F0F0000") == 0x7F0F0000
    assert _nsc_reference_to_id("@android:01080000") == 0x01080000
    assert _nsc_reference_to_id("@xml/name") is None
    assert _nsc_reference_to_id("plain") is None
    assert _nsc_reference_to_id(None) is None


def test_named_reference_path_mapping() -> None:
    assert _nsc_named_ref_path("@xml/network_security_config") == (
        "res/xml/network_security_config.xml"
    )
    assert _nsc_named_ref_path("@com.x:xml/nsc") == "res/xml/nsc.xml"
    assert _nsc_named_ref_path("@7F0F0000") is None
    assert _nsc_named_ref_path(None) is None


def test_decode_axml_or_text_fallbacks() -> None:
    # Plain XML decodes as UTF-8 text.
    assert _decode_axml_or_text(b"<network-security-config/>") == "<network-security-config/>"
    # Compiled-AXML magic without androguard available degrades to None, not a raise.
    assert _decode_axml_or_text(b"\x03\x00\x08\x00\x00\x00\x00\x00") is None
    assert _decode_axml_or_text(b"") is None
    assert _decode_axml_or_text(None) is None


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.network_security_config")
    assert "Answers with" in doc
    assert "trusts_user_ca" in doc and "has_pinning" in doc
    assert "cleartext_permitted_domains" in doc
    assert "domain_configs" in doc
