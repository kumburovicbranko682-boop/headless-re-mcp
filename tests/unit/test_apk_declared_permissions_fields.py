"""apk.declared_permissions lists the app's own <permission> declarations.

Driven through the _apk seam with a fake APK whose get_android_manifest_xml
returns a real lxml tree parsed from a manifest snippet. The protectionLevel
decoder is exercised directly since a compiled AXML carries the integer form.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from lxml import etree

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    _decode_protection_level,
)
from headless_re_mcp.tools.apk import build_apk_tools

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
  <permission android:name="com.example.perm.NORMAL"
              android:protectionLevel="normal"/>
  <permission android:name="com.example.perm.DANGER"
              android:protectionLevel="dangerous"
              android:permissionGroup="com.example.group.G"/>
  <permission android:name="com.example.perm.SAFE"
              android:protectionLevel="signature"/>
  <permission android:name="com.example.perm.SIGSYS"
              android:protectionLevel="signatureOrSystem"/>
  <permission android:name="com.example.perm.PRIV"
              android:protectionLevel="signature|privileged"/>
  <permission android:name="com.example.perm.DEFAULT"
              android:label="Default"/>
  <permission-group android:name="com.example.group.G" android:label="Grp"/>
  <permission-tree android:name="com.example.tree" android:label="Tree"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="App"/>
</manifest>
"""

_NUMERIC_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <permission android:name=".Num1" android:protectionLevel="0x12"/>
  <permission android:name=".Num2" android:protectionLevel="0x1"/>
  <permission android:name=".Num3" android:protectionLevel="2"/>
  <application/>
</manifest>
"""


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


class _FakeApk:
    def __init__(self, xml: str | None) -> None:
        self._root = etree.fromstring(xml.encode("utf-8")) if xml else None

    def get_android_manifest_xml(self) -> Any:
        return self._root


def _client_with(xml: str | None) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(xml)  # type: ignore[method-assign]
    return client


# --- protectionLevel decoder -------------------------------------------------


def test_decoder_defaults_absent_level_to_normal() -> None:
    assert _decode_protection_level(None) == ("normal", [])
    assert _decode_protection_level("") == ("normal", [])
    assert _decode_protection_level("   ") == ("normal", [])


def test_decoder_reads_the_name_form() -> None:
    assert _decode_protection_level("dangerous") == ("dangerous", [])
    assert _decode_protection_level("signature") == ("signature", [])
    assert _decode_protection_level("signatureOrSystem") == ("signatureOrSystem", [])
    # Flags trail the base and keep their spelling.
    assert _decode_protection_level("signature|privileged") == (
        "signature",
        ["privileged"],
    )


def test_decoder_reads_the_compiled_integer_form() -> None:
    # 0x12 == signature (0x2) with the privileged flag (0x10).
    assert _decode_protection_level("0x12") == ("signature", ["privileged"])
    # 0x1 == dangerous, no flags.
    assert _decode_protection_level("0x1") == ("dangerous", [])
    # A bare decimal is still an integer.
    assert _decode_protection_level("2") == ("signature", [])
    assert _decode_protection_level("0") == ("normal", [])


# --- declared_permissions ----------------------------------------------------


def test_declared_permissions_report_decoded_levels_and_group() -> None:
    payload = _client_with(_MANIFEST).declared_permissions(Path("d.apk"))
    assert payload["total"] == 6
    assert payload["count"] == 6
    by_name = {p["name"]: p for p in payload["permissions"]}

    danger = by_name["com.example.perm.DANGER"]
    assert danger["protection_level"] == "dangerous"
    assert danger["weak_protection"] is True
    assert danger["permission_group"] == "com.example.group.G"

    priv = by_name["com.example.perm.PRIV"]
    assert priv["protection_level"] == "signature"
    assert priv["protection_flags"] == ["privileged"]
    assert priv["weak_protection"] is False


def test_declared_permissions_default_level_is_weak_normal() -> None:
    payload = _client_with(_MANIFEST).declared_permissions(Path("d.apk"))
    by_name = {p["name"]: p for p in payload["permissions"]}
    default = by_name["com.example.perm.DEFAULT"]
    # No android:protectionLevel at all -> platform default normal -> weak.
    assert default["protection_level_raw"] is None
    assert default["protection_level"] == "normal"
    assert default["weak_protection"] is True
    assert default["label"] == "Default"


def test_declared_permissions_weak_count_folds_normal_and_dangerous() -> None:
    payload = _client_with(_MANIFEST).declared_permissions(Path("d.apk"))
    # NORMAL, DANGER and DEFAULT are weak; SAFE, SIGSYS and PRIV are not.
    assert payload["weak_count"] == 3


def test_declared_permissions_list_groups_and_trees() -> None:
    payload = _client_with(_MANIFEST).declared_permissions(Path("d.apk"))
    assert payload["permission_groups"] == [
        {"name": "com.example.group.G", "label": "Grp"}
    ]
    assert payload["permission_trees"] == [
        {"name": "com.example.tree", "label": "Tree"}
    ]


def test_declared_permissions_ignore_uses_permission() -> None:
    # <uses-permission> is a request, not a declaration, so it is not counted.
    payload = _client_with(_MANIFEST).declared_permissions(Path("d.apk"))
    names = {p["name"] for p in payload["permissions"]}
    assert "android.permission.INTERNET" not in names


def test_declared_permissions_decode_the_integer_form_end_to_end() -> None:
    payload = _client_with(_NUMERIC_MANIFEST).declared_permissions(Path("d.apk"))
    by_name = {p["name"]: p for p in payload["permissions"]}
    assert by_name[".Num1"]["protection_level"] == "signature"
    assert by_name[".Num1"]["protection_flags"] == ["privileged"]
    assert by_name[".Num1"]["weak_protection"] is False
    assert by_name[".Num2"]["protection_level"] == "dangerous"
    assert by_name[".Num2"]["weak_protection"] is True
    assert by_name[".Num3"]["protection_level"] == "signature"
    assert payload["weak_count"] == 1


def test_declared_permissions_on_a_manifest_without_permissions() -> None:
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.example"><application/></manifest>'
    )
    payload = _client_with(manifest).declared_permissions(Path("d.apk"))
    assert payload["permissions"] == []
    assert payload["permission_groups"] == []
    assert payload["permission_trees"] == []
    assert payload["total"] == 0
    assert payload["weak_count"] == 0
    assert payload["has_more"] is False


def test_declared_permissions_on_a_missing_manifest() -> None:
    payload = _client_with(None).declared_permissions(Path("d.apk"))
    assert payload["total"] == 0
    assert payload["permissions"] == []


def test_service_apk_declared_permissions_dispatch(
    tmp_path: Path,
) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)

    def _fake_binary(_session_id: str) -> Path:
        return Path("d.apk")

    service._apk_binary = _fake_binary  # type: ignore[method-assign]
    original = ApkClient.declared_permissions

    def _patched(self: ApkClient, _path: Path) -> dict[str, Any]:
        self._apk = lambda _p: _FakeApk(_MANIFEST)  # type: ignore[method-assign]
        return original(self, _path)

    ApkClient.declared_permissions = _patched  # type: ignore[method-assign]
    try:
        result = service.apk_declared_permissions("session")
    finally:
        ApkClient.declared_permissions = original  # type: ignore[method-assign]
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["weak_count"] == 3


def test_apk_declared_permissions_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_apk_tools(service)}
    assert "apk.declared_permissions" in names


def test_apk_declared_permissions_docstring_names_the_shape() -> None:
    doc = " ".join(_tool_docstring("apk.declared_permissions").split())
    assert "protection_level" in doc
    assert "protection_flags" in doc
    assert "weak_protection" in doc
    assert "weak_count" in doc
    assert "permission_group" in doc
    assert "permission_trees" in doc
