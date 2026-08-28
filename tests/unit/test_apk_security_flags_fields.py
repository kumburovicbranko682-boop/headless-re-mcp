"""apk.security_flags resolves the security-relevant manifest <application> flags.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the resolution on hand-written
manifests: explicit values, Android's per-attribute defaults, the API-28
usesCleartextTraffic default flip, numeric boolean parsing, the manifest-level
sharedUserId/installLocation, malformed-XML truncation, the decode error, plus
the tool docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.tools.apk import build_apk_tools

_ALL_SET = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app"
          android:sharedUserId="com.example.shared"
          android:installLocation="auto">
  <application android:debuggable="true"
               android:allowBackup="false"
               android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config"
               android:testOnly="true"
               android:hasCode="false"
               android:largeHeap="true"
               android:backupAgent=".MyBackupAgent"
               android:fullBackupContent="@xml/backup_rules"
               android:dataExtractionRules="@xml/data_extraction_rules"/>
</manifest>
"""

_DEFAULTS = (
    b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    b'package="com.example.app"><application/></manifest>'
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


class _FakeApk:
    def __init__(
        self,
        xml: bytes = _ALL_SET,
        *,
        target: str | None = "30",
        min_sdk: str | None = "21",
        raise_axml: bool = False,
    ) -> None:
        self._xml = xml
        self._target = target
        self._min = min_sdk
        self._raise_axml = raise_axml

    def get_package(self) -> str:
        return "com.example.app"

    def get_min_sdk_version(self) -> str | None:
        return self._min

    def get_target_sdk_version(self) -> str | None:
        return self._target

    def get_android_manifest_axml(self) -> _Axml:
        return _Axml(self._xml, raise_exc=self._raise_axml)


def _client(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def test_all_flags_resolved_from_explicit_values() -> None:
    payload = _client(_FakeApk()).security_flags(Path("d.apk"))
    assert payload["package"] == "com.example.app"
    assert payload["min_sdk"] == 21
    assert payload["target_sdk"] == 30
    assert payload["debuggable"] is True
    assert payload["allow_backup"] is False
    assert payload["test_only"] is True
    assert payload["has_code"] is False
    assert payload["large_heap"] is True
    assert payload["uses_cleartext_traffic"] is True
    assert payload["uses_cleartext_traffic_declared"] == "true"
    assert payload["network_security_config"] == "@xml/network_security_config"
    assert payload["backup_agent"] == ".MyBackupAgent"
    assert payload["full_backup_content"] == "@xml/backup_rules"
    assert payload["data_extraction_rules"] == "@xml/data_extraction_rules"
    assert payload["shared_user_id"] == "com.example.shared"
    assert payload["install_location"] == "auto"
    assert payload["truncated"] is False


def test_unset_flags_fall_back_to_android_defaults() -> None:
    payload = _client(_FakeApk(_DEFAULTS)).security_flags(Path("d"))
    assert payload["debuggable"] is False
    assert payload["allow_backup"] is True
    assert payload["test_only"] is False
    assert payload["has_code"] is True
    assert payload["large_heap"] is False
    assert payload["uses_cleartext_traffic_declared"] is None
    assert payload["network_security_config"] is None
    assert payload["backup_agent"] is None
    assert payload["full_backup_content"] is None
    assert payload["data_extraction_rules"] is None
    assert payload["shared_user_id"] is None
    assert payload["install_location"] is None


def test_cleartext_default_follows_the_api28_flip() -> None:
    # Unset + target >= 28 -> false (the modern default).
    modern = _client(_FakeApk(_DEFAULTS, target="30")).security_flags(Path("d"))
    assert modern["uses_cleartext_traffic"] is False
    # Unset + target < 28 -> true (the legacy default).
    legacy = _client(_FakeApk(_DEFAULTS, target="27")).security_flags(Path("d"))
    assert legacy["uses_cleartext_traffic"] is True
    # Unset + unknown target -> true (conservative: assume plaintext allowed).
    unknown = _client(_FakeApk(_DEFAULTS, target=None)).security_flags(Path("d"))
    assert unknown["uses_cleartext_traffic"] is True


def test_explicit_cleartext_overrides_the_sdk_default() -> None:
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application '
        b'android:usesCleartextTraffic="false"/></manifest>'
    )
    payload = _client(_FakeApk(xml, target="27")).security_flags(Path("d"))
    assert payload["uses_cleartext_traffic"] is False
    assert payload["uses_cleartext_traffic_declared"] == "false"


def test_numeric_boolean_attributes_are_parsed() -> None:
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application '
        b'android:debuggable="0xffffffff" android:allowBackup="0"/></manifest>'
    )
    payload = _client(_FakeApk(xml)).security_flags(Path("d"))
    assert payload["debuggable"] is True
    assert payload["allow_backup"] is False


def test_malformed_manifest_sets_truncated_with_defaults() -> None:
    payload = _client(_FakeApk(b"<manifest><application")).security_flags(Path("d"))
    assert payload["truncated"] is True
    # Nothing parsed, so every flag falls back to its default.
    assert payload["debuggable"] is False
    assert payload["allow_backup"] is True
    assert payload["network_security_config"] is None


def test_manifest_decode_failure_is_backend_error() -> None:
    with pytest.raises(ApkError) as info:
        _client(_FakeApk(raise_axml=True)).security_flags(Path("d"))
    assert info.value.code == "backend_error"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.security_flags")
    assert "Answers with" in doc
    assert "debuggable" in doc and "allow_backup" in doc
    assert "uses_cleartext_traffic" in doc
    assert "network_security_config" in doc
    assert "truncated" in doc
