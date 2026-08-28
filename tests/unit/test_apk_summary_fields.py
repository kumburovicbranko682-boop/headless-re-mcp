"""apk.summary rolls the manifest-level facts into one triage profile.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the roll-up: identity fields carried
over from apk.open, component counts (not names), native-lib/ABI/certificate
counts, the v1_signed flag, that a zip with no package name is a backend error,
and the tool docstring naming the returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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
    pass


class _FakeApk:
    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.2.3"

    def get_androidversion_code(self) -> str:
        return "42"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "34"

    def get_main_activity(self) -> str:
        return "com.example.app.Main"

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.CAMERA"]

    def get_activities(self) -> list[str]:
        return ["A0", "A1", "A2"]

    def get_services(self) -> list[str]:
        return ["S0"]

    def get_receivers(self) -> list[str]:
        return ["R0", "R1"]

    def get_providers(self) -> list[str]:
        return []

    def get_files(self) -> list[str]:
        return [
            "lib/arm64-v8a/libfoo.so",
            "lib/armeabi-v7a/libfoo.so",
            "classes.dex",
            "AndroidManifest.xml",
        ]

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert()]


def _client() -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    return client


def test_summary_rolls_up_the_manifest_facts() -> None:
    payload = _client().summary(Path("dummy.apk"))
    assert payload["opened"] is True
    assert payload["package"] == "com.example.app"
    assert payload["version_name"] == "1.2.3"
    assert payload["version_code"] == "42"
    assert payload["min_sdk"] == "21"
    assert payload["target_sdk"] == "34"
    assert payload["main_activity"] == "com.example.app.Main"
    assert payload["permission_count"] == 2
    assert payload["components"] == {
        "activities": 3,
        "services": 1,
        "receivers": 2,
        "providers": 0,
    }
    assert payload["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert payload["native_lib_count"] == 2
    assert payload["certificate_count"] == 1
    assert payload["v1_signed"] is True


def test_summary_reports_counts_not_lists() -> None:
    payload = _client().summary(Path("dummy.apk"))
    # The listing tools own the names; the summary is counts only.
    assert isinstance(payload["components"]["activities"], int)
    assert "activities" not in payload
    assert "native_libs" not in payload
    assert "permissions" not in payload
    assert "certificates" not in payload


class _NoPackageApk(_FakeApk):
    def get_package(self) -> str:
        return ""


def test_zip_without_package_is_a_backend_error() -> None:
    client = ApkClient()
    client._apk = lambda _path: _NoPackageApk()  # type: ignore[method-assign]
    with pytest.raises(ApkError) as info:
        client.summary(Path("dummy.apk"))
    assert info.value.code == "backend_error"
    assert info.value.details.get("opened") is False


class _UnsignedApk(_FakeApk):
    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return []


def test_unsigned_apk_reports_no_v1_and_zero_certs() -> None:
    client = ApkClient()
    client._apk = lambda _path: _UnsignedApk()  # type: ignore[method-assign]
    payload = client.summary(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["certificate_count"] == 0


class _OldAndroguardApk(_FakeApk):
    def get_signature_names(self) -> list[str]:
        raise RuntimeError("not supported on this androguard")

    def get_certificates(self) -> list[_Cert]:
        raise RuntimeError("not supported on this androguard")


def test_certificate_getters_that_raise_degrade_gracefully() -> None:
    client = ApkClient()
    client._apk = lambda _path: _OldAndroguardApk()  # type: ignore[method-assign]
    payload = client.summary(Path("dummy.apk"))
    assert payload["v1_signed"] is False
    assert payload["certificate_count"] == 0
    # The rest of the profile still stands.
    assert payload["package"] == "com.example.app"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.summary")
    assert "Answers with" in doc
    assert "permission_count" in doc
    assert "components" in doc
    assert "native_lib_count" in doc
    assert "certificate_count" in doc
    assert "v1_signed" in doc
