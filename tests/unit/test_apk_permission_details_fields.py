"""apk.permission_details classifies an APK's permissions by protection level.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the classification on hand-written
androguard return values: the dangerous/normal/signature/unknown bucketing, the
per-category counts computed over every requested permission (not just the
returned page), the maxSdkVersion enrichment read from the manifest XML, the
app-declared custom permission listing (including numeric protectionLevel
resolution), dedup, the 256 cap, graceful degradation when the manifest XML or an
androguard call fails, plus the tool docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools

_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
                   android:maxSdkVersion="28"/>
  <uses-permission android:name="android.permission.READ_LOGS"/>
  <uses-permission android:name="com.acme.sdk.CUSTOM"/>
  <permission android:name="com.example.app.permission.MY_SERVICE"
              android:protectionLevel="0x2"
              android:permissionGroup="com.example.group"/>
  <application/>
</manifest>
"""

_DEFAULT_REQUESTED = [
    "android.permission.CAMERA",
    "android.permission.INTERNET",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_LOGS",
    "com.acme.sdk.CUSTOM",
]

_DEFAULT_DETAILS = {
    "android.permission.CAMERA": ["dangerous", "", ""],
    "android.permission.INTERNET": ["normal", "", ""],
    "android.permission.WRITE_EXTERNAL_STORAGE": ["dangerous", "", ""],
    "android.permission.READ_LOGS": ["signature|privileged", "", ""],
    # com.acme.sdk.CUSTOM deliberately absent -> unknown (third-party).
}

_DEFAULT_DECLARED = {
    "com.example.app.permission.MY_SERVICE": {
        "label": "",
        "description": "",
        "permissionGroup": "com.example.group",
        "protectionLevel": "0x2",
    },
}


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
        *,
        xml: bytes = _MANIFEST,
        target: str = "30",
        requested: list[str] | None = None,
        details: dict[str, list[str]] | None = None,
        declared: dict[str, dict[str, str]] | None = None,
        raise_axml: bool = False,
        raise_details: bool = False,
        raise_permissions: bool = False,
    ) -> None:
        self._xml = xml
        self._target = target
        self._requested = _DEFAULT_REQUESTED if requested is None else requested
        self._details = _DEFAULT_DETAILS if details is None else details
        self._declared = _DEFAULT_DECLARED if declared is None else declared
        self._raise_axml = raise_axml
        self._raise_details = raise_details
        self._raise_permissions = raise_permissions

    def get_package(self) -> str:
        return "com.example.app"

    def get_target_sdk_version(self) -> str:
        return self._target

    def get_permissions(self) -> list[str]:
        if self._raise_permissions:
            raise RuntimeError("boom")
        return list(self._requested)

    def get_details_permissions(self) -> dict[str, list[str]]:
        if self._raise_details:
            raise RuntimeError("boom")
        return dict(self._details)

    def get_declared_permissions_details(self) -> dict[str, dict[str, str]]:
        return dict(self._declared)

    def get_android_manifest_axml(self) -> _Axml:
        return _Axml(self._xml, raise_exc=self._raise_axml)


def _client(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def _row(payload: dict, name: str) -> dict:
    matches = [r for r in payload["requested"] if r["name"] == name]
    assert len(matches) == 1, name
    return matches[0]


def test_buckets_and_counts_over_all_requested() -> None:
    payload = _client(_FakeApk()).permission_details(Path("d.apk"))
    assert payload["package"] == "com.example.app"
    assert payload["target_sdk"] == 30
    assert payload["requested_count"] == 5
    assert payload["counts"] == {
        "dangerous": 2,
        "normal": 1,
        "signature": 1,
        "other": 0,
        "unknown": 1,
    }
    assert payload["has_more"] is False


def test_dangerous_and_signature_rows_carry_raw_level() -> None:
    payload = _client(_FakeApk()).permission_details(Path("d"))
    camera = _row(payload, "android.permission.CAMERA")
    assert camera["category"] == "dangerous"
    assert camera["protection_level"] == "dangerous"
    assert camera["app_defined"] is False
    logs = _row(payload, "android.permission.READ_LOGS")
    assert logs["category"] == "signature"
    # The raw resolved word is kept so the bucket is auditable.
    assert logs["protection_level"] == "signature|privileged"


def test_unresolved_third_party_permission_is_unknown() -> None:
    row = _row(_client(_FakeApk()).permission_details(Path("d")), "com.acme.sdk.CUSTOM")
    assert row["category"] == "unknown"
    assert row["protection_level"] is None


def test_max_sdk_is_read_from_the_manifest() -> None:
    payload = _client(_FakeApk()).permission_details(Path("d"))
    assert _row(payload, "android.permission.WRITE_EXTERNAL_STORAGE")["max_sdk"] == 28
    assert _row(payload, "android.permission.CAMERA")["max_sdk"] is None


def test_declared_permission_resolves_numeric_level() -> None:
    payload = _client(_FakeApk()).permission_details(Path("d"))
    assert payload["declared_count"] == 1
    declared = payload["declared"]
    assert len(declared) == 1
    row = declared[0]
    assert row["name"] == "com.example.app.permission.MY_SERVICE"
    # protectionLevel "0x2" (the signature flag) resolves to the signature bucket.
    assert row["protection_level"] == "signature"
    assert row["category"] == "signature"
    assert row["group"] == "com.example.group"


def test_app_defined_flag_marks_self_declared_requests() -> None:
    name = "com.example.app.permission.MY_SERVICE"
    apk = _FakeApk(
        requested=[name],
        details={name: ["signature", "", ""]},
    )
    row = _row(_client(apk).permission_details(Path("d")), name)
    assert row["app_defined"] is True
    assert row["category"] == "signature"


def test_declared_numeric_levels_across_the_base_range() -> None:
    declared = {
        "p.dangerous": {"protectionLevel": "0x1", "permissionGroup": "None"},
        "p.signature": {"protectionLevel": "2", "permissionGroup": ""},
        "p.normal": {"protectionLevel": "0x0", "permissionGroup": None},
        "p.absent": {"protectionLevel": "None"},
    }
    rows = {
        r["name"]: r
        for r in _client(_FakeApk(declared=declared)).permission_details(Path("d"))["declared"]
    }
    assert rows["p.dangerous"]["category"] == "dangerous"
    assert rows["p.signature"]["category"] == "signature"
    assert rows["p.normal"]["category"] == "normal"
    assert rows["p.absent"]["category"] == "unknown"
    assert rows["p.absent"]["protection_level"] is None
    # A "None" / empty permissionGroup is normalised to null.
    assert rows["p.dangerous"]["group"] is None
    assert rows["p.normal"]["group"] is None


def test_duplicate_requests_are_counted_once() -> None:
    apk = _FakeApk(
        requested=["android.permission.CAMERA", "android.permission.CAMERA"],
        details={"android.permission.CAMERA": ["dangerous", "", ""]},
    )
    payload = _client(apk).permission_details(Path("d"))
    assert payload["requested_count"] == 1
    assert len(payload["requested"]) == 1
    assert payload["counts"]["dangerous"] == 1


def test_requested_list_is_capped_but_counts_stay_complete() -> None:
    many = [f"com.x.P{i}" for i in range(300)]
    payload = _client(_FakeApk(requested=many, details={})).permission_details(Path("d"))
    assert payload["requested_count"] == 300
    assert len(payload["requested"]) == 256
    assert payload["has_more"] is True
    # Counts are over every requested permission, not the returned page.
    assert payload["counts"]["unknown"] == 300


def test_axml_failure_degrades_to_truncated_not_error() -> None:
    payload = _client(_FakeApk(raise_axml=True)).permission_details(Path("d"))
    assert payload["truncated"] is True
    # Classification still runs; only the maxSdkVersion enrichment is lost.
    assert payload["requested_count"] == 5
    assert _row(payload, "android.permission.WRITE_EXTERNAL_STORAGE")["max_sdk"] is None
    assert _row(payload, "android.permission.CAMERA")["category"] == "dangerous"


def test_malformed_manifest_sets_truncated_but_keeps_classification() -> None:
    payload = _client(_FakeApk(xml=b"<manifest><uses-permission")).permission_details(Path("d"))
    assert payload["truncated"] is True
    assert payload["requested_count"] == 5
    assert payload["counts"]["dangerous"] == 2


def test_androguard_failures_degrade_gracefully() -> None:
    # get_permissions raising leaves the requested list empty, not an exception.
    empty = _client(_FakeApk(raise_permissions=True)).permission_details(Path("d"))
    assert empty["requested"] == []
    assert empty["requested_count"] == 0
    # get_details_permissions raising leaves everything unresolved -> unknown.
    unresolved = _client(_FakeApk(raise_details=True)).permission_details(Path("d"))
    assert unresolved["counts"]["unknown"] == 5
    assert unresolved["counts"]["dangerous"] == 0


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.permission_details")
    assert "Answers with" in doc
    assert "requested" in doc and "declared" in doc
    assert "counts" in doc and "category" in doc
    assert "app_defined" in doc
    assert "has_more" in doc
