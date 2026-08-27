"""apk.permissions must surface protection levels and flag dangerous permissions.

The protection level is the security-relevant fact a bare name list omits, so
these drive ApkClient.permissions with fakes standing in for androguard's
get_details_permissions / get_declared_permissions.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _permission_protection

_INTERNET = "android.permission.INTERNET"
_CONTACTS = "android.permission.READ_CONTACTS"
_SETTINGS = "android.permission.WRITE_SETTINGS"
_CUSTOM = "com.example.app.CUSTOM"


class _FakeApk:
    def get_permissions(self) -> list[str]:
        return [_INTERNET, _CONTACTS, _SETTINGS, _CUSTOM]

    def get_declared_permissions(self) -> list[str]:
        return [_CUSTOM]

    def get_details_permissions(self) -> dict[str, list[str]]:
        return {
            _INTERNET: ["normal|instant", "label", "desc"],
            _CONTACTS: ["dangerous", "label", "desc"],
            _SETTINGS: ["signature", "label", "desc"],
            # _CUSTOM is intentionally unresolved: absent from the details DB.
        }


class _NoDetailsApk(_FakeApk):
    def get_details_permissions(self) -> dict[str, list[str]]:
        raise RuntimeError("no AOSP permission DB bundled")


def _permissions(apk: object) -> dict[str, object]:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign,assignment]
    return client.permissions(Path("dummy.apk"))


def test_reports_base_protection_levels() -> None:
    levels = _permissions(_FakeApk())["protection_levels"]
    assert isinstance(levels, dict)
    # "normal|instant" collapses to its base token; the others pass through.
    assert levels[_INTERNET] == "normal"
    assert levels[_CONTACTS] == "dangerous"
    assert levels[_SETTINGS] == "signature"


def test_flags_the_dangerous_subset() -> None:
    payload = _permissions(_FakeApk())
    assert payload["dangerous"] == [_CONTACTS]


def test_unresolved_permission_is_absent_not_safe() -> None:
    levels = _permissions(_FakeApk())["protection_levels"]
    # A permission the DB cannot resolve simply has no level; it is not silently
    # reported as normal, and it is not in the dangerous list either.
    assert _CUSTOM not in levels


def test_custom_permissions_are_listed_separately() -> None:
    payload = _permissions(_FakeApk())
    assert payload["custom_permissions"] == [_CUSTOM]
    # The requested list and the app-declared list are distinct surfaces.
    assert _CUSTOM in payload["permissions"]


def test_existing_fields_are_unchanged() -> None:
    payload = _permissions(_FakeApk())
    assert payload["requested_permissions"] == payload["permissions"]
    assert payload["count"] == len(payload["permissions"])
    assert payload["has_more"] is False


def test_degrades_when_details_db_is_missing() -> None:
    payload = _permissions(_NoDetailsApk())
    # A build without the AOSP DB must not fail permissions(); the levels degrade
    # to empty and nothing is flagged dangerous rather than guessing.
    assert payload["protection_levels"] == {}
    assert payload["dangerous"] == []
    assert payload["permissions"]


def test_permission_protection_helper_restricts_and_tokenizes() -> None:
    class _Apk:
        def get_details_permissions(self) -> dict[str, list[str]]:
            return {
                "A.DANGER": ["dangerous|instant", "l", "d"],
                "A.SIG": ["signatureOrSystem", "l", "d"],
                "A.OUT_OF_SCOPE": ["dangerous", "l", "d"],
            }

    levels, dangerous = _permission_protection(_Apk(), {"A.DANGER", "A.SIG"})
    # Permission names keep their case; only the level token is normalized/lowered.
    assert levels == {"A.DANGER": "dangerous", "A.SIG": "signatureorsystem"}
    # Only in-scope names count; the dangerous one outside `names` is dropped.
    assert dangerous == ["A.DANGER"]
