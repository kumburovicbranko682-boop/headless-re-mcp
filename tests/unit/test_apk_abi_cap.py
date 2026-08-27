"""apk.open / apk.native_libs bound the distinct-ABI set like every other list.

The ABI names come straight from the APK central directory, so a crafted
archive controls how many distinct ``lib/<abi>/`` directories it names. Every
other collection this client returns is capped with a has_more signal; these
two derived sets are held to the same bound so a hostile file cannot inflate
them past ``_MAX_ABIS``.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.apk.client import _MAX_ABIS, ApkClient


class _ManyAbiApk:
    """A pathological APK: thousands of distinct lib/<abi>/ directories."""

    def __init__(self, distinct: int) -> None:
        self._distinct = distinct

    def get_files(self) -> list[str]:
        return [f"lib/abi{index:06d}/l.so" for index in range(self._distinct)] + [
            "classes.dex"
        ]

    # open() reads these; only native_abis is under test here.
    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "34"

    def get_main_activity(self) -> str:
        return "com.example.app.Main"

    def get_permissions(self) -> list[str]:
        return []


def test_native_libs_caps_the_distinct_abi_set() -> None:
    client = ApkClient()
    client._apk = lambda _path: _ManyAbiApk(5000)  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert len(payload["abis"]) == _MAX_ABIS
    # 5000 distinct ABIs is well past the cap, so the truncation has to show.
    assert payload["has_more"] is True
    # Sorted and deduplicated, so the window is a stable prefix, not arbitrary.
    assert payload["abis"] == sorted(payload["abis"])
    assert len(set(payload["abis"])) == _MAX_ABIS


def test_open_caps_the_distinct_abi_set() -> None:
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _ManyAbiApk(5000)  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert len(payload["native_abis"]) == _MAX_ABIS
    assert payload["native_abis"] == sorted(payload["native_abis"])


def test_a_normal_abi_set_is_untouched() -> None:
    """The cap is headroom: a real handful of ABIs passes through whole."""
    client = ApkClient()
    client._available = True

    class _RealApk(_ManyAbiApk):
        def get_files(self) -> list[str]:
            return [
                "lib/arm64-v8a/libnative.so",
                "lib/armeabi-v7a/libnative.so",
                "lib/x86_64/libnative.so",
                "classes.dex",
            ]

    client._apk = lambda _path: _RealApk(0)  # type: ignore[method-assign]
    opened = client.open(Path("dummy.apk"))
    libs = client.native_libs(Path("dummy.apk"))
    assert opened["native_abis"] == ["arm64-v8a", "armeabi-v7a", "x86_64"]
    assert libs["abis"] == ["arm64-v8a", "armeabi-v7a", "x86_64"]
    assert libs["has_more"] is False
