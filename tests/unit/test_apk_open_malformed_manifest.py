"""apk.open must degrade, not file an incident, on an unparseable manifest.

A valid APK whose ``AndroidManifest.xml`` androguard cannot parse is hostile
input, not a server fault. androguard is not uniform about it: most manifest
getters return empty, but ``get_androidversion_name`` / ``get_androidversion_code``
raise ``KeyError`` when its own manifest analysis failed. That ``KeyError`` was
uncaught in ``open`` and reached the service envelope as an ``internal_error``
with a logged incident. These pin the degrade-to-null behaviour so the miscast
cannot come back.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient


class _BrokenManifestApk:
    """Mimics androguard's shape when the manifest did not analyse."""

    def get_package(self) -> str:
        return ""

    def get_androidversion_name(self) -> str:
        raise KeyError("Name")

    def get_androidversion_code(self) -> str:
        raise KeyError("Code")

    def get_min_sdk_version(self) -> None:
        return None

    def get_target_sdk_version(self) -> None:
        return None

    def get_main_activity(self) -> None:
        return None

    def get_permissions(self) -> list[str]:
        return []

    def get_files(self) -> list[str]:
        return ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libnative.so"]


def test_open_degrades_to_null_fields_when_the_manifest_will_not_parse() -> None:
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _BrokenManifestApk()  # type: ignore[method-assign]

    # The version getters raise KeyError here; open must not let that escape.
    payload = client.open(Path("dummy.apk"))

    assert payload["opened"] is True
    assert payload["version_name"] is None
    assert payload["version_code"] is None
    assert payload["package"] == ""
    assert payload["permission_count"] == 0
    # Facts that come from the zip, not the manifest, are still reported.
    assert payload["native_abis"] == ["arm64-v8a"]
