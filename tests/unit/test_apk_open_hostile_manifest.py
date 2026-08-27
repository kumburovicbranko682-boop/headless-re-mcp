"""apk.open must refuse an unreadable manifest, not leak androguard's KeyError.

androguard builds an APK object even for a manifest it cannot parse -- a
truncated or garbage ``AndroidManifest.xml``, or none at all, every one a
plausible hostile input. On that object its getters are inconsistent, as
measured against androguard 4.x: ``get_package()`` returns ``""`` and
``get_min_sdk_version()`` / ``get_main_activity()`` return ``None``, but
``get_androidversion_name()`` / ``get_androidversion_code()`` raise
``KeyError('Name'/'Code')`` because ``self.androidversion`` was never populated
(package and the version keys are only set together, in one block, after the
manifest parses).

apk.open reads the package first and raises a structured ``backend_error`` when
it is empty, which shields the version getters. That ordering is the only thing
standing between a hostile-but-zippable APK and a raw ``KeyError`` reaching the
service as an ``internal_error`` with a logged incident -- a bad input miscast
as a tool bug. Nothing pinned it, so a refactor that read a version before the
package check would silently reintroduce the leak. These tests fix the contract:
one with a fake reproducing androguard's measured getter behaviour (runs
everywhere, deterministic), one driving real androguard on a real garbage APK
where the extra is installed (skip != pass otherwise).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _HostileApk:
    """Mirrors androguard 4.x on an unparseable manifest (measured behaviour)."""

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
        return []


def test_open_refuses_an_unreadable_manifest_without_leaking_keyerror() -> None:
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _HostileApk()  # type: ignore[method-assign]

    with pytest.raises(ApkError) as caught:
        client.open(Path("hostile.apk"))

    # The empty-package guard must fire before any version getter runs; a raw
    # KeyError escaping here would be the internal_error incident this pins out.
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("opened") is False


def test_open_degrades_on_a_real_garbage_manifest_apk(tmp_path: Path) -> None:
    pytest.importorskip("androguard", reason="androguard not installed (skip != pass)")

    apk = tmp_path / "garbage.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        # A valid zip whose AndroidManifest.xml is not AXML: androguard opens the
        # archive, fails to parse the manifest, and leaves package empty.
        archive.writestr("AndroidManifest.xml", b"this is not a binary AXML manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")

    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client.open(apk)
    assert caught.value.code == "backend_error"
