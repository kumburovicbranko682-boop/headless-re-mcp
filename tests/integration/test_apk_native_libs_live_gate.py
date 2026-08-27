"""apk.native_libs live gate: real androguard APK().get_files() over a real zip.

``apk.native_libs`` was only ever run against a fake APK object whose
``get_files()`` returned a synthetic list -- the unit test replaces
``ApkClient._apk`` outright, so androguard never parses anything. Nothing proved
the tool works against a real ``androguard.core.apk.APK`` built from an actual
zip: that the constructor tolerates the archive, that ``get_files()`` yields the
real entry names, and that the ``lib/<abi>/<name>`` filter picks native code out
of the rest of the package.

This gate builds real APK zips and drives ``ApkClient.native_libs`` across them:

  * a multi-ABI package lists exactly its ``lib/`` entries (sorted), reports each
    distinct ABI, and excludes non-native entries (``classes.dex``, ``assets/``);
    and
  * a package with more shared objects than the 256 cap truncates the listing
    (``count`` 256, ``has_more`` True) while still reporting *every* ABI -- the
    ABI set is collected before the cap, so a truncated list never hides that a
    target ships, say, x86 code.

Skip != pass: the gate skips with a reason when androguard is not installed. CI
installs the android extra, so a skip there is a real regression, not a bare
machine.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import _MAX_NATIVE_LIBS, ApkClient

try:  # androguard logs a warning per parse; keep the gate output clean.
    from loguru import logger as _loguru_logger

    _loguru_logger.disable("androguard")
except Exception:  # noqa: BLE001 - loguru is androguard's dep, absent when it is
    pass


def _write_apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


@pytest.mark.integration
def test_native_libs_lists_real_apk_libraries_by_abi(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — native_libs gate not run (skip != pass)")

    apk = _write_apk(
        tmp_path / "multi_abi.apk",
        {
            "lib/arm64-v8a/libnative.so": b"\x7fELF-arm64",
            "lib/armeabi-v7a/libnative.so": b"\x7fELF-arm",
            "lib/x86_64/libother.so": b"\x7fELF-x86_64",
            # Not native code: must not appear in the listing.
            "assets/config.json": b"{}",
            "classes.dex": b"dex\n035\x00",
            "resources.arsc": b"\x00\x00",
        },
    )

    result = client.native_libs(apk)

    assert result["native_libs"] == [
        "lib/arm64-v8a/libnative.so",
        "lib/armeabi-v7a/libnative.so",
        "lib/x86_64/libother.so",
    ]
    assert result["abis"] == ["arm64-v8a", "armeabi-v7a", "x86_64"]
    assert result["count"] == 3
    assert result["has_more"] is False
    # The non-native entries were really in the archive; the filter, not an empty
    # zip, is what kept them out.
    assert not any(name.endswith(".dex") for name in result["native_libs"])


@pytest.mark.integration
def test_native_libs_caps_the_list_but_keeps_every_abi(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — native_libs gate not run (skip != pass)")

    entries: dict[str, bytes] = {"classes.dex": b"dex\n035\x00"}
    # More arm64 objects than the cap, plus one lone x86 object placed after them.
    for index in range(_MAX_NATIVE_LIBS + 20):
        entries[f"lib/arm64-v8a/lib{index:04d}.so"] = b"x"
    entries["lib/x86/liblonely.so"] = b"x"
    apk = _write_apk(tmp_path / "many_libs.apk", entries)

    result = client.native_libs(apk)

    # The listing is truncated at the cap and says so.
    assert result["count"] == _MAX_NATIVE_LIBS
    assert len(result["native_libs"]) == _MAX_NATIVE_LIBS
    assert result["has_more"] is True
    # But the ABI inventory is complete: x86 is reported even though its object
    # would fall past the truncation point, because ABIs are gathered before the
    # cap. A caller must not conclude "arm64 only" from a capped list.
    assert result["abis"] == ["arm64-v8a", "x86"]
