"""describe_apk bounds the native-ABI set it reads at session creation.

describe_apk runs before any tool call, needs no androguard, and derives its
native_abis from the archive's own entry names -- which a crafted package fully
controls. It is held to the same bound as the androguard client so a package
naming thousands of distinct lib/<abi>/ directories cannot inflate the set that
lands in session metadata.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from headless_re_mcp.core.session import _MAX_APK_ABIS, describe_apk


def _apk_with_abis(path: Path, distinct: int) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        for index in range(distinct):
            archive.writestr(f"lib/abi{index:06d}/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    return path


def test_describe_apk_caps_a_pathological_abi_set(tmp_path: Path) -> None:
    info = describe_apk(_apk_with_abis(tmp_path / "many.apk", 3000))["apk"]
    assert len(info["native_abis"]) == _MAX_APK_ABIS
    assert info["native_abis"] == sorted(info["native_abis"])
    assert len(set(info["native_abis"])) == _MAX_APK_ABIS
    # The count fields still reflect the real archive; only the derived set is capped.
    assert info["dex_count"] == 1
    assert info["signed_v1"] is True


def test_describe_apk_leaves_a_normal_abi_set_whole(tmp_path: Path) -> None:
    path = tmp_path / "real.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        archive.writestr("lib/armeabi-v7a/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")
    info = describe_apk(path)["apk"]
    assert info["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert info["dex_count"] == 1
