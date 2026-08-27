"""``apk.open`` derives ``native_abis`` from the APK file list, filtered and deduped.

``open`` reports the set of native ABIs an APK ships so a caller can route to the
right disassembler. It reads them straight out of the zip's file list with an
inline comprehension -- *not* the ``native_libs`` method -- and every clause here
is load-bearing::

    "native_abis": sorted(
        {
            name.split("/")[1]                       # the <abi> segment of lib/<abi>/<file>
            for name in apk.get_files()
            if name.startswith("lib/") and len(name.split("/")) >= 3
        }
    ),

An Android APK stores native code as ``lib/<abi>/<name>.so`` (``lib/arm64-v8a/…``,
``lib/x86_64/…``); the middle segment is the ABI. But the same zip also holds
``assets/…``, ``res/…``, ``classes.dex`` and, in malformed or repacked samples,
truncated ``lib/`` entries with no filename. The comprehension keeps only true
per-file lib paths, takes the ABI segment, dedupes with a set, and sorts.

The existing ``open`` test feeds exactly one clean file -- ``lib/arm64-v8a/libx.so``
-- so ``native_abis == ["arm64-v8a"]`` passes with every discriminating clause
inert. Four behaviours a single, well-formed entry cannot show:

* **``lib/`` filters out other multi-segment paths.** ``assets/models/model.tflite``
  has three segments too, and its ``split("/")[1]`` is ``"models"``. Only the
  ``startswith("lib/")`` clause stops that from surfacing as a bogus ABI. Drop it
  and asset/resource directory names leak into ``native_abis``.

* **``len(...) >= 3`` rejects a lib path with no filename.** ``lib/armeabi`` and a
  bare ``lib/`` are two segments; their ``split("/")[1]`` is ``"armeabi"`` and
  ``""``. The length guard drops them so a directory entry (or a corrupt one)
  never masquerades as a shipped ABI. Drop it and ``native_abis`` gains phantom
  and empty-string entries.

* **The set dedupes.** A real APK has many ``.so`` files per ABI
  (``libssl.so``, ``libcrypto.so``, …); they must collapse to one ABI, not repeat
  once per file. A single file never exercises the fold.

* **The result is sorted.** Multiple ABIs come back in a stable, sorted order so a
  caller comparing against a known set does not flake on set iteration order.

These drive ``ApkClient.open`` through fake APKs whose ``get_files`` returns rich,
mixed, and malformed listings -- no androguard, no zip.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient


class _FilesApk:
    """A fake APK with fixed metadata and a caller-chosen ``get_files`` listing."""

    def __init__(self, files: list[str]) -> None:
        self._files = files

    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "33"

    def get_main_activity(self) -> str:
        return "com.example.app.Main"

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_files(self) -> list[str]:
        return self._files


def _abis(files: list[str]) -> list[str]:
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FilesApk(files)  # type: ignore[method-assign]
    return client.open(Path("app.apk"))["native_abis"]


def test_multiple_abis_are_deduped_and_sorted() -> None:
    """Many .so files across three ABIs collapse to three sorted ABI names.

    Two libraries under ``arm64-v8a`` must fold to a single entry, and the three
    distinct ABIs must come back sorted -- not once per file and not in set order.
    """
    abis = _abis(
        [
            "lib/x86/libz.so",
            "lib/arm64-v8a/libssl.so",
            "lib/arm64-v8a/libcrypto.so",
            "lib/armeabi-v7a/libc.so",
        ]
    )
    assert abis == ["arm64-v8a", "armeabi-v7a", "x86"]
    assert abis == sorted(set(abis))  # deduped and ordered


def test_a_non_lib_multi_segment_path_never_leaks_a_fake_abi() -> None:
    """An ``assets/`` path with a middle segment must not surface as an ABI.

    ``assets/models/model.tflite`` splits into three segments just like a lib
    path; only the ``lib/`` prefix filter keeps ``"models"`` out of the ABI set.
    The one genuine lib entry is all that survives.
    """
    abis = _abis(
        [
            "lib/arm64-v8a/libnative.so",
            "assets/models/model.tflite",
            "res/raw/config.bin",
            "classes.dex",
            "AndroidManifest.xml",
        ]
    )
    assert abis == ["arm64-v8a"]
    assert "models" not in abis
    assert "raw" not in abis


def test_a_lib_path_without_a_filename_is_ignored() -> None:
    """A directory-only ``lib/<abi>`` (or bare ``lib/``) is not a shipped ABI.

    ``lib/armeabi`` and ``lib/`` are two segments, so the ``len >= 3`` guard drops
    them; without it ``native_abis`` would gain ``"armeabi"`` (a directory, not a
    real per-file entry) and an empty string.
    """
    abis = _abis(
        [
            "lib/x86_64/libok.so",
            "lib/armeabi",
            "lib/",
        ]
    )
    assert abis == ["x86_64"]
    assert "armeabi" not in abis
    assert "" not in abis


def test_an_apk_with_no_native_libs_reports_no_abis() -> None:
    """A pure-Java APK (no ``lib/`` entries) reports an empty ABI list, not noise."""
    abis = _abis(
        [
            "AndroidManifest.xml",
            "classes.dex",
            "res/layout/main.xml",
            "assets/data/pack.bin",
        ]
    )
    assert abis == []
