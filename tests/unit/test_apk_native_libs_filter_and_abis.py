"""``apk.native_libs`` lists only ``lib/`` members and reads ABIs from the tree.

``ApkClient.native_libs`` walks every archive member and keeps the ones under
``lib/``, deriving the ABI from the directory the ``.so`` sits in:

    for name in apk.get_files() or []:
        text = str(name)
        if not text.startswith("lib/"):
            continue
        parts = text.split("/")
        if len(parts) >= 3:
            abis.add(parts[1])
        if len(libs) >= _MAX_NATIVE_LIBS:
            has_more = True
            continue
        libs.append(text)

Three behaviours here are load-bearing, and ``test_apk_native_libs_fields`` --
whose fixture is 300 ``lib/arm64-v8a/*.so`` plus one ``classes.dex``, asserting
only ``count == 256`` / ``has_more`` / ``abis == ["arm64-v8a"]`` -- exercises
none of them:

* **The ``lib/`` filter.** A real APK is mostly non-native members
  (``AndroidManifest.xml``, ``classes.dex``, ``res/``, ``META-INF/``,
  ``assets/``). Only ``lib/`` files are native libraries. The existing test's
  lone ``classes.dex`` cannot show this: it sorts ahead of the ``lib/`` paths and
  the count is already capped at 256, so whether it is filtered or not, the
  asserted fields do not move. Drop the ``startswith`` guard and every APK's
  manifest and dex start showing up as "native libs".

* **ABIs are the set of ``lib/<abi>/`` subdirectories.** A shipped app carries
  several (``arm64-v8a``, ``armeabi-v7a``, ``x86_64``); the fixture has one, so
  the set collapsing multiple ABIs is never seen. And ``len(parts) >= 3`` guards
  a ``lib/``-level file with no ABI subdirectory: it is still listed, but
  ``parts[1]`` (its filename) must not be read as an ABI. Loosen the guard to
  ``>= 2`` and a stray ``lib/notice.txt`` invents an ABI called ``notice.txt``.

* **ABIs stay complete when the libs list is capped.** The ABI is recorded
  *before* the cap check, and the cap uses ``continue`` not ``break``, so an ABI
  whose ``.so`` files only appear past ``_MAX_NATIVE_LIBS`` is still reported.
  Change that ``continue`` to ``break`` and the truncated page loses those ABIs
  entirely -- the caller sees ``has_more`` but a short ABI list that reads as the
  whole set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import _MAX_NATIVE_LIBS, ApkClient


class _FakeApk:
    def __init__(self, files: list[str]) -> None:
        self._files = files

    def get_files(self) -> list[str]:
        return self._files


def _client(files: list[str]) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(files)  # type: ignore[method-assign]
    return client


def test_only_lib_members_are_native_libs(tmp_path: Any) -> None:
    """Manifest, dex, resources, signatures and assets are not native libraries.

    Every non-``lib/`` member must be filtered out; only the two ``lib/`` paths
    survive. ``classes.dex`` sorts ahead of the ``lib/`` entries, so if the
    filter were gone it would be ``native_libs[0]`` -- this asserts the exact
    two-entry list and count instead.
    """
    files = [
        "AndroidManifest.xml",
        "classes.dex",
        "res/layout/main.xml",
        "META-INF/CERT.RSA",
        "assets/data.bin",
        "lib/arm64-v8a/libfoo.so",
        "lib/armeabi-v7a/libfoo.so",
    ]
    payload = _client(files).native_libs(Path("app.apk"))
    assert payload["native_libs"] == [
        "lib/arm64-v8a/libfoo.so",
        "lib/armeabi-v7a/libfoo.so",
    ]
    assert payload["count"] == 2
    assert payload["has_more"] is False
    for member in ("classes.dex", "AndroidManifest.xml", "res/layout/main.xml"):
        assert member not in payload["native_libs"]


def test_abis_collect_every_subdir_and_ignore_a_lib_level_file(tmp_path: Any) -> None:
    """ABIs are the distinct ``lib/<abi>/`` dirs; a bare ``lib/`` file adds none.

    Three ABIs must all appear. ``lib/notice.txt`` has no ABI subdirectory, so
    it is listed as a member but must not contribute an ABI -- the ``>= 3`` guard
    is what stops its filename becoming a phantom ABI.
    """
    files = [
        "lib/arm64-v8a/a.so",
        "lib/armeabi-v7a/a.so",
        "lib/x86_64/a.so",
        "lib/notice.txt",
    ]
    payload = _client(files).native_libs(Path("app.apk"))
    assert payload["abis"] == ["arm64-v8a", "armeabi-v7a", "x86_64"]
    # The bare lib/ file is still a listed member but never a phantom ABI.
    assert "lib/notice.txt" in payload["native_libs"]
    assert "notice.txt" not in payload["abis"]


def test_abis_survive_when_the_libs_list_is_capped(tmp_path: Any) -> None:
    """ABIs whose .so files land past the cap are still reported -- all of them.

    The first _MAX_NATIVE_LIBS entries are one ABI, then two *more* ABIs follow,
    past the cap. The ABI is recorded before the cap check, so the first
    over-cap entry is caught either way; the ``continue`` (rather than ``break``)
    is what keeps the scan going to reach the *second* over-cap ABI. A ``break``
    would stop at the first over-cap file and silently drop ``x86_64`` while
    still reporting ``has_more`` -- a truncated ABI list read as the whole set.
    """
    files = [f"lib/arm64-v8a/l{index}.so" for index in range(_MAX_NATIVE_LIBS)]
    files += ["lib/armeabi-v7a/late.so", "lib/x86_64/later.so"]
    payload = _client(files).native_libs(Path("app.apk"))
    assert payload["count"] == _MAX_NATIVE_LIBS
    assert payload["has_more"] is True
    assert payload["abis"] == ["arm64-v8a", "armeabi-v7a", "x86_64"]
