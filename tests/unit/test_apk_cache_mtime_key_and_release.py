"""The APK parse caches must key on mtime and ``release`` must fully evict.

``test_apk_client_parse_layer.py`` proves the light and full caches parse once
then serve, and that they evict the oldest past the limit -- but every "serve"
call re-opens the *same file with an unchanged mtime*, so the mtime half of the
cache key is executed without being observed: replace ``_key`` with
``(str(path), 0)`` and that whole suite still passes, while a rebuilt APK at the
same path (apk.decode -> edit -> apk.build writes it back) would be served its
stale pre-edit parse. That is the exact repack workflow, so a stale hit means
apk.* answers about a file that no longer exists on disk.

``release`` is only tested for its OSError-returns-False arc; its actual job --
dropping every cached parse for a path, across both caches and across every
mtime the path was ever cached under, while leaving other APKs alone -- is
unpinned. Shrinking its loop to ``(cls._light_cache,)`` leaves the expensive
full-DEX analysis resident after session close (the very leak release exists to
prevent) and the current suite stays green. These tests pin both.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from headless_re_mcp.backends.apk.client import ApkClient


@pytest.fixture(autouse=True)
def _clear_caches() -> Any:
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _install_androguard(
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk_factory: Any = None,
    analyze_factory: Any = None,
) -> None:
    root = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    core_apk = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    core_apk.APK = apk_factory or (lambda path: MagicMock(name="APK"))  # type: ignore[attr-defined]
    misc.AnalyzeAPK = analyze_factory or (  # type: ignore[attr-defined]
        lambda path: (MagicMock(name="apk"), MagicMock(name="dex"), MagicMock(name="analysis"))
    )
    root.core = core  # type: ignore[attr-defined]
    core.apk = core_apk  # type: ignore[attr-defined]
    root.misc = misc  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", root)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.apk", core_apk)
    monkeypatch.setitem(sys.modules, "androguard.misc", misc)


def _apk_file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04")
    return path


def _rewrite_with_newer_mtime(path: Path, data: bytes) -> None:
    """Edit the file and force a strictly newer mtime.

    Coarse filesystem mtime resolution can make a same-second rewrite look
    unchanged, which would mask a real cache miss; bumping the stamp a whole
    second makes the miss deterministic without depending on timer precision.
    """
    path.write_bytes(data)
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


# --- mtime keying ------------------------------------------------------------


def test_a_modified_apk_reparses_because_the_light_key_carries_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    _install_androguard(monkeypatch, apk_factory=lambda path: calls.append(path) or object())
    client = ApkClient()
    apk = _apk_file(tmp_path)

    client._apk(apk)
    client._apk(apk)
    assert len(calls) == 1, "an unchanged file is served from cache"

    _rewrite_with_newer_mtime(apk, b"PK\x03\x04\x00rebuilt")
    client._apk(apk)
    assert len(calls) == 2, "a rebuilt file at the same path is a cache miss"


def test_a_modified_apk_reanalyzes_because_the_full_key_carries_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    _install_androguard(
        monkeypatch,
        analyze_factory=lambda path: calls.append(path) or (object(), object(), object()),
    )
    client = ApkClient()
    apk = _apk_file(tmp_path)

    client._parsed(apk)
    client._parsed(apk)
    assert len(calls) == 1

    _rewrite_with_newer_mtime(apk, b"PK\x03\x04\x00rebuilt")
    client._parsed(apk)
    assert len(calls) == 2


# --- release -----------------------------------------------------------------


def test_release_drops_the_cached_parse_and_returns_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path)
    client._apk(apk)
    assert len(ApkClient._light_cache) == 1

    assert ApkClient.release(apk) is True
    assert len(ApkClient._light_cache) == 0
    # A second release finds nothing left to drop.
    assert ApkClient.release(apk) is False


def test_release_drops_across_both_the_light_and_full_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The full-DEX analysis is the heavy resident cost release exists to free."""
    _install_androguard(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path)
    client._apk(apk)
    client._parsed(apk)
    assert len(ApkClient._light_cache) == 1
    assert len(ApkClient._full_cache) == 1

    assert ApkClient.release(apk) is True
    assert len(ApkClient._light_cache) == 0
    assert len(ApkClient._full_cache) == 0


def test_release_drops_every_mtime_variant_cached_for_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """release matches on the path alone, so a stale earlier parse goes too.

    Editing an APK leaves its pre-edit parse cached under the old mtime key;
    release keys on ``key[0]`` (the path), not the whole key, so closing the
    session must reclaim both the current and the superseded entry.
    """
    _install_androguard(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path)
    client._apk(apk)
    _rewrite_with_newer_mtime(apk, b"PK\x03\x04\x00v2")
    client._apk(apk)
    assert len(ApkClient._light_cache) == 2, "two mtime variants of one path"

    assert ApkClient.release(apk) is True
    assert len(ApkClient._light_cache) == 0


def test_release_leaves_other_apks_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch)
    client = ApkClient()
    target = _apk_file(tmp_path, "target.apk")
    bystander = _apk_file(tmp_path, "bystander.apk")
    client._apk(target)
    client._apk(bystander)

    assert ApkClient.release(target) is True
    remaining = [key[0] for key in ApkClient._light_cache]
    assert remaining == [str(bystander.resolve())]
