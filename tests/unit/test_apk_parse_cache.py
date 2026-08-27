"""ApkClient parse cache: the reuse, invalidation, and eviction paths driven for real.

androguard's full DEX analysis is tens to hundreds of megabytes and seconds of
work, so ApkClient caches it. Every existing test either pre-seeds the class-level
caches with hand-built keys ``(path, 1)`` or re-implements the eviction loop
inline -- none drives ``_apk`` / ``_parsed`` through a counting parser, so the
contract those methods actually enforce is unpinned:

* a second read of an *unchanged* file reuses the cached parse (the whole point);
* the cache key carries ``st_mtime_ns``, so a *modified* APK is re-parsed rather
  than served stale (a repacked APK at the same path must not read as the old one);
* the light (manifest-only) and full (DEX) caches are independent;
* the LRU is real -- oldest evicted past the cap, and a re-read moves an entry to
  the newest end so it survives the next eviction.

These are driven by monkeypatching androguard's lazily-imported ``APK`` /
``AnalyzeAPK`` with call-counting fakes, so no real APK or androguard parse runs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import androguard.core.apk as androguard_apk
import androguard.misc as androguard_misc
import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient


@pytest.fixture(autouse=True)
def _clean_caches() -> Any:
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


class _Calls:
    def __init__(self) -> None:
        self.apk = 0
        self.analyze = 0


def _install_counting_parsers(monkeypatch: pytest.MonkeyPatch) -> _Calls:
    calls = _Calls()

    class _FakeAPK:
        def __init__(self, path: str) -> None:
            calls.apk += 1
            self.path = path

    def _fake_analyze(path: str) -> tuple[str, str, str]:
        calls.analyze += 1
        return (f"apk::{path}", "dex", "analysis")

    monkeypatch.setattr(androguard_apk, "APK", _FakeAPK)
    monkeypatch.setattr(androguard_misc, "AnalyzeAPK", _fake_analyze)
    return calls


def _apk_file(root: Path, name: str) -> Path:
    path = root / name
    path.write_bytes(b"PK\x03\x04" + name.encode("utf-8"))
    return path


def test_a_second_read_of_an_unchanged_apk_reuses_the_cached_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reason the cache exists. Two reads of the same untouched file parse
    once and hand back the identical object -- for both the light and full paths.
    """
    calls = _install_counting_parsers(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path, "app.apk")

    light_first = client._apk(apk)
    light_second = client._apk(apk)
    assert calls.apk == 1
    assert light_first is light_second

    full_first = client._parsed(apk)
    full_second = client._parsed(apk)
    assert calls.analyze == 1
    assert full_first is full_second


def test_a_modified_apk_is_reparsed_not_served_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cache key carries st_mtime_ns. Repack the file at the same path (here:
    bump its mtime) and the next read must miss and re-parse -- otherwise an agent
    analysing a freshly rebuilt APK would read the previous build's classes.
    """
    calls = _install_counting_parsers(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path, "app.apk")

    first = client._apk(apk)
    assert calls.apk == 1

    # Same path, new contents and a distinct mtime -- a repack.
    apk.write_bytes(b"PK\x03\x04rebuilt-and-larger")
    os.utime(apk, ns=(1_000_000_000, 1_000_000_000))

    second = client._apk(apk)
    assert calls.apk == 2
    assert second is not first


def test_the_light_and_full_caches_are_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cheap manifest-only parse must not satisfy a later full-analysis request,
    and vice versa: they answer different questions and live in separate caches.
    """
    calls = _install_counting_parsers(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path, "app.apk")

    client._apk(apk)
    assert (calls.apk, calls.analyze) == (1, 0)

    # The light cache is warm, but the full path must still run AnalyzeAPK.
    client._parsed(apk)
    assert (calls.apk, calls.analyze) == (1, 1)

    # And the full cache does not back-fill the light one.
    client._apk(apk)
    assert calls.apk == 1


def test_the_cache_evicts_the_oldest_apk_past_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the cap the least-recently-used entry is dropped, newest kept. Without
    the eviction an unattended process parsing APK after APK would sit on every
    hundred-megabyte analysis forever.
    """
    _install_counting_parsers(monkeypatch)
    monkeypatch.setattr(apk_client, "_CACHE_LIMIT", 2)
    client = ApkClient()

    first = _apk_file(tmp_path, "first.apk")
    second = _apk_file(tmp_path, "second.apk")
    third = _apk_file(tmp_path, "third.apk")
    for apk in (first, second, third):
        client._apk(apk)

    keys = {key[0] for key in ApkClient._light_cache}
    assert len(ApkClient._light_cache) == 2
    assert str(first.resolve()) not in keys
    assert str(third.resolve()) in keys


def test_a_reread_moves_an_entry_to_the_newest_end_so_it_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The LRU touch is load-bearing: re-reading the oldest entry before an
    overflow must spare it and evict the next-oldest instead. Drop move_to_end and
    a hot APK read every cycle would still be the one thrown away.
    """
    _install_counting_parsers(monkeypatch)
    monkeypatch.setattr(apk_client, "_CACHE_LIMIT", 2)
    client = ApkClient()

    older = _apk_file(tmp_path, "older.apk")
    newer = _apk_file(tmp_path, "newer.apk")
    client._apk(older)
    client._apk(newer)  # cache is [older, newer]; older is the eviction victim

    client._apk(older)  # touch: cache becomes [newer, older]; newer now oldest

    third = _apk_file(tmp_path, "third.apk")
    client._apk(third)  # overflow: evict newer, keep older

    keys = {key[0] for key in ApkClient._light_cache}
    assert str(older.resolve()) in keys
    assert str(newer.resolve()) not in keys
