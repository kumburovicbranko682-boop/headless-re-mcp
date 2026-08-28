"""The apk parse cache must reuse, bound, forget failures, and release on demand.

``ApkClient`` keeps two process-wide LRU caches keyed by (path, mtime): a light
one for manifest-only ``APK`` parses and a full one for ``AnalyzeAPK`` DEX
analyses. Both are load-bearing and none of it was covered by a test:

  * a DEX analysis of a large app costs seconds and tens to hundreds of MB, so a
    second tool call in the same session must hit the cache, not re-run it; the
    hit also has to refresh recency (``move_to_end``) or the LRU degrades to a
    FIFO that evicts the app the agent is actively working on.
  * the caches are capped at ``_CACHE_LIMIT`` because an unbounded one is the
    overnight OOM the cap exists to prevent -- the oldest entry must actually be
    evicted past the cap.
  * a parse that raised must surface as a ``backend_error`` and must **not** be
    cached, or a transient failure would be pinned and every retry would replay
    the same error against a file that may now be readable.
  * ``release`` drops every cached parse for one path so a closed session stops
    sitting on an APK it will never look at again.

These drive the two deferred androguard imports (``androguard.core.apk.APK`` and
``androguard.misc.AnalyzeAPK``) through fakes, so the cache logic runs without a
real APK or a real analysis.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    _CACHE_LIMIT,
    ApkClient,
    ApkError,
    _ParsedApk,
)

_HAS_ANDROGUARD = importlib.util.find_spec("androguard") is not None


@pytest.fixture(autouse=True)
def _androguard_importable() -> Any:
    """Run these cache tests on the minimal quality install, where androguard is absent.

    The suite drives the client's two deferred imports by patching
    ``androguard.core.apk.APK`` and ``androguard.misc.AnalyzeAPK``, which needs
    those modules importable. androguard is an optional extra and the
    every-commit quality job installs only ``.[test,dev,web]``, so there the
    patch raised ModuleNotFoundError and all seven cache tests failed for a
    missing backend rather than exercising the cache the way they do locally
    (where the android extra is installed). Unit tests are meant to be
    self-sufficient -- every other backend suite injects fakes without importing
    the real module -- so when androguard cannot be imported, stand in minimal
    stub modules, wired as a package so both ``ApkClient.__init__``'s probe and
    the deferred ``from ... import`` resolve and the client reports itself
    available. Drop only the stubs we inserted so a real androguard (the
    android-extra jobs, local dev) is never shadowed.
    """
    inserted: list[str] = []
    if not _HAS_ANDROGUARD:
        for name, is_pkg in (
            ("androguard", True),
            ("androguard.core", True),
            ("androguard.core.apk", False),
            ("androguard.misc", False),
        ):
            module = ModuleType(name)
            if is_pkg:
                module.__path__ = []  # a package, so submodule imports resolve
            sys.modules[name] = module
            inserted.append(name)
        sys.modules["androguard"].core = sys.modules["androguard.core"]
        sys.modules["androguard.core"].apk = sys.modules["androguard.core.apk"]
        sys.modules["androguard"].misc = sys.modules["androguard.misc"]
        # Placeholder symbols the tests replace via monkeypatch.setattr.
        sys.modules["androguard.core.apk"].APK = None
        sys.modules["androguard.misc"].AnalyzeAPK = None
    try:
        yield
    finally:
        for name in reversed(inserted):
            sys.modules.pop(name, None)


@pytest.fixture(autouse=True)
def _clear_process_caches() -> Any:
    """The caches are class-level and process-wide, so isolate every test.

    Without this a parse cached by one test would count as a hit in the next and
    the call counters below would lie.
    """
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _apk_file(tmp_path: Path, name: str = "app.apk", body: bytes = b"PK\x03\x04") -> Path:
    path = tmp_path / name
    path.write_bytes(body)
    return path


def _install_apk_fake(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Replace androguard's manifest parser with a construction counter."""
    calls = {"n": 0}

    def fake_apk(path_str: str) -> Any:
        calls["n"] += 1
        return SimpleNamespace(path=path_str, nth=calls["n"])

    monkeypatch.setattr("androguard.core.apk.APK", fake_apk)
    return calls


def _install_analyze_fake(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Replace androguard's AnalyzeAPK with a counter returning a 3-tuple."""
    calls = {"n": 0}

    def fake_analyze(path_str: str) -> tuple[Any, Any, Any]:
        del path_str
        calls["n"] += 1
        return (
            SimpleNamespace(tag="apk"),
            SimpleNamespace(tag="dex"),
            SimpleNamespace(tag="analysis"),
        )

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", fake_analyze)
    return calls


def test_light_parse_is_cached_and_reused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second manifest read of the same APK returns the cached parse, not a re-parse."""
    calls = _install_apk_fake(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path)

    first = client._apk(apk)
    second = client._apk(apk)

    assert calls["n"] == 1  # parsed once, served from cache the second time
    assert first is second


def test_full_analysis_is_cached_and_wired_and_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The expensive DEX analysis runs once and its three products stay wired.

    A second call must return the same ``_ParsedApk`` -- re-running AnalyzeAPK is
    the multi-second, tens-of-MB cost the cache exists to avoid -- and the tuple
    androguard returns (apk, dex, analysis) must land on the right attributes,
    since every downstream tool reads ``.analysis`` and ``.apk`` off this object.
    """
    calls = _install_analyze_fake(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path)

    first = client._parsed(apk)
    second = client._parsed(apk)

    assert calls["n"] == 1
    assert first is second
    assert isinstance(first, _ParsedApk)
    assert first.apk.tag == "apk"
    assert first.analysis.tag == "analysis"
    assert first._dex.tag == "dex"


def test_a_parse_failure_is_a_backend_error_and_is_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raising parse surfaces as backend_error and leaves nothing cached.

    androguard raises many types on a malformed or non-APK zip; those collapse to
    one backend_error. Crucially the failure is not stored, so a retry re-parses
    rather than replaying a pinned error -- a file that was mid-write on the first
    call, or a transient read error, must not poison the cache for the session.
    """
    attempts = {"n": 0}

    def boom(path_str: str) -> Any:
        del path_str
        attempts["n"] += 1
        raise ValueError("bad zip central directory")

    monkeypatch.setattr("androguard.core.apk.APK", boom)
    client = ApkClient()
    bad = _apk_file(tmp_path, name="bad.apk", body=b"not a zip")

    for _ in range(2):
        with pytest.raises(ApkError) as caught:
            client._apk(bad)
        assert caught.value.code == "backend_error"
        assert "failed to parse APK" in caught.value.message

    # Both calls actually re-parsed: the failure was never cached.
    assert attempts["n"] == 2
    assert not any(str(bad.resolve()) == key[0] for key in ApkClient._light_cache)


def test_analysis_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The full-analysis path classifies its own failures the same way."""

    def boom(path_str: str) -> Any:
        del path_str
        raise RuntimeError("dex vm blew up")

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", boom)
    client = ApkClient()
    apk = _apk_file(tmp_path)

    with pytest.raises(ApkError) as caught:
        client._parsed(apk)
    assert caught.value.code == "backend_error"
    assert "failed to analyze APK" in caught.value.message
    assert len(ApkClient._full_cache) == 0


def test_cache_evicts_the_oldest_and_a_hit_refreshes_recency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the cap the least-recently-used entry is dropped, and a hit is 'used'.

    Fill the cache to its limit, then re-read the first APK: that hit must
    ``move_to_end`` so the entry counts as most-recent, not still-oldest. The next
    insert pushes the cache over the cap and evicts what is now the oldest -- the
    *second* APK -- while the refreshed first one survives. Without the recency
    refresh the LRU is a plain FIFO that would evict the app just touched, forcing
    a re-analysis of exactly the file the agent is working on.
    """
    calls = _install_apk_fake(monkeypatch)
    client = ApkClient()
    files = [_apk_file(tmp_path, name=f"f{i}.apk", body=bytes([i])) for i in range(_CACHE_LIMIT)]
    for path in files:
        client._apk(path)
    assert len(ApkClient._light_cache) == _CACHE_LIMIT

    # Touch the oldest so it becomes the most-recently-used entry.
    client._apk(files[0])
    assert calls["n"] == _CACHE_LIMIT  # a hit, not a re-parse

    # One more distinct APK tips the cache over the cap.
    extra = _apk_file(tmp_path, name="extra.apk", body=b"extra")
    client._apk(extra)

    keys = {key[0] for key in ApkClient._light_cache}
    assert len(ApkClient._light_cache) == _CACHE_LIMIT
    # The refreshed first APK is kept; the next-oldest (files[1]) is the eviction.
    assert str(files[0].resolve()) in keys
    assert str(files[1].resolve()) not in keys
    assert str(extra.resolve()) in keys


def test_release_drops_every_cached_parse_for_one_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """release clears both caches for one APK and reports whether it dropped anything.

    A closed session calls release so the process stops holding a fully-analysed
    DEX it will never read again. It must clear the light and full caches together
    (an agent may have both a manifest read and an analysis outstanding) and
    return False when there was nothing to drop, so a double close is not reported
    as having freed memory twice.
    """
    _install_apk_fake(monkeypatch)
    _install_analyze_fake(monkeypatch)
    client = ApkClient()
    apk = _apk_file(tmp_path)

    client._apk(apk)
    client._parsed(apk)
    assert len(ApkClient._light_cache) == 1
    assert len(ApkClient._full_cache) == 1

    assert ApkClient.release(apk) is True
    assert len(ApkClient._light_cache) == 0
    assert len(ApkClient._full_cache) == 0

    # Nothing left to drop: a second release is honest about freeing nothing.
    assert ApkClient.release(apk) is False


def test_full_analysis_cache_evicts_the_oldest_past_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The expensive DEX cache is capped independently of the light one.

    A full ``_ParsedApk`` is tens to hundreds of MB, so an unbounded full cache is
    the real memory leak the cap guards. The light-cache eviction is pinned above;
    this proves the ``_full_cache`` obeys the same bound -- filling it to the cap
    and analysing one more APK drops the oldest entry rather than growing without
    limit, so an agent that walks a directory of APKs cannot exhaust the process.
    """
    _install_analyze_fake(monkeypatch)
    client = ApkClient()
    files = [_apk_file(tmp_path, name=f"g{i}.apk", body=bytes([i])) for i in range(_CACHE_LIMIT)]
    for path in files:
        client._parsed(path)
    assert len(ApkClient._full_cache) == _CACHE_LIMIT

    extra = _apk_file(tmp_path, name="extra.apk", body=b"extra")
    client._parsed(extra)

    keys = {key[0] for key in ApkClient._full_cache}
    assert len(ApkClient._full_cache) == _CACHE_LIMIT
    # The first-inserted APK is the oldest and is evicted; the newest survives.
    assert str(files[0].resolve()) not in keys
    assert str(extra.resolve()) in keys


def test_release_reports_false_when_the_path_cannot_be_resolved() -> None:
    """A path that cannot be resolved frees nothing rather than crashing close.

    release runs on session close, and the path can be gone or unresolvable by
    then (a deleted temp dir, a broken symlink, an ELOOP). resolve() raising must
    answer False -- freed nothing -- not let an OSError escape and abort the
    session teardown that was only trying to reclaim memory.
    """

    class _UnresolvablePath:
        def expanduser(self) -> _UnresolvablePath:
            return self

        def resolve(self) -> Path:
            raise OSError("too many levels of symbolic links")

    assert ApkClient.release(_UnresolvablePath()) is False  # type: ignore[arg-type]
