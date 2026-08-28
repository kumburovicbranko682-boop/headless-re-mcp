"""jadx fallback resolution and subprocess guard paths behave as promised.

apk.decompile resolves a class to its expected package path first, and only
then falls back to a simple-name walk of the jadx tree -- accepting the file
only when the walk is unambiguous. These lock in that fallback contract (a
unique match wins, decoys that are not regular files or cannot be resolved are
skipped, a missing tree or ambiguity is ``not_found``), the bounded listing's
edge behavior (missing root, non-file matches, the counted-files ceiling), and
``_run``'s error mapping (``capability_unavailable`` without a configured
executable, ``not_found`` for a missing APK, ``timeout`` and launch failures).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import client as jadx_mod
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)

_RUN_BOUNDED = "headless_re_mcp.backends.jadx.client.run_bounded"


def _jadx(tmp_path: Path) -> tuple[JadxClient, Path, Path]:
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    out = tmp_path / "out"
    return JadxClient(tool), apk, out


def _writes(out: Path, *rel_files: str) -> Callable[..., Completed]:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        out.mkdir(parents=True, exist_ok=True)
        for rel in rel_files:
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"class {target.stem} {{}}", encoding="utf-8")
        return Completed(0, b"", b"")

    return fake_run


def test_listing_a_missing_root_is_empty(tmp_path: Path) -> None:
    names, total, has_more = _capped_java_listing(tmp_path / "absent", cap=10)

    assert names == []
    assert total == 0
    assert has_more is False


def test_listing_skips_a_directory_named_like_a_java_file(tmp_path: Path) -> None:
    (tmp_path / "Fake.java").mkdir()
    (tmp_path / "Real.java").write_text("class Real {}", encoding="utf-8")

    names, total, has_more = _capped_java_listing(tmp_path, cap=10)

    assert names == ["Real.java"]
    assert total == 1
    assert has_more is False


def test_listing_stops_counting_at_the_file_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_mod, "_MAX_COUNTED_FILES", 2)
    for index in range(3):
        (tmp_path / f"C{index}.java").write_text("class C {}", encoding="utf-8")

    names, total, has_more = _capped_java_listing(tmp_path, cap=10)

    assert total == 2
    assert len(names) == 2
    assert has_more is True


def test_listing_returns_the_alphabetical_head_not_the_walk_order_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tree past the cap returns the alphabetically-first files, not walk order.

    rglob yields in undefined, platform-dependent filesystem order. The old code
    appended the first `cap` files in that order and sorted only those, so the
    preview looked sorted but was a walk-order-arbitrary subset -- alphabetically-
    early files walked after the cap were silently dropped, and the page could
    differ between two decompiles of the same APK. Here the walk hands files back
    reverse-sorted, so a cap of three must still be a.java/b.java/c.java (the real
    head), not c/m/z (the reverse-order prefix alphabetized). This is the same
    sort-before-window contract adb.packages and apk.classes keep.
    """
    for name in ("a", "b", "c", "m", "z"):
        (tmp_path / f"{name}.java").write_text("class C {}", encoding="utf-8")
    walk_order = sorted(tmp_path.glob("*.java"), key=lambda p: p.name, reverse=True)
    monkeypatch.setattr(jadx_mod.Path, "rglob", lambda self, *a, **k: iter(walk_order))

    names, total, has_more = _capped_java_listing(tmp_path, cap=3)

    assert names == ["a.java", "b.java", "c.java"]
    assert total == 5
    assert has_more is True


def test_decompile_rejects_a_blank_class_name(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "   ")

    assert caught.value.code == "invalid_params"


def test_decompile_falls_back_to_a_unique_simple_name_match(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/pkg/Main.java")

    def fake_with_decoy(cmd: list[str], **kwargs: Any) -> Completed:
        completed = fake_run(cmd, **kwargs)
        # A directory named like the class file must not count as a match.
        (out / "sources" / "decoy" / "Main.java").mkdir(parents=True)
        return completed

    with patch(_RUN_BOUNDED, fake_with_decoy):
        payload = client.decompile(apk, out, "com.example.Main")

    assert payload["source"] == "class Main {}"
    assert payload["path"] == str(out / "sources" / "pkg" / "Main.java")


def test_decompile_reports_the_on_disk_size_as_bytes(tmp_path: Path) -> None:
    """A class that fits carries bytes equal to its on-disk size, not truncated.

    bytes is the full size fstat measured, so a caller reads the class's true
    scale -- the same signal web.script.source carries -- even though the read
    is bounded to keep a huge class out of memory.
    """
    client, apk, out = _jadx(tmp_path)

    with patch(_RUN_BOUNDED, _writes(out, "sources/pkg/Main.java")):
        payload = client.decompile(apk, out, "com.example.Main")

    assert payload["source"] == "class Main {}"
    assert payload["bytes"] == len(b"class Main {}")
    assert payload["truncated"] is False


def test_decompile_skips_a_match_that_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _jadx(tmp_path)
    real_resolve = Path.resolve

    def failing_resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        if self.name == "Main.java" and "decoy" in self.parts:
            raise OSError("resolve failed")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", failing_resolve)

    with (
        patch(_RUN_BOUNDED, _writes(out, "sources/decoy/Main.java")),
        pytest.raises(JadxError) as caught,
    ):
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details["class_name"] == "com.example.Main"


def test_decompile_is_not_found_when_the_name_is_ambiguous(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    fake_run = _writes(out, "sources/a/Main.java", "sources/b/Main.java")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"
    assert caught.value.details["expected"] == str(Path("com", "example", "Main.java"))


def test_decompile_is_not_found_when_jadx_wrote_no_sources_tree(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)
    # A stray file outside sources/ keeps _run happy but leaves no tree to walk.
    fake_run = _writes(out, "Stray.java")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "not_found"


def test_decompile_maps_an_unreadable_source_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _jadx(tmp_path)
    real_open = Path.open

    def failing_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".java" and "b" in mode:
            raise OSError("read failed")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    with (
        patch(_RUN_BOUNDED, _writes(out, "sources/com/example/Main.java")),
        pytest.raises(JadxError) as caught,
    ):
        client.decompile(apk, out, "com.example.Main")

    assert caught.value.code == "backend_error"
    assert "failed to read source" in caught.value.message


def test_run_without_a_configured_executable_is_capability_unavailable(
    tmp_path: Path,
) -> None:
    client = JadxClient(None)

    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "app.apk", tmp_path / "out")

    assert caught.value.code == "capability_unavailable"


def test_run_with_a_missing_apk_is_not_found(tmp_path: Path) -> None:
    client, _, out = _jadx(tmp_path)

    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "missing.apk", out)

    assert caught.value.code == "not_found"
    assert caught.value.details["path"] == str(tmp_path / "missing.apk")


def test_run_maps_a_timed_out_jadx_to_timeout(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(5.0, killed=[123])

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.export_sources(apk, out, timeout=5.0)

    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [123]


def test_run_maps_a_launch_failure_to_backend_error(tmp_path: Path) -> None:
    client, apk, out = _jadx(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("exec format error")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JadxError) as caught:
        client.export_sources(apk, out)

    assert caught.value.code == "backend_error"
    assert "failed to launch jadx" in caught.value.message
