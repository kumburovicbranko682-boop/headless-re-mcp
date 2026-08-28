"""Guard, listing and fallback branches of the jadx decompiler adapter.

The existing jadx tests pin the partial-decompile signalling and the path-safety
rejections. This file fills in the branches those step over: the capped Java
listing (non-dir root, directory-named-like-a-source, counted ceiling), the
single-class simple-name fallback (unique match, no match, no sources tree, an
unreadable source), the empty class_name guard, and the availability /
missing-apk / timeout / launch-failure guards on the bounded run. Each test
pins one branch; no jadx binary is spawned -- `run_bounded` (or export_sources)
is faked at the seam.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.backends.jadx import client as jadxmod
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)


def _client_apk_out(tmp_path: Path) -> tuple[JadxClient, Path, Path]:
    tool = tmp_path / "jadx"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    return JadxClient(tool), apk, tmp_path / "out"


# ---------------------------------------------------------------------------
# _capped_java_listing.
# ---------------------------------------------------------------------------
def test_capped_listing_returns_empty_for_a_non_dir_root(tmp_path: Path) -> None:
    assert _capped_java_listing(tmp_path / "absent", cap=10) == ([], 0, False)


def test_capped_listing_skips_a_directory_named_like_a_source(tmp_path: Path) -> None:
    """A directory whose name ends in .java is counted as neither file nor name."""
    root = tmp_path / "r"
    root.mkdir()
    (root / "weird.java").mkdir()
    (root / "Real.java").write_text("class Real {}", encoding="utf-8")
    names, total, has_more = _capped_java_listing(root, cap=10)
    assert names == ["Real.java"]
    assert total == 1
    assert has_more is False


def test_capped_listing_marks_names_beyond_the_cap(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    for i in range(3):
        (root / f"C{i}.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(root, cap=2)
    assert len(names) == 2
    assert total == 3
    assert has_more is True


def test_capped_listing_stops_at_the_counted_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadxmod, "_MAX_COUNTED_FILES", 2)
    root = tmp_path / "r"
    root.mkdir()
    for i in range(3):
        (root / f"C{i}.java").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_java_listing(root, cap=100)
    assert total == 2
    assert has_more is True
    assert len(names) == 2


# ---------------------------------------------------------------------------
# decompile: class_name guard and simple-name fallback.
# ---------------------------------------------------------------------------
def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    client, apk, out = _client_apk_out(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "   ")
    assert caught.value.code == "invalid_params"


def test_decompile_finds_a_unique_simple_name_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the expected path is absent, a single same-named file is accepted.

    jadx may emit a class under a package that differs from the dotted name the
    caller gave; a unique filename match resolves it, while a directory that
    merely shares the name is skipped rather than mistaken for the source.
    """
    client, apk, out = _client_apk_out(tmp_path)
    src = out / "sources" / "other"
    src.mkdir(parents=True)
    (src / "Main.java").write_text("class Main {}", encoding="utf-8")
    (out / "sources" / "pkg" / "Main.java").mkdir(parents=True)
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    payload = client.decompile(apk, out, "com.example.Main")
    assert payload["source"] == "class Main {}"
    assert payload["path"].endswith(str(Path("other") / "Main.java"))


@pytest.mark.skipif(os.name == "nt", reason="creating test symlinks needs Windows privileges")
def test_decompile_skips_an_unresolvable_candidate_during_the_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A symlink loop met during the fallback walk is skipped, not fatal.

    resolve() raises on a self-referencing link; the walk continues and the one
    real file still wins.
    """
    client, apk, out = _client_apk_out(tmp_path)
    src = out / "sources" / "other"
    src.mkdir(parents=True)
    (src / "Main.java").write_text("class Main {}", encoding="utf-8")
    loop_dir = out / "sources" / "loop"
    loop_dir.mkdir(parents=True)
    os.symlink("Main.java", loop_dir / "Main.java")
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    payload = client.decompile(apk, out, "com.example.Main")
    assert payload["source"] == "class Main {}"
    assert payload["path"].endswith(str(Path("other") / "Main.java"))


def test_decompile_reports_not_found_when_no_class_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _client_apk_out(tmp_path)
    src = out / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Other.java").write_text("class Other {}", encoding="utf-8")
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Nope")
    assert caught.value.code == "not_found"


def test_decompile_reports_not_found_without_a_sources_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _client_apk_out(tmp_path)
    out.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")
    assert caught.value.code == "not_found"


def test_decompile_wraps_an_unreadable_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _client_apk_out(tmp_path)
    src = out / "sources" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Main.java").write_text("class Main {}", encoding="utf-8")
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    real_open = Path.open

    def flaky_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".java" and "r" in mode and "b" in mode:
            raise OSError("read denied")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", flaky_open)
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Main")
    assert caught.value.code == "backend_error"
    assert "failed to read source" in caught.value.message


# ---------------------------------------------------------------------------
# _run guards.
# ---------------------------------------------------------------------------
def test_run_without_jadx_is_capability_unavailable(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    client = JadxClient(None)
    with pytest.raises(JadxError) as caught:
        client.export_sources(apk, tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    client, apk, out = _client_apk_out(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.export_sources(apk, out, timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_reports_a_missing_apk(tmp_path: Path) -> None:
    client, _apk, out = _client_apk_out(tmp_path)
    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "absent.apk", out)
    assert caught.value.code == "not_found"


def test_run_reports_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, apk, out = _client_apk_out(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [77])

    monkeypatch.setattr(jadxmod, "run_bounded", fake_run)
    with pytest.raises(JadxError) as caught:
        client.export_sources(apk, out)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [77]


def test_run_wraps_a_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, apk, out = _client_apk_out(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("not executable")

    monkeypatch.setattr(jadxmod, "run_bounded", fake_run)
    with pytest.raises(JadxError) as caught:
        client.export_sources(apk, out)
    assert caught.value.code == "backend_error"
    assert "failed to launch jadx" in caught.value.message
