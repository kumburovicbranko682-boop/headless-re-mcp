"""Listing, decompile-resolution, and _run guard paths for the jadx client.

The partial-decompile signalling and the path-safety refusals already live in
``test_jadx_partial_decompile.py`` / ``test_jadx_path_safety.py``. This file
covers what they skip: the ``_capped_java_listing`` edges (missing root,
non-file match, counted cap), the ``decompile`` simple-name fallback and its
not-found arm, and ``_run``'s capability/not-found/timeout/launch mappings.
``export_sources`` is stubbed and the tree hand-built so no real jadx runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.backends.jadx import client as jadx_mod
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# _capped_java_listing
# ---------------------------------------------------------------------------


def test_capped_listing_returns_empty_for_a_missing_root(tmp_path: Path) -> None:
    assert _capped_java_listing(tmp_path / "nope", cap=10) == ([], 0, False)


def test_capped_listing_skips_a_directory_named_like_a_source(tmp_path: Path) -> None:
    root = tmp_path / "out"
    root.mkdir()
    (root / "pkg.java").mkdir()  # a directory whose name matches *.java
    (root / "A.java").write_text("class A {}", encoding="utf-8")
    names, total, has_more = _capped_java_listing(root, cap=10)
    assert names == ["A.java"]
    assert total == 1
    assert has_more is False


def test_capped_listing_stops_at_the_counted_ceiling(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(jadx_mod, "_MAX_COUNTED_FILES", 2)
    root = tmp_path / "out"
    root.mkdir()
    for index in range(3):
        (root / f"C{index}.java").write_text("class C {}", encoding="utf-8")
    _names, total, has_more = _capped_java_listing(root, cap=10)
    assert total == 2
    assert has_more is True


def test_capped_listing_flags_more_when_over_the_display_cap(tmp_path: Path) -> None:
    root = tmp_path / "out"
    root.mkdir()
    for index in range(5):
        (root / f"C{index}.java").write_text("class C {}", encoding="utf-8")
    names, total, has_more = _capped_java_listing(root, cap=2)
    assert len(names) == 2
    assert total == 5
    assert has_more is True


# ---------------------------------------------------------------------------
# decompile resolution
# ---------------------------------------------------------------------------


def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(JadxError) as raised:
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "   ")
    assert raised.value.code == "invalid_params"


def test_decompile_reports_not_found_when_no_sources_tree_exists(
    tmp_path: Path, monkeypatch: Any
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    client = JadxClient(_executable(tmp_path / "jadx"))
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    with pytest.raises(JadxError) as raised:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")
    assert raised.value.code == "not_found"


def test_decompile_falls_back_to_a_unique_basename_match(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """When the exact path is absent, a single same-named file is accepted,
    while a directory of the same name is skipped rather than chosen."""
    out = tmp_path / "out"
    sources = out / "sources"
    sources.mkdir(parents=True)
    (sources / "decoydir" / "Main.java").mkdir(parents=True)  # not a file: skipped
    real = sources / "real" / "Main.java"
    real.parent.mkdir(parents=True)
    real.write_text("class Main {}", encoding="utf-8")

    client = JadxClient(_executable(tmp_path / "jadx"))
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    result = client.decompile(tmp_path / "app.apk", out, "com.example.Main")

    assert result["source"] == "class Main {}"
    assert result["path"].endswith(str(Path("real") / "Main.java"))
    assert result["truncated"] is False


def test_decompile_reports_not_found_on_an_ambiguous_basename(
    tmp_path: Path, monkeypatch: Any
) -> None:
    out = tmp_path / "out"
    sources = out / "sources"
    for pkg in ("a", "b"):
        target = sources / pkg / "Main.java"
        target.parent.mkdir(parents=True)
        target.write_text("class Main {}", encoding="utf-8")

    client = JadxClient(_executable(tmp_path / "jadx"))
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {})
    with pytest.raises(JadxError) as raised:
        client.decompile(tmp_path / "app.apk", out, "com.example.Main")
    assert raised.value.code == "not_found"


def test_decompile_propagates_export_failure_fields(
    tmp_path: Path, monkeypatch: Any
) -> None:
    out = tmp_path / "out"
    candidate = out / "sources" / "com" / "example" / "Main.java"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("class Main {}", encoding="utf-8")

    client = JadxClient(_executable(tmp_path / "jadx"))
    monkeypatch.setattr(
        client,
        "export_sources",
        lambda *a, **k: {"exit_code": 1, "tool_failed": True, "stderr": "boom"},
    )
    result = client.decompile(tmp_path / "app.apk", out, "com.example.Main")
    assert result["source"] == "class Main {}"
    assert result["exit_code"] == 1
    assert result["tool_failed"] is True
    assert result["stderr"] == "boom"


# ---------------------------------------------------------------------------
# _run
# ---------------------------------------------------------------------------


def test_run_refuses_without_jadx(tmp_path: Path) -> None:
    client = JadxClient(None)
    with pytest.raises(JadxError) as raised:
        client._run(tmp_path / "app.apk", [], tmp_path / "out", timeout=5.0)
    assert raised.value.code == "capability_unavailable"


def test_run_reports_a_missing_apk(tmp_path: Path) -> None:
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(JadxError) as raised:
        client._run(tmp_path / "missing.apk", [], tmp_path / "out", timeout=5.0)
    assert raised.value.code == "not_found"


def test_run_maps_a_timeout(tmp_path: Path, monkeypatch: Any) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [909])

    monkeypatch.setattr(jadx_mod, "run_bounded", boom)
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(JadxError) as raised:
        client._run(apk, [], tmp_path / "out", timeout=5.0)
    assert raised.value.code == "timeout"
    assert raised.value.details["killed_pids"] == [909]


def test_run_maps_a_launch_failure(tmp_path: Path, monkeypatch: Any) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("cannot exec")

    monkeypatch.setattr(jadx_mod, "run_bounded", boom)
    client = JadxClient(_executable(tmp_path / "jadx"))
    with pytest.raises(JadxError) as raised:
        client._run(apk, [], tmp_path / "out", timeout=5.0)
    assert raised.value.code == "backend_error"


# ---------------------------------------------------------------------------
# JadxError
# ---------------------------------------------------------------------------


def test_jadx_error_is_a_runtime_error_carrying_code_and_details() -> None:
    err = JadxError("not_found", "gone", class_name="x")
    assert isinstance(err, RuntimeError)
    assert err.code == "not_found"
    assert err.details["class_name"] == "x"
