"""JadxClient listing, decompile fallback and the _run deadline mapping.

The field-shape tests pin what ``apk.decompile`` / ``apk.export_sources`` answer
with. What is covered here is the machinery around them: the bounded Java-file
listing (an empty root, a directory that happens to end in ``.java``, the
counted-file ceiling), the single-class fallback that only accepts an
unambiguous simple-name match, and ``_run`` mapping a missing tool, a missing
apk, a blown deadline and a failed launch to their structured codes. No real
jadx or JVM is ever spawned.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError, _capped_java_listing


def _executable(path: Path) -> Path:
    path.write_text("x\n", encoding="utf-8")
    return path


def _apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    return path


# --------------------------------------------------------------------------
# _capped_java_listing
# --------------------------------------------------------------------------
def test_listing_is_empty_for_a_missing_root(tmp_path: Path) -> None:
    assert _capped_java_listing(tmp_path / "nope", cap=10) == ([], 0, False)


def test_listing_ignores_a_directory_named_like_a_java_file(tmp_path: Path) -> None:
    """rglob('*.java') can match a directory; only real files are counted."""
    (tmp_path / "weird.java").mkdir()
    (tmp_path / "Real.java").write_text("class Real {}", encoding="utf-8")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert names == ["Real.java"]
    assert total == 1
    assert has_more is False


def test_listing_stops_at_the_counted_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 2)
    for index in range(3):
        (tmp_path / f"C{index}.java").write_text("class C {}", encoding="utf-8")
    _, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert total == 2
    assert has_more is True


# --------------------------------------------------------------------------
# decompile guards + fallback
# --------------------------------------------------------------------------
def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    with pytest.raises(JadxError) as caught:
        client.decompile(_apk(tmp_path / "a.apk"), tmp_path / "out", "   ")
    assert caught.value.code == "invalid_params"


def test_decompile_finds_a_unique_simple_name_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When jadx emits a class at an unexpected package path, a lone name match wins."""
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "out"
    sources = out / "sources"
    (sources / "other").mkdir(parents=True)
    (sources / "other" / "Bar.java").write_text("class Bar { int x; }", encoding="utf-8")
    # A directory with the same base name must be skipped, not treated as a match.
    (sources / "decoy" / "Bar.java").mkdir(parents=True)

    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {"ok": True})
    payload = client.decompile(apk, out, "com.example.Bar")
    assert payload["class_name"] == "com.example.Bar"
    assert "class Bar" in payload["source"]


def test_decompile_refuses_an_ambiguous_simple_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two files with the same base name are not a confident match: not_found."""
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "out"
    sources = out / "sources"
    (sources / "a").mkdir(parents=True)
    (sources / "b").mkdir(parents=True)
    (sources / "a" / "Bar.java").write_text("class Bar {}", encoding="utf-8")
    (sources / "b" / "Bar.java").write_text("class Bar {}", encoding="utf-8")

    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {"ok": True})
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Bar")
    assert caught.value.code == "not_found"


def test_decompile_reports_not_found_when_no_sources_were_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _apk(tmp_path / "a.apk")
    out = tmp_path / "out"
    out.mkdir()
    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    monkeypatch.setattr(client, "export_sources", lambda *a, **k: {"ok": True})
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.Foo")
    assert caught.value.code == "not_found"


# --------------------------------------------------------------------------
# _run mapping
# --------------------------------------------------------------------------
def test_run_refuses_when_jadx_is_unconfigured(tmp_path: Path) -> None:
    client = JadxClient(None)
    with pytest.raises(JadxError) as caught:
        client.export_sources(_apk(tmp_path / "a.apk"), tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_run_reports_a_missing_apk(tmp_path: Path) -> None:
    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "missing.apk", tmp_path / "out")
    assert caught.value.code == "not_found"


def test_run_maps_a_deadline_to_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _timed_out(*args: Any, **kwargs: Any) -> Completed:
        raise TimedOut(300.0, [999])

    monkeypatch.setattr(jadx_client, "run_bounded", _timed_out)
    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    with pytest.raises(JadxError) as caught:
        client.export_sources(_apk(tmp_path / "a.apk"), tmp_path / "out")
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [999]


def test_run_maps_a_launch_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _no_exec(*args: Any, **kwargs: Any) -> Completed:
        raise OSError("cannot execute")

    monkeypatch.setattr(jadx_client, "run_bounded", _no_exec)
    client = JadxClient(_executable(tmp_path / "jadx.bat"))
    with pytest.raises(JadxError) as caught:
        client.export_sources(_apk(tmp_path / "a.apk"), tmp_path / "out")
    assert caught.value.code == "backend_error"
