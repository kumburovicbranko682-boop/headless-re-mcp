"""Device-free behaviour of the jadx adapter around the subprocess call.

test_jadx_path_safety.py already pins the containment guards (a class name or a
sources symlink that escapes the output root). What is exercised here is the
logic on either side of the one step that needs a real jadx: the tree summary
(_capped_java_listing), the export_sources envelope, the class-resolution
fallback inside decompile, and _run's own pre-launch guards. Every test stubs
the subprocess (or calls the pure helper directly), so none of it needs jadx or
a JRE installed.

The resolution fallback carries a real correctness contract worth pinning: when
the class file is not where the dotted name predicts, jadx used to return the
first same-named file it found anywhere in the tree -- whoever it emitted first,
not necessarily the class asked for. It now resolves a bare basename only when
exactly one file matches, and reports not_found when the match is ambiguous.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import headless_re_mcp.backends.jadx.client as jadx_client
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)


def _write(path: Path, data: bytes = b"class X {}\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _stub_tree(
    client: JadxClient, monkeypatch: pytest.MonkeyPatch, tree: dict[str, bytes]
) -> None:
    """Replace the subprocess step with one that materialises a fake output tree."""

    def _fake_run(
        apk: Path, extra: list[str], out_dir: Path, *, timeout: float
    ) -> tuple[str, str, int]:
        del apk, extra, timeout
        for rel, content in tree.items():
            _write(Path(out_dir) / rel, content)
        return "", "", 0

    monkeypatch.setattr(client, "_run", _fake_run)


# --- _capped_java_listing -------------------------------------------------


def test_listing_of_a_missing_root_is_empty_not_an_error(tmp_path: Path) -> None:
    names, total, has_more = _capped_java_listing(tmp_path / "nope", cap=10)
    assert names == []
    assert total == 0
    assert has_more is False


def test_listing_counts_every_file_but_returns_only_up_to_the_cap(tmp_path: Path) -> None:
    for name in ("c", "a", "b"):
        _write(tmp_path / "sources" / f"{name}.java")
    names, total, has_more = _capped_java_listing(tmp_path, cap=2)
    assert total == 3
    assert has_more is True
    # Capped to two, and the returned names are sorted so the page is stable
    # rather than filesystem-iteration order.
    assert names == sorted(names)
    assert len(names) == 2


def test_listing_skips_a_directory_that_merely_ends_in_dot_java(tmp_path: Path) -> None:
    # rglob("*.java") matches directories too; only real files must be counted.
    (tmp_path / "weird.java").mkdir()
    _write(tmp_path / "real" / "Main.java")
    names, total, has_more = _capped_java_listing(tmp_path, cap=10)
    assert total == 1
    assert has_more is False
    assert names == [str(Path("real") / "Main.java")]


# --- export_sources envelope ---------------------------------------------


def test_export_sources_summarises_the_written_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    _stub_tree(
        client,
        monkeypatch,
        {
            "sources/com/example/App.java": b"class App {}\n",
            "sources/com/example/Util.java": b"class Util {}\n",
        },
    )
    out = tmp_path / "out"
    data = client.export_sources(tmp_path / "app.apk", out)
    assert data["output_dir"] == str(out)
    assert data["sources_dir"] == str(out / "sources")
    assert data["java_file_count"] == 2
    assert data["has_more"] is False
    assert data["java_files"] == sorted(data["java_files"])


def test_export_sources_reports_no_sources_dir_when_jadx_wrote_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    # jadx wrote something, but not under sources/ -- sources_dir must be None
    # rather than a path that does not exist.
    _stub_tree(client, monkeypatch, {"resources/AndroidManifest.xml": b"<manifest/>"})
    out = tmp_path / "out"
    data = client.export_sources(tmp_path / "app.apk", out)
    assert data["sources_dir"] is None
    assert data["java_file_count"] == 0


# --- decompile class resolution ------------------------------------------


def test_decompile_requires_a_class_name(tmp_path: Path) -> None:
    # Refused before any decompile is attempted, so no stub is needed.
    client = JadxClient(tmp_path / "jadx")
    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", tmp_path / "out", "   ")
    assert caught.value.code == "invalid_params"


def test_decompile_returns_the_class_at_its_predicted_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    _stub_tree(
        client,
        monkeypatch,
        {"sources/com/example/App.java": b"class App { int x; }\n"},
    )
    out = tmp_path / "out"
    data = client.decompile(tmp_path / "app.apk", out, "com.example.App")
    assert data["class_name"] == "com.example.App"
    assert data["source"] == "class App { int x; }\n"
    assert data["truncated"] is False
    assert data["path"] == str(out / "sources" / "com" / "example" / "App.java")


def test_decompile_falls_back_to_a_unique_basename_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Predicted path (sources/Widget.java) is absent, but exactly one Widget.java
    # exists in the tree, so it resolves to that one.
    client = JadxClient(tmp_path / "jadx")
    _stub_tree(
        client,
        monkeypatch,
        {"sources/com/example/Widget.java": b"class Widget {}\n"},
    )
    out = tmp_path / "out"
    data = client.decompile(tmp_path / "app.apk", out, "Widget")
    assert data["path"] == str(out / "sources" / "com" / "example" / "Widget.java")


def test_decompile_refuses_an_ambiguous_basename_rather_than_guessing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two files share the basename and none sits at the predicted path, so the
    # request is ambiguous: report not_found instead of returning whichever jadx
    # emitted first.
    client = JadxClient(tmp_path / "jadx")
    _stub_tree(
        client,
        monkeypatch,
        {
            "sources/a/Model.java": b"class Model {} // a\n",
            "sources/b/Model.java": b"class Model {} // b\n",
        },
    )
    out = tmp_path / "out"
    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "Model")
    assert caught.value.code == "not_found"


def test_decompile_reports_not_found_when_the_class_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = JadxClient(tmp_path / "jadx")
    _stub_tree(client, monkeypatch, {"sources/com/example/App.java": b"class App {}\n"})
    out = tmp_path / "out"
    with pytest.raises(JadxError) as caught:
        client.decompile(tmp_path / "app.apk", out, "com.example.Missing")
    assert caught.value.code == "not_found"
    assert caught.value.details["class_name"] == "com.example.Missing"


def test_decompile_truncates_source_at_the_byte_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jadx_client, "_MAX_SOURCE_BYTES", 10)
    client = JadxClient(tmp_path / "jadx")
    _stub_tree(
        client,
        monkeypatch,
        {"sources/com/example/App.java": b"0123456789ABCDEF"},
    )
    out = tmp_path / "out"
    data = client.decompile(tmp_path / "app.apk", out, "com.example.App")
    assert data["truncated"] is True
    assert data["source"] == "0123456789"


# --- _run pre-launch guards ----------------------------------------------


def test_available_is_false_without_a_configured_executable(tmp_path: Path) -> None:
    assert JadxClient(None).available is False
    assert JadxClient(tmp_path / "absent").available is False
    assert JadxClient(_write(tmp_path / "jadx")).available is True


def test_run_degrades_when_jadx_is_not_configured(tmp_path: Path) -> None:
    # capability_unavailable, not a crash, when there is no executable to launch.
    client = JadxClient(None)
    with pytest.raises(JadxError) as caught:
        client._run(tmp_path / "app.apk", [], tmp_path / "out", timeout=1.0)
    assert caught.value.code == "capability_unavailable"


def test_run_reports_a_missing_apk_before_launching(tmp_path: Path) -> None:
    # executable exists (so available is True) but the apk does not: the guard
    # fails as not_found without ever reaching run_bounded.
    exe = _write(tmp_path / "jadx", b"#!/bin/sh\nexit 0\n")
    if os.name != "nt":
        exe.chmod(0o755)
    client = JadxClient(exe)
    with pytest.raises(JadxError) as caught:
        client._run(tmp_path / "missing.apk", [], tmp_path / "out", timeout=1.0)
    assert caught.value.code == "not_found"
    assert caught.value.details["path"] == str(tmp_path / "missing.apk")
