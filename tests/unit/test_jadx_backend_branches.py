"""Branch coverage for the jadx decompiler subprocess backend.

jadx routinely exits non-zero on a per-class failure while still emitting a
usable tree, so the adapter keeps partial output and flags it rather than
failing; a missing tool degrades to capability_unavailable; and class lookup
resolves the exact package path first, falling back to a unique simple-name
match only when that path is absent (never guessing among duplicates). These
fakes drive the listing, lookup, and degradation branches without a JRE; the
live gate (tests/integration/test_android_re_gate.py) pins the real tool.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import client as jadx_client
from headless_re_mcp.backends.jadx.client import (
    JadxClient,
    JadxError,
    _capped_java_listing,
)

MP = pytest.MonkeyPatch
_EXE = Path(sys.executable)


def _install(monkeypatch: MP, handler: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def _fake(cmd: list[str], *, timeout: float, creationflags: int = 0) -> Completed:
        calls.append({"cmd": list(cmd), "timeout": timeout})
        return handler(list(cmd))

    monkeypatch.setattr(jadx_client, "run_bounded", _fake)
    return calls


def _make_source(out_dir: Path, rel: str, body: str = "class X {}") -> Path:
    dest = out_dir / "sources" / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body)
    return dest


class TestCappedListing:
    def test_missing_root_is_empty(self, tmp_path: Path) -> None:
        assert _capped_java_listing(tmp_path / "nope", cap=10) == ([], 0, False)

    def test_directories_named_java_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "weird.java").mkdir()  # a directory, not a source file
        (tmp_path / "real.java").write_text("class R {}")
        names, total, has_more = _capped_java_listing(tmp_path, cap=10)
        assert names == ["real.java"]
        assert total == 1
        assert has_more is False

    def test_listing_cap_flags_has_more(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"F{i}.java").write_text("x")
        names, total, has_more = _capped_java_listing(tmp_path, cap=2)
        assert len(names) == 2
        assert total == 3
        assert has_more is True

    def test_counted_cap_stops_the_walk(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(jadx_client, "_MAX_COUNTED_FILES", 1)
        (tmp_path / "A.java").write_text("x")
        (tmp_path / "B.java").write_text("x")
        names, total, has_more = _capped_java_listing(tmp_path, cap=10)
        assert total == 1
        assert has_more is True
        assert len(names) == 1


class TestRunGuards:
    def test_export_needs_jadx(self, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=None).export_sources(apk, tmp_path / "out")
        assert excinfo.value.code == "capability_unavailable"

    def test_export_reports_a_missing_apk(self, tmp_path: Path) -> None:
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).export_sources(tmp_path / "gone.apk", tmp_path / "out")
        assert excinfo.value.code == "not_found"

    def test_export_rejects_a_bad_timeout(self, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).export_sources(apk, tmp_path / "out", timeout=0)
        assert excinfo.value.code == "invalid_params"

    def test_export_maps_a_timeout(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")

        def _boom(_cmd: list[str]) -> Completed:
            raise TimedOut(5.0, killed=[9])

        _install(monkeypatch, _boom)
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).export_sources(apk, tmp_path / "out")
        assert excinfo.value.code == "timeout"
        assert excinfo.value.details.get("killed_pids") == [9]

    def test_export_maps_a_launch_oserror(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")

        def _boom(_cmd: list[str]) -> Completed:
            raise PermissionError("not executable")

        _install(monkeypatch, _boom)
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).export_sources(apk, tmp_path / "out")
        assert excinfo.value.code == "backend_error"

    def test_export_fails_hard_when_nothing_lands(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        _install(
            monkeypatch, lambda cmd: Completed(returncode=1, stdout=b"", stderr=b"jadx died")
        )
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).export_sources(apk, tmp_path / "out")
        assert excinfo.value.code == "backend_error"


class TestExportSources:
    def test_export_summarizes_a_clean_tree(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            _make_source(out_dir, "com/example/Foo.java")
            _make_source(out_dir, "com/example/Bar.java")
            return Completed(returncode=0, stdout=b"done", stderr=b"")

        calls = _install(monkeypatch, _handler)
        result = JadxClient(executable=_EXE).export_sources(apk, out_dir, no_imports=True)
        assert result["java_file_count"] == 2
        assert result["sources_dir"].endswith("sources")
        assert "tool_failed" not in result
        assert "--no-imports" in calls[0]["cmd"]

    def test_export_flags_a_partial_decompile(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            _make_source(out_dir, "com/example/Foo.java")
            return Completed(returncode=1, stdout=b"", stderr=b"class Bar failed")

        _install(monkeypatch, _handler)
        result = JadxClient(executable=_EXE).export_sources(apk, out_dir)
        assert result["tool_failed"] is True
        assert result["exit_code"] == 1
        assert "class Bar failed" in result["stderr"]


class TestDecompile:
    def test_decompile_requires_a_class_name(self, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, tmp_path / "out", "   ")
        assert excinfo.value.code == "invalid_params"

    def test_decompile_returns_the_named_class(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            _make_source(out_dir, "com/example/Foo.java", body="class Foo { int x; }")
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        result = JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert result["class_name"] == "com.example.Foo"
        assert "class Foo" in result["source"]
        assert result["truncated"] is False

    def test_decompile_falls_back_to_a_unique_simple_name(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            # jadx emitted the class under a different package than requested.
            _make_source(out_dir, "org/other/Foo.java", body="class Foo {}")
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        result = JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert result["path"].endswith("org/other/Foo.java")

    def test_decompile_refuses_to_guess_among_duplicates(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            _make_source(out_dir, "a/Foo.java")
            _make_source(out_dir, "b/Foo.java")
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert excinfo.value.code == "not_found"

    def test_decompile_not_found_when_nothing_matches(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            _make_source(out_dir, "org/other/Bar.java")
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert excinfo.value.code == "not_found"

    def test_decompile_wraps_a_read_failure(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"
        # Stage the tree up front so the patched open below only affects the
        # source read, not the handler writing files during export.
        _make_source(out_dir, "Foo.java")
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"", stderr=b""))

        real_open = Path.open

        def _fake_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self.name == "Foo.java":
                raise OSError("read blew up")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", _fake_open)
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, out_dir, "Foo")
        assert excinfo.value.code == "backend_error"
        assert "failed to read source" in str(excinfo.value)

    def test_decompile_skips_a_match_that_cannot_resolve(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"
        sources = out_dir / "sources"
        sources.mkdir(parents=True)
        loop = sources / "Foo.java"
        loop.symlink_to(loop)  # a self-referential link: resolve() raises
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"", stderr=b""))
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert excinfo.value.code == "not_found"

    def test_decompile_skips_a_match_outside_the_tree(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"
        sources = out_dir / "sources"
        sources.mkdir(parents=True)
        outside = tmp_path / "outside.java"
        outside.write_text("class Foo {}")
        (sources / "Foo.java").symlink_to(outside)  # resolves outside sources
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"", stderr=b""))
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert excinfo.value.code == "not_found"

    def test_decompile_not_found_without_a_sources_dir(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            # jadx wrote java files, but not under a "sources" subtree.
            top = out_dir / "Foo.java"
            top.parent.mkdir(parents=True, exist_ok=True)
            top.write_text("class Foo {}")
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        with pytest.raises(JadxError) as excinfo:
            JadxClient(executable=_EXE).decompile(apk, out_dir, "Foo")
        assert excinfo.value.code == "not_found"

    def test_decompile_carries_the_partial_verdict(self, tmp_path: Path, monkeypatch: MP) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        out_dir = tmp_path / "out"

        def _handler(cmd: list[str]) -> Completed:
            _make_source(out_dir, "com/example/Foo.java", body="class Foo {}")
            return Completed(returncode=1, stdout=b"", stderr=b"some classes failed")

        _install(monkeypatch, _handler)
        result = JadxClient(executable=_EXE).decompile(apk, out_dir, "com.example.Foo")
        assert result["tool_failed"] is True
        assert result["exit_code"] == 1
