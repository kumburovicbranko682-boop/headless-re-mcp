"""Ghidra export bounds: a cut decompile must not look complete."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import (
    _MAX_ANALYZE_EXCERPT,
    _MAX_DECOMPILE_CHARS,
    GhidraClient,
    _disclose_decompile,
    _page_export,
)


def _client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]
) -> dict[str, Any]:
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    project = tmp_path / "proj"
    analyze = tmp_path / "analyzeHeadless"
    analyze.write_text("x", encoding="utf-8")

    def fake_run(self: GhidraClient, project_dir: Path, **kwargs: object) -> tuple[str, str, int]:
        out = project_dir / "export_decompile.json"
        out.write_text(json.dumps(payload), encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(GhidraClient, "_run_headless", fake_run)
    client = GhidraClient(home=tmp_path, java=tmp_path / "java")
    client.analyze = analyze
    return client.decompile(binary, project, "0x1000")


def _functions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
    *,
    limit: int = 256,
) -> dict[str, Any]:
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    project = tmp_path / "proj"
    analyze = tmp_path / "analyzeHeadless"
    analyze.write_text("x", encoding="utf-8")

    def fake_run(self: GhidraClient, project_dir: Path, **kwargs: object) -> tuple[str, str, int]:
        out = project_dir / "export_functions.json"
        out.write_text(json.dumps(payload), encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(GhidraClient, "_run_headless", fake_run)
    client = GhidraClient(home=tmp_path, java=tmp_path / "java")
    client.analyze = analyze
    return client.functions(binary, project, limit=limit)


class TestGhidraSaysWhenADecompileWasCut:
    """250_000 characters used to come back as 200_000 with no truncated flag."""

    def test_an_old_script_cut_at_the_cap_is_marked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _client(
            tmp_path,
            monkeypatch,
            {"mode": "decompile", "decompiled": "A" * _MAX_DECOMPILE_CHARS, "count": 0},
        )
        assert result["truncated"] is True
        assert len(result["decompiled"]) == _MAX_DECOMPILE_CHARS
        assert result["bytes"] == _MAX_DECOMPILE_CHARS

    def test_a_longer_original_keeps_its_byte_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _client(
            tmp_path,
            monkeypatch,
            {
                "mode": "decompile",
                "decompiled": "B" * (_MAX_DECOMPILE_CHARS + 50_000),
                "truncated": True,
                "bytes": _MAX_DECOMPILE_CHARS + 50_000,
                "count": 0,
            },
        )
        assert result["truncated"] is True
        assert len(result["decompiled"]) == _MAX_DECOMPILE_CHARS
        assert result["bytes"] == _MAX_DECOMPILE_CHARS + 50_000

    def test_a_short_decompile_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _client(
            tmp_path,
            monkeypatch,
            {"mode": "decompile", "decompiled": "int main() { return 0; }", "count": 0},
        )
        assert result["truncated"] is False
        assert result["decompiled"] == "int main() { return 0; }"
        assert result["bytes"] == len("int main() { return 0; }")

    def test_disclose_helper_marks_a_cap_fill_without_a_flag(self) -> None:
        payload = _disclose_decompile(
            {"decompiled": "C" * _MAX_DECOMPILE_CHARS}
        )
        assert payload["truncated"] is True
        assert payload["bytes"] == _MAX_DECOMPILE_CHARS


class TestGhidraSaysWhenTheExportIsOnlyAPage:
    """500 functions with limit=256 used to come back as count=256, no has_more."""

    def test_a_list_past_the_page_reports_more(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        items = [{"name": f"f{index}"} for index in range(257)]
        result = _functions(
            tmp_path,
            monkeypatch,
            {"mode": "functions", "items": items, "count": 257},
            limit=256,
        )
        assert result["count"] == 256
        assert len(result["items"]) == 256
        assert result["limit"] == 256
        assert result["has_more"] is True

    def test_a_list_that_fits_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        items = [{"name": "main"}, {"name": "init"}]
        result = _functions(
            tmp_path,
            monkeypatch,
            {"mode": "functions", "items": items, "count": 2, "has_more": False},
            limit=256,
        )
        assert result["count"] == 2
        assert result["has_more"] is False

    def test_a_script_flag_survives_an_exact_page(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        items = [{"name": f"f{index}"} for index in range(256)]
        result = _functions(
            tmp_path,
            monkeypatch,
            {"mode": "functions", "items": items, "count": 256, "has_more": True},
            limit=256,
        )
        assert result["count"] == 256
        assert result["has_more"] is True

    def test_page_helper_keeps_an_exact_fill_complete(self) -> None:
        payload = _page_export(
            {"items": [{"name": "a"}, {"name": "b"}], "count": 2},
            limit=2,
        )
        assert payload["has_more"] is False
        assert payload["count"] == 2


def _analyze(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str
) -> dict[str, Any]:
    binary = tmp_path / "a.bin"
    binary.write_bytes(b"MZ")
    project = tmp_path / "proj"
    analyze = tmp_path / "analyzeHeadless"
    analyze.write_text("x", encoding="utf-8")

    def fake_run(self: GhidraClient, project_dir: Path, **kwargs: object) -> tuple[str, str, int]:
        return stdout, "", 0

    monkeypatch.setattr(GhidraClient, "_run_headless", fake_run)
    client = GhidraClient(home=tmp_path, java=tmp_path / "java")
    client.analyze = analyze
    return client.analyze_binary(binary, project)


class TestGhidraSaysWhenTheAnalyzeLogWasCut:
    """20000 characters of analyze log used to come back as an 8000-char excerpt."""

    def test_a_long_log_is_marked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _analyze(tmp_path, monkeypatch, "L" * 20000)
        assert len(result["stdout_excerpt"]) == _MAX_ANALYZE_EXCERPT
        assert result["truncated"] is True
        assert result["stdout_chars"] == 20000
        assert result["returned_chars"] == _MAX_ANALYZE_EXCERPT

    def test_a_short_log_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _analyze(tmp_path, monkeypatch, "INFO analyze done")
        assert result["stdout_excerpt"] == "INFO analyze done"
        assert "truncated" not in result
