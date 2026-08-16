"""Ghidra export bounds: a cut decompile must not look complete."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import (
    _MAX_DECOMPILE_CHARS,
    GhidraClient,
    _disclose_decompile,
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
