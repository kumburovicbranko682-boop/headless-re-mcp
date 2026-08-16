"""Ghidra export boundaries: a cut function list must not look complete."""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.ghidra.client import GhidraClient

_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "headless_re_mcp"
    / "backends"
    / "ghidra"
    / "scripts"
    / "ExportJson.py"
)


def _functions_page(total: int, limit: int) -> tuple[int, bool]:
    """Mirrors ExportJson.py functions mode: stop at limit and say so."""
    items: list[int] = []
    has_more = False
    for index in range(total):
        if len(items) >= limit:
            has_more = True
            break
        items.append(index)
    return len(items), has_more


class TestGhidraFunctionsSaysWhenItWasCut:
    """A function page that hit the cap used to look like every function.

    Measured: an export of 256 items (14 KiB) came back as count=256 with
    no has_more and no total, so an agent treated the page as the program.
    """

    def test_a_full_page_is_not_the_whole_program(self) -> None:
        count, has_more = _functions_page(400, 256)
        assert count == 256
        assert has_more is True

    def test_an_exact_page_is_complete(self) -> None:
        count, has_more = _functions_page(256, 256)
        assert count == 256
        assert has_more is False

    def test_the_export_script_sets_has_more_on_a_full_page(self) -> None:
        source = _SCRIPT.read_text(encoding="utf-8")
        functions_block = source.split('elif mode == "symbols"')[0]
        assert "has_more = True" in functions_block
        assert 'payload["has_more"]' in functions_block

    def test_the_client_forwards_has_more(self, tmp_path: Path) -> None:
        class _Client(GhidraClient):
            def __init__(self) -> None:
                self.home = tmp_path
                self.java = tmp_path
                self.analyze = tmp_path / "analyzeHeadless"
                self.analyze.write_text("", encoding="utf-8")

            def _run_headless(self, project_dir: Path, **_: object) -> tuple[str, str, int]:
                items = [
                    {"name": f"fun_{index}", "entry": hex(0x1000 + index), "body_size": 16}
                    for index in range(256)
                ]
                out_path = project_dir / "export_functions.json"
                out_path.write_text(
                    json.dumps(
                        {
                            "mode": "functions",
                            "items": items,
                            "count": 256,
                            "has_more": True,
                        }
                    ),
                    encoding="utf-8",
                )
                return "", "", 0

        binary = tmp_path / "app.bin"
        binary.write_bytes(b"MZ")
        project = tmp_path / "proj"
        project.mkdir()
        result = _Client().functions(binary, project, limit=256)
        assert result["count"] == 256
        assert result["has_more"] is True
