from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock


def test_ghidra_analyze_description_does_not_promise_a_kept_project() -> None:
    """The docstring used to say later ghidra tools read what analyze produced.

    Measured: analyze_binary and functions both call _run_headless with
    delete_project=True, and every headless invocation includes -import. An
    unattended agent that spent minutes on analyze then expected cached
    analysis was paying twice and reading a lie.
    """
    from headless_re_mcp.tools.ghidra import build_ghidra_tools

    tools = {item.name: item for item in build_ghidra_tools(MagicMock())}
    doc = tools["ghidra.analyze"].handler.__doc__ or ""
    lowered = doc.casefold()
    assert "one-shot" in lowered or "import the file again" in lowered
    assert "read what this produced" not in lowered
    assert "run it first" not in lowered


def test_ghidra_functions_says_when_the_page_is_not_the_whole_set(tmp_path: Path) -> None:
    """A full page used to look like every function Ghidra found.

    Measured: 256 items, limit=256, keys were mode/items/count only. An agent
    that stopped there missed the rest of the program.
    """
    from headless_re_mcp.backends.ghidra.client import GhidraClient

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ")
    project = tmp_path / "proj"
    project.mkdir()
    client = GhidraClient()
    client.analyze = tmp_path / "analyzeHeadless"
    client.java = tmp_path / "java"

    def fake_run(project_dir: Path, **_kwargs: object) -> tuple[str, str, int]:
        out = Path(project_dir) / "export_functions.json"
        out.write_text(
            json.dumps(
                {
                    "mode": "functions",
                    "items": [{"name": f"f{i}"} for i in range(256)],
                    "count": 256,
                }
            ),
            encoding="utf-8",
        )
        return "", "", 0

    client._run_headless = fake_run  # type: ignore[method-assign]
    got = client.functions(binary, project, limit=256)
    assert got["count"] == 256
    assert got["has_more"] is True


def test_ghidra_decompile_says_when_the_c_was_cut(tmp_path: Path) -> None:
    """A 200_000-character decompile came back with no truncated flag.

    An agent that greps that C for a helper past the cap concludes it was
    never there.
    """
    from headless_re_mcp.backends.ghidra.client import GhidraClient

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ")
    project = tmp_path / "proj"
    project.mkdir()
    client = GhidraClient()
    client.analyze = tmp_path / "analyzeHeadless"
    client.java = tmp_path / "java"

    def fake_run(project_dir: Path, **_kwargs: object) -> tuple[str, str, int]:
        out = Path(project_dir) / "export_decompile.json"
        out.write_text(
            json.dumps(
                {
                    "mode": "decompile",
                    "items": [],
                    "count": 0,
                    "decompiled": "C" * 200_000,
                    "function": "Foo",
                    "entry": "0x1000",
                }
            ),
            encoding="utf-8",
        )
        return "", "", 0

    client._run_headless = fake_run  # type: ignore[method-assign]
    got = client.decompile(binary, project, "0x1000")
    assert len(got["decompiled"]) == 200_000
    assert got["truncated"] is True


def test_ghidra_list_tools_tell_the_model_to_read_has_more() -> None:
    from headless_re_mcp.tools.ghidra import build_ghidra_tools

    tools = {item.name: item for item in build_ghidra_tools(MagicMock())}
    for name in ("ghidra.functions", "ghidra.symbols", "ghidra.xrefs"):
        doc = tools[name].handler.__doc__ or ""
        assert "has_more" in doc, name
