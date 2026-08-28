"""r2.sections/symbols/entrypoints/relocations: wiring, address mapping, docs.

These four tools bring the radare2 line closer to ghidra parity: a static
section/RWX map, the full symbol table, entry points, and load-time
relocations. They all go through the generic ``*j`` request path, so the
tests pin the whitelisted command each dispatches, the vaddr->Address
mapping enrich_r2_payload performs, the cut disclosure, and the docstrings.
"""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.r2 import build_r2_tools

_NEW_TOOLS = ("r2.sections", "r2.symbols", "r2.entrypoints", "r2.relocations")


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _write_pe_with_base(path: Path, image_base: int = 0x140000000) -> None:
    """A PE32+ header just complete enough for pe_preferred_base to read base."""
    image = bytearray(0x400)
    image[:2] = b"MZ"
    pe = 0x80
    image[0x3C:0x40] = pe.to_bytes(4, "little")
    image[pe : pe + 4] = b"PE\0\0"
    image[pe + 4 : pe + 6] = (0x8664).to_bytes(2, "little")
    opt_size = 0xF0
    image[pe + 20 : pe + 22] = opt_size.to_bytes(2, "little")
    opt = pe + 24
    image[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    image[opt + 24 : opt + 32] = image_base.to_bytes(8, "little")
    path.write_bytes(image)


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    _write_pe_with_base(binary)
    return R2Client(executable), binary


@pytest.mark.parametrize(
    ("command", "entry", "va"),
    [
        (
            "iSj",
            {"name": ".text", "size": 0x1000, "vsize": 0x1000, "paddr": 0x400,
             "vaddr": 0x140001000, "perm": "-r-x"},
            0x140001000,
        ),
        (
            "isj",
            {"name": "main", "realname": "main", "type": "FUNC", "bind": "GLOBAL",
             "size": 0x40, "paddr": 0x500, "vaddr": 0x140001100, "is_imported": False},
            0x140001100,
        ),
        (
            "iej",
            {"vaddr": 0x140001000, "paddr": 0x400, "type": "program"},
            0x140001000,
        ),
        (
            "irj",
            {"vaddr": 0x140002000, "paddr": 0x1400, "type": "SET_64", "name": "CreateFileW"},
            0x140002000,
        ),
    ],
)
def test_new_r2_commands_pass_whitelist_and_map_vaddr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    entry: dict[str, Any],
    va: int,
) -> None:
    """The client launches once and enrich maps vaddr to a va/rva/module Address."""
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, json.dumps([entry]).encode("utf-8"), b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.run(binary, [command])

    assert len(launched) == 1
    assert result["commands"] == [command]
    assert result["parsed"] is True
    assert result["count"] == 1
    item = result["items"][0]
    assert item["address"]["va"] == va
    assert item["address"]["rva"] == va - 0x140000000
    assert item["address"]["module"] == "sample.exe"


def test_new_r2_service_methods_dispatch_expected_commands(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Each service method must send its own whitelisted *j command, in order."""

    class _CommandCapture:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def run(
            self, binary: Path, commands: list[str], *, timeout: float = 30.0
        ) -> dict[str, Any]:
            del binary, timeout
            captured.append(list(commands))
            return {"raw": "[]", "commands": list(commands), "items": [], "count": 0}

    captured: list[list[str]] = []
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: _CommandCapture(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe_with_base(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        for method in (
            service.r2_sections,
            service.r2_symbols,
            service.r2_entrypoints,
            service.r2_relocations,
        ):
            result = method(session_id)
            assert result.ok, result.error
            assert result.data is not None
            assert result.data["items"] == []

        assert captured == [["iSj"], ["isj"], ["iej"], ["irj"]]
    finally:
        service.close_all()


def test_r2_sections_reports_the_cut(tmp_path: Path) -> None:
    """Over the cap, sections say items_truncated/items_total, never a sections key."""
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"s{index}", "vaddr": 0x140001000 + index, "size": 0x10}
        for index in range(_MAX_ITEMS + 5)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 5
    assert payload["items_limit"] == _MAX_ITEMS
    assert "sections" not in payload
    assert "has_more" not in payload


def test_new_r2_tools_are_registered_and_documented() -> None:
    """All four tools bind and their docstrings name items and disclaim has_more."""
    settings = Settings.load()
    service = AnalysisService(settings)
    names = {tool.name for tool in build_r2_tools(service)}
    for name in _NEW_TOOLS:
        assert name in names, name
        doc = " ".join(_tool_docstring(name).split())
        assert "items" in doc
        # Every new tool disclaims the paginator fields callers might expect.
        assert "truncated or has_more field" in doc


@pytest.mark.parametrize(
    ("name", "negative"),
    [
        ("r2.sections", "no integer address, sections"),
        ("r2.symbols", "no integer address, symbols"),
        ("r2.entrypoints", "no integer address, entrypoints"),
        ("r2.relocations", "no integer address, relocations"),
    ],
)
def test_new_r2_docstrings_disclaim_absent_fields(name: str, negative: str) -> None:
    doc = " ".join(_tool_docstring(name).split())
    assert negative in doc


def test_new_r2_commands_reach_the_client_whitelist() -> None:
    """A guard so a future whitelist trim cannot silently strip these commands."""
    from headless_re_mcp.backends.r2.client import _ALLOWED

    assert {"iSj", "isj", "iej", "irj"}.issubset(_ALLOWED)


def test_new_r2_commands_reject_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whitelisting the bare command must not admit a composed variant."""
    client, binary = _client_and_binary(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs, cmd
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    with pytest.raises(R2Error, match="not whitelisted"):
        client.run(binary, ["iSj;!echo hi"])
