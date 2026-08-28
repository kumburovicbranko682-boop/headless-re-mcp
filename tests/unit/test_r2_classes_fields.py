"""r2.classes exposes radare2's class listing (icj): wiring, mapping, docs.

radare2 recovers C++ RTTI / Objective-C / Swift / Java / .NET class structure
from a binary's own metadata. This tool surfaces it through the same generic
``*j`` request path as r2.sections/symbols, so the tests pin the whitelisted
command it dispatches, the class-addr->Address mapping enrich_r2_payload
performs (nested method addresses left as integers), the cut disclosure, the
whitelist guard, and the docstring.
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


def test_classes_pass_whitelist_and_map_class_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """icj launches once; the class addr maps, nested method addrs stay ints."""
    client, binary = _client_and_binary(tmp_path)
    entry = {
        "classname": "Foo",
        "addr": 0x140001000,
        "methods": [
            {"name": "Foo::bar", "addr": 0x140001100, "type": "METH"},
            {"name": "Foo::baz", "addr": 0x140001200, "type": "METH"},
        ],
        "fields": [],
    }
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, json.dumps([entry]).encode("utf-8"), b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.run(binary, ["icj"])

    assert len(launched) == 1
    assert result["commands"] == ["icj"]
    assert result["parsed"] is True
    assert result["count"] == 1
    item = result["items"][0]
    assert item["classname"] == "Foo"
    assert item["address"]["va"] == 0x140001000
    assert item["address"]["rva"] == 0x1000
    assert item["address"]["module"] == "sample.exe"
    # The nested methods are passed through untouched -- their addr stays the
    # integer radare2 emitted, not an Address object.
    assert item["methods"][0]["name"] == "Foo::bar"
    assert item["methods"][0]["addr"] == 0x140001100


def test_service_r2_classes_dispatches_icj(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """service.r2_classes must send exactly the whitelisted icj command."""

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
        result = service.r2_classes(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["items"] == []
        assert captured == [["icj"]]
    finally:
        service.close_all()


def test_r2_classes_reports_the_cut(tmp_path: Path) -> None:
    """Over the cap, classes say items_truncated/items_total, never a classes key."""
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"classname": f"C{index}", "addr": 0x140001000 + index, "methods": []}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["icj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert payload["items_limit"] == _MAX_ITEMS
    assert "classes" not in payload
    assert "has_more" not in payload


def test_r2_classes_is_registered_and_documented() -> None:
    """The tool binds and its docstring names items and disclaims has_more."""
    settings = Settings.load()
    service = AnalysisService(settings)
    names = {tool.name for tool in build_r2_tools(service)}
    assert "r2.classes" in names
    doc = " ".join(_tool_docstring("r2.classes").split())
    assert "items" in doc
    assert "classname" in doc
    assert "methods" in doc
    assert "truncated or has_more field" in doc


def test_r2_classes_command_reaches_the_client_whitelist() -> None:
    """A guard so a future whitelist trim cannot silently strip icj."""
    from headless_re_mcp.backends.r2.client import _ALLOWED

    assert "icj" in _ALLOWED


def test_r2_classes_rejects_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whitelisting the bare command must not admit a composed variant."""
    client, binary = _client_and_binary(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs, cmd
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    with pytest.raises(R2Error, match="not whitelisted"):
        client.run(binary, ["icj @@ sym.*"])
