"""r2.libraries shapes the ilj string array into a linked-library list.

ilj answers with a JSON array of library-name strings (not the object arrays
the shared enrich path shapes), so the backend parses the list itself. These
mock R2Client.run to feed that raw output and pin the shape: the name list, the
empty static case, robustness to an object-wrapped format, the cap, the
whitelist, and the docstring.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.client import (
    _MAX_LIBRARIES,
    R2Client,
    _require_allowed_command,
)
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


def _client_returning(raw: str, monkeypatch: Any) -> R2Client:
    """An R2Client whose run() yields the given raw ilj output, unspawned."""
    client = R2Client(Path("/usr/bin/true"))

    def _fake_run(
        self: R2Client, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {"raw": raw, "commands": commands}

    monkeypatch.setattr(R2Client, "run", _fake_run)
    return client


def test_r2_libraries_parses_the_string_list(monkeypatch: Any) -> None:
    client = _client_returning(json.dumps(["libc.so.6", "libssl.so.3"]), monkeypatch)
    result = client.libraries(Path("app.elf"))
    assert result["libraries"] == ["libc.so.6", "libssl.so.3"]
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["module"] == "app.elf"
    assert result["commands"] == ["ilj"]
    assert "libraries_truncated" not in result


def test_r2_libraries_empty_for_a_static_binary(monkeypatch: Any) -> None:
    """A static binary links nothing at load, and the empty list is the finding."""
    client = _client_returning("[]", monkeypatch)
    result = client.libraries(Path("static.elf"))
    assert result["libraries"] == []
    assert result["count"] == 0
    assert result["total"] == 0


def test_r2_libraries_survives_an_object_wrapped_format(monkeypatch: Any) -> None:
    """A newer r2 that wraps each library in an object must still yield names."""
    raw = json.dumps([{"name": "libc.so.6"}, {"library": "libm.so.6"}, {}])
    client = _client_returning(raw, monkeypatch)
    result = client.libraries(Path("app.elf"))
    assert result["libraries"] == ["libc.so.6", "libm.so.6"]
    assert result["count"] == 2
    assert result["total"] == 2


def test_r2_libraries_caps_a_hostile_fan_out(monkeypatch: Any) -> None:
    names = [f"lib{index}.so" for index in range(_MAX_LIBRARIES + 3)]
    client = _client_returning(json.dumps(names), monkeypatch)
    result = client.libraries(Path("app.elf"))
    assert result["count"] == _MAX_LIBRARIES
    assert result["total"] == _MAX_LIBRARIES + 3
    assert result["libraries_truncated"] is True
    assert result["libraries_total"] == _MAX_LIBRARIES + 3
    assert result["libraries_limit"] == _MAX_LIBRARIES


def test_r2_ilj_is_whitelisted() -> None:
    _require_allowed_command("ilj")


def test_r2_libraries_docstring_names_the_shape() -> None:
    doc = _tool_docstring("r2.libraries")
    assert doc, "r2.libraries is missing its docstring"
    assert "ilj" in doc
    assert "DT_NEEDED" in doc
    assert "libc.so.6" in doc
    assert "libraries_truncated" in doc
    assert "statically" in doc
    assert "empty list" in doc
