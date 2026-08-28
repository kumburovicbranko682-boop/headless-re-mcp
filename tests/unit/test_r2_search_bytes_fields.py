"""r2.search_bytes locates a hex byte pattern and maps each hit to an Address."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error, _require_allowed_command
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.tools.binding import input_schema_for
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


def _pe(tmp_path: Path) -> Path:
    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(image))
    return pe


def _fake_run(hits: list[dict]):
    """Stand in for R2Client.run: /xj yields hexpair match rows."""

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0):  # noqa: ANN001
        assert len(commands) == 1 and commands[0].startswith("/xj ")
        return enrich_r2_payload({"raw": json.dumps(hits), "commands": commands}, binary=binary)

    return run


def test_search_bytes_maps_each_hit(tmp_path: Path, monkeypatch) -> None:
    """Each match's offset becomes an Address; the normalized pattern is echoed.

    /xj reports every location holding the bytes. offset is the match VA, which
    maps to {va, rva, module}, and the searched hex is echoed as pattern so a
    caller knows what produced the hits.
    """
    hits = [
        {"offset": 0x140002004, "type": "hexpair", "data": "68656c6c6f"},
        {"offset": 0x140003000, "type": "hexpair", "data": "68656c6c6f"},
    ]
    monkeypatch.setattr(R2Client, "run", _fake_run(hits))
    # Mixed-case and spaced input must normalize to lower-case, space-free hex.
    out = R2Client().search_bytes(_pe(tmp_path), "68 65 6C 6C 6F")

    assert out["pattern"] == "68656c6c6f"
    assert out["count"] == 2
    assert out["items"][0]["offset"] == 0x140002004
    assert out["items"][0]["address"]["rva"] == 0x2004
    assert out["items"][0]["data"] == "68656c6c6f"
    assert out["items"][1]["address"]["rva"] == 0x3000


def test_search_bytes_empty_when_absent(tmp_path: Path, monkeypatch) -> None:
    """A pattern present nowhere yields an honest empty list, not a failure."""
    monkeypatch.setattr(R2Client, "run", _fake_run([]))
    out = R2Client().search_bytes(_pe(tmp_path), "deadbeef")
    assert out["items"] == []
    assert out["count"] == 0
    assert out["parsed"] is True
    assert out["pattern"] == "deadbeef"


def test_search_bytes_rejects_non_hex_and_odd_and_oversized(tmp_path: Path) -> None:
    """Text, odd-length and over-cap patterns are refused before spawning r2."""
    pe = _pe(tmp_path)
    for bad in ("hello", "abc", "", "   ", "de ad be e", "ff" * 129, "0xdead"):
        with pytest.raises(R2Error) as excinfo:
            R2Client().search_bytes(pe, bad)
        assert excinfo.value.code == "invalid_params"


def test_search_xj_command_is_whitelisted() -> None:
    """/xj with a bounded hex-pair pattern is allowed; other shapes are refused."""
    _require_allowed_command("/xj 7f454c46")
    _require_allowed_command("/xj " + "ab" * 128)
    for bad in (
        "/xj",
        "/xj 7f45 4c46",  # space inside the built command is not allowed
        "/xj 7f454c4",  # odd length
        "/xj " + "ab" * 129,  # over the 128-byte cap
        "/xj 7f454c46; iI",
        "/x 7f454c46",
        "/j hello",
    ):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_search_bytes_schema_and_docstring() -> None:
    """The tool bounds the pattern length in-schema and names its fields."""
    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    assert "r2.search_bytes" in named
    props = input_schema_for(named["r2.search_bytes"])["properties"]
    assert props["pattern"]["minLength"] == 2
    assert props["pattern"]["maxLength"] == 400

    doc = _tool_docstring("r2.search_bytes")
    for token in ("offset", "pattern", "read_bytes", "xrefs_to"):
        assert token in doc


def test_search_bytes_arch_used_for_rva(tmp_path: Path, monkeypatch) -> None:
    """An explicit architecture flows through so RVAs derive against ImageBase."""
    monkeypatch.setattr(
        R2Client,
        "run",
        _fake_run([{"offset": 0x140001000, "type": "hexpair", "data": "cc"}]),
    )
    out = R2Client().search_bytes(_pe(tmp_path), "cc")
    assert out["items"][0]["address"]["va"] == 0x140001000
    assert out["items"][0]["address"]["rva"] == 0x1000
    assert out["architecture"] == Architecture.X64.value
