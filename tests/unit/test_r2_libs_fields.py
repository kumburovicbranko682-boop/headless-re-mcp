"""r2.libs must normalise ilj (bare names or objects) to {"name": ...} items."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.client import (
    R2Client,
    _require_allowed_command,
)
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS
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


def _canned(raw: str) -> Any:
    """A fake R2Client.run returning ``raw`` as the ilj output."""

    def run(binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        return {"raw": raw, "commands": commands}

    return run


def _fixture(tmp_path: Path) -> Path:
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    return binary


def test_r2_libs_normalises_a_bare_name_array(tmp_path: Path, monkeypatch: Any) -> None:
    """Most r2 builds emit ilj as an array of library-name strings.

    Each string becomes a ``{"name": ...}`` item, order preserved, with a
    matching count and parsed True -- the coarse dependency list an agent reads
    before walking per-symbol imports.
    """
    binary = _fixture(tmp_path)
    names = ["libc.so.6", "libssl.so.3", "ld-linux-x86-64.so.2"]
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(json.dumps(names)))
    out = client.libs(binary)
    assert out["parsed"] is True
    assert out["count"] == 3
    assert [item["name"] for item in out["items"]] == names
    # A DT_NEEDED name has no load address; the reader must not invent one.
    assert all(set(item) == {"name"} for item in out["items"])
    assert "items_truncated" not in out
    doc = _tool_docstring("r2.libs")
    assert "items" in doc
    assert "count" in doc


def test_r2_libs_normalises_an_object_array(tmp_path: Path, monkeypatch: Any) -> None:
    """Some builds emit objects; the name is pulled from name/library/lib.

    The reader must survive r2's cross-version/format key drift and still yield
    a flat name list, dropping any entry without a usable name.
    """
    binary = _fixture(tmp_path)
    payload = [
        {"name": "libc.so.6"},
        {"library": "libm.so.6"},
        {"lib": "libpthread.so.0"},
        {"other": "ignored"},
    ]
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(json.dumps(payload)))
    out = client.libs(binary)
    assert [item["name"] for item in out["items"]] == [
        "libc.so.6",
        "libm.so.6",
        "libpthread.so.0",
    ]
    assert out["count"] == 3


def test_r2_libs_accepts_a_libs_wrapper_object(tmp_path: Path, monkeypatch: Any) -> None:
    """A build that wraps the vector as {"libs": [...]} must still parse.

    parse_r2_json returns the object, so the reader has to reach into the libs
    key rather than treating the dict as "no array" and returning empty.
    """
    binary = _fixture(tmp_path)
    raw = json.dumps({"libs": ["libc.so.6", "libz.so.1"]})
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(raw))
    out = client.libs(binary)
    assert out["parsed"] is True
    assert [item["name"] for item in out["items"]] == ["libc.so.6", "libz.so.1"]


def test_r2_libs_static_binary_is_a_clean_empty_list(tmp_path: Path, monkeypatch: Any) -> None:
    """A fully static ELF links nothing: an empty array, not an error.

    ilj on a static binary is ``[]``; that must read as parsed True with zero
    items, so "no dependencies" is a legible answer rather than a fault.
    """
    binary = _fixture(tmp_path)
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned("[]"))
    out = client.libs(binary)
    assert out["parsed"] is True
    assert out["count"] == 0
    assert out["items"] == []


def test_r2_libs_survives_a_non_array_output(tmp_path: Path, monkeypatch: Any) -> None:
    """A banner or error instead of JSON must be empty, not a crash.

    Matching the other r2 readers: an unparsable run yields parsed False with an
    empty list the caller can see, never an exception at the tool boundary.
    """
    binary = _fixture(tmp_path)
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned("[x] Cannot open file"))
    out = client.libs(binary)
    assert out["parsed"] is False
    assert out["count"] == 0
    assert out["items"] == []


def test_r2_libs_caps_and_discloses_a_huge_list(tmp_path: Path, monkeypatch: Any) -> None:
    """A crafted module with a huge lib vector must be capped and disclosed.

    The item list stops at the shared cap, and items_truncated/items_total/
    items_limit say so, so "these are all the libraries" is never a wrong read.
    """
    binary = _fixture(tmp_path)
    names = [f"lib{i}.so" for i in range(_MAX_ITEMS + 25)]
    client = R2Client(executable=Path("/nonexistent-r2"))
    monkeypatch.setattr(client, "run", _canned(json.dumps(names)))
    out = client.libs(binary)
    assert out["count"] == _MAX_ITEMS
    assert out["items_truncated"] is True
    assert out["items_total"] == _MAX_ITEMS + 25
    assert out["items_limit"] == _MAX_ITEMS


def test_ilj_is_whitelisted_and_needs_no_analysis() -> None:
    """ilj is a bin-info read, whitelisted like the other i* readers.

    It needs no ``aa`` analysis pass, so libs() runs it alone; the whitelist
    must accept it directly.
    """
    _require_allowed_command("ilj")
