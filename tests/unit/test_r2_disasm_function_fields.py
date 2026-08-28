"""r2.disasm_function lifts pdfj's function object into mapped op items."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _require_allowed_command
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
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
    """A minimal PE64 with ImageBase 0x140000000 so RVAs are derivable."""
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


def _fake_run(func_obj: dict[str, object]):
    """Stand in for R2Client.run: pdfj yields a function object under info."""

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0):  # noqa: ANN001
        assert commands[0] == "aa"
        assert commands[1].startswith("pdfj @ ")
        return enrich_r2_payload({"raw": json.dumps(func_obj), "commands": commands}, binary=binary)

    return run


def test_disasm_function_lifts_ops_and_metadata(tmp_path: Path, monkeypatch) -> None:
    """The nested ops become mapped items; function metadata is surfaced.

    pdfj is a function object, not an op array, so enrich alone would stash it
    under info and map nothing. disasm_function must lift ops into items (each
    op.offset -> Address, branch targets kept as raw jump VAs) and expose the
    resolved name, size, addr and ninstr under function.
    """
    func = {
        "name": "sym.main",
        "addr": 0x140001000,
        "size": 0x24,
        "ops": [
            {
                "offset": 0x140001000,
                "opcode": "endbr64",
                "disasm": "endbr64",
                "type": "null",
                "size": 4,
            },
            {
                "offset": 0x140001004,
                "opcode": "call 0x140001100",
                "disasm": "call sym.add",
                "type": "call",
                "jump": 0x140001100,
                "size": 5,
            },
            {"offset": 0x140001009, "opcode": "ret", "disasm": "ret", "type": "ret", "size": 1},
        ],
    }
    monkeypatch.setattr(R2Client, "run", _fake_run(func))
    out = R2Client().disasm_function(_pe(tmp_path), 0x140001000)

    assert out["parsed"] is True
    assert out["count"] == 3
    assert out["items"][0]["address"]["rva"] == 0x1000
    assert out["items"][0]["opcode"] == "endbr64"
    # A branch target stays a raw VA on the op (jump), like basic_blocks edges.
    assert out["items"][1]["jump"] == 0x140001100
    assert out["items"][1]["address"]["rva"] == 0x1004
    # No info blob leaks through -- the function object was lifted, not stashed.
    assert "info" not in out

    fn = out["function"]
    assert fn["name"] == "sym.main"
    assert fn["size"] == 0x24
    assert fn["ninstr"] == 3
    assert fn["addr"] == 0x140001000
    assert fn["address"]["rva"] == 0x1000
    # The queried address is echoed as an integer alongside its mapped form.
    assert out["address_va"] == 0x140001000
    assert type(out["address"]) is not int


def test_disasm_function_empty_when_no_function(tmp_path: Path, monkeypatch) -> None:
    """An address with no function yields empty items and ninstr 0, not a crash."""

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0):  # noqa: ANN001
        # r2 prints nothing when pdfj lands outside any function.
        return enrich_r2_payload({"raw": "", "commands": commands}, binary=binary)

    monkeypatch.setattr(R2Client, "run", run)
    out = R2Client().disasm_function(_pe(tmp_path), 0x140009999)
    assert out["items"] == []
    assert out["count"] == 0
    assert out["function"] == {"ninstr": 0}


def test_disasm_function_rejects_bad_address(tmp_path: Path) -> None:
    """A negative address is refused before any subprocess is spawned."""
    with pytest.raises(R2Error) as excinfo:
        R2Client().disasm_function(_pe(tmp_path), -1)
    assert excinfo.value.code == "invalid_params"


def test_pdfj_command_is_whitelisted() -> None:
    """pdfj at a hex or decimal address is allowed; opaque forms are refused."""
    _require_allowed_command("pdfj @ 0x140001000")
    _require_allowed_command("pdfj @ 4096")
    for bad in ("pdfj", "pdfj @ sym.main", "pdfj @ 0x10; iI", "pdfj@0x10", "pdf @ 0x10"):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_disasm_function_schema_and_docstring() -> None:
    """The tool rejects negative addresses in-schema and names its fields."""
    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    assert "r2.disasm_function" in named
    props = input_schema_for(named["r2.disasm_function"])["properties"]
    assert props["address"]["minimum"] == 0

    doc = _tool_docstring("r2.disasm_function")
    for token in ("function", "ninstr", "jump", "disasm", "address_va"):
        assert token in doc


def test_client_module_imports_resolve() -> None:
    """address_dict and Architecture are wired in for function-addr mapping."""
    assert hasattr(r2_client, "address_dict")
    assert hasattr(r2_client, "Architecture")
