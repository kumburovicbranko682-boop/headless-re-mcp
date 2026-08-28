"""r2.read_bytes renders pxj's byte array as hex and ASCII at a mapped address."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

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


def _fake_run(values: list[int]):
    """Stand in for R2Client.run: pxj yields a plain array of byte values."""

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0):  # noqa: ANN001
        # No analysis pass for a byte read: pxj is the only command.
        assert commands == [commands[0]]
        assert commands[0].startswith("pxj ")
        return enrich_r2_payload({"raw": json.dumps(values), "commands": commands}, binary=binary)

    return run


def test_read_bytes_renders_hex_and_ascii(tmp_path: Path, monkeypatch) -> None:
    """The byte array becomes hex + a printable-ASCII column; address is mapped.

    'hello world\\0' plus two non-printable bytes exercises both the hex
    rendering and the '.'-for-non-printable ASCII column. The queried address
    is echoed as an integer and mapped to {va, rva, module}.
    """
    values = list(b"hello world\x00") + [0x01, 0x1B]
    monkeypatch.setattr(R2Client, "run", _fake_run(values))
    out = R2Client().read_bytes(_pe(tmp_path), 0x140002018, size=14)

    assert out["size"] == 14
    assert out["hex"] == bytes(values).hex()
    assert out["ascii"] == "hello world..."
    assert out["address"]["va"] == 0x140002018
    assert out["address"]["rva"] == 0x2018
    assert out["address_va"] == 0x140002018
    # Byte values are not list items; the misleading empty list is dropped.
    assert "items" not in out
    assert "count" not in out


def test_read_bytes_surfaces_unmapped_filler(tmp_path: Path, monkeypatch) -> None:
    """radare2's 0xff filler for unmapped memory is surfaced, not masked."""
    monkeypatch.setattr(R2Client, "run", _fake_run([0xFF] * 8))
    out = R2Client().read_bytes(_pe(tmp_path), 0x140009999, size=8)
    assert out["hex"] == "ff" * 8
    assert out["ascii"] == "." * 8
    assert out["size"] == 8


def test_read_bytes_rejects_bad_arguments(tmp_path: Path) -> None:
    """Negative addresses and out-of-range sizes are refused before spawning r2."""
    pe = _pe(tmp_path)
    for address, size in ((-1, 64), (0, 0), (0, 4097), (0, -5)):
        with pytest.raises(R2Error) as excinfo:
            R2Client().read_bytes(pe, address, size=size)
        assert excinfo.value.code == "invalid_params"


def test_pxj_command_is_whitelisted() -> None:
    """pxj with a count and hex/decimal address is allowed within the cap."""
    _require_allowed_command("pxj 64 @ 0x140002018")
    _require_allowed_command("pxj 4096 @ 8216")
    for bad in (
        "pxj",
        "pxj 64",
        "pxj @ 0x10",
        "pxj 4097 @ 0x10",  # over the 4096 cap
        "pxj 16 @ sym.main",
        "pxj 16 @ 0x10; iI",
    ):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_read_bytes_schema_and_docstring() -> None:
    """The tool bounds address/size in-schema and names its output fields."""
    bindings = build_r2_tools(object())  # type: ignore[arg-type]
    named = {binding.name: binding.handler for binding in bindings}
    assert "r2.read_bytes" in named
    props = input_schema_for(named["r2.read_bytes"])["properties"]
    assert props["address"]["minimum"] == 0
    assert props["size"]["minimum"] == 1
    assert props["size"]["maximum"] == 4096

    doc = _tool_docstring("r2.read_bytes")
    for token in ("hex", "ascii", "0xff", "address_va"):
        assert token in doc
