"""r2.resolve maps a raw address to its function and nearest symbol.

The reverse of every other r2 reader (xrefs/relocations/search/read/disasm all
emit addresses). These tests patch ``R2Client.run`` so the real ``resolve``
parsing runs against canned ``afij``/``fdj`` output -- exactly the two-stream
shape r2 prints (a JSON array then a JSON object).
"""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import (
    R2Client,
    R2Error,
    _decode_r2_values,
    _require_allowed_command,
)
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


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _patch_run(monkeypatch: Any, afij: Any, fdj: Any) -> list[list[str]]:
    """Make R2Client.run echo the afij array then the fdj object as one stream.

    Returns a sink the test can read to assert the exact commands the resolver
    put on the wire (``aa`` then ``afij @ addr`` then ``fdj @ addr``).
    """
    seen: list[list[str]] = []
    raw = json.dumps(afij) + "\n" + json.dumps(fdj)

    def _run(
        self: R2Client, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del self, binary, timeout
        seen.append(list(commands))
        return {"raw": raw, "commands": list(commands)}

    monkeypatch.setattr(R2Client, "run", _run)
    return seen


def test_resolve_maps_an_address_inside_a_function(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An address 16 bytes into main resolves to main with delta 16.

    This is the core read: afij bounds the containing function, so the result
    carries its name, start, size and the offset into it, and the queried
    address is mapped to an Address. The nearest flag lands on the same symbol.
    """
    start = 0x1150
    addr = 0x1160
    afij = [
        {
            "offset": start,
            "name": "sym.main",
            "size": 56,
            "signature": "int main (int argc, char **argv);",
            "type": "sym",
        }
    ]
    fdj = {"offset": start, "name": "sym.main", "realname": "main"}
    seen = _patch_run(monkeypatch, afij, fdj)
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)

    result = R2Client(None).resolve(binary, addr)

    assert seen[0] == ["aa", f"afij @ {addr}", f"fdj @ {addr}"]
    assert result["address_va"] == addr
    assert result["address"]["va"] == addr
    func = result["function"]
    assert func is not None
    assert func["name"] == "sym.main"
    assert func["addr"] == start
    assert func["size"] == 56
    assert func["delta"] == 16
    assert func["signature"].startswith("int main")
    assert func["type"] == "sym"
    assert func["address"]["va"] == start
    flag = result["flag"]
    assert flag is not None
    assert flag["name"] == "sym.main"
    assert flag["realname"] == "main"
    assert flag["addr"] == start
    assert flag["delta"] == 16


def test_resolve_reads_the_r2_6x_addr_key_for_the_function_start(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2 6.x renamed afij's function-start field from ``offset`` to ``addr``.

    The resolver must read either, or a 6.x function comes back with a null
    start and a missing delta -- the same version drift the other r2 readers
    already tolerate.
    """
    start = 0x4010
    addr = 0x4030
    afij = [{"addr": start, "name": "sym.helper", "size": 64}]
    fdj = {"addr": start, "name": "sym.helper"}
    _patch_run(monkeypatch, afij, fdj)
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)

    func = R2Client(None).resolve(binary, addr)["function"]

    assert func is not None
    assert func["addr"] == start
    assert func["delta"] == 0x20


def test_resolve_returns_a_null_function_for_a_data_address(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """afij prints ``[]`` at an address not inside any function.

    A string constant or a GOT slot has no containing function, so ``function``
    is null (not an error) while the nearest flag still names it. When fdj omits
    the offset the flag sits exactly on the address, so delta is 0 and there is
    no flag address to report.
    """
    addr = 0x2010
    afij: list[Any] = []
    fdj = {"name": "str.marker_9449", "realname": "str.marker_9449"}
    _patch_run(monkeypatch, afij, fdj)
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)

    result = R2Client(None).resolve(binary, addr)

    assert result["function"] is None
    flag = result["flag"]
    assert flag is not None
    assert flag["name"] == "str.marker_9449"
    assert flag["delta"] == 0
    assert "addr" not in flag
    assert "address" not in flag


def test_resolve_computes_flag_delta_when_the_flag_precedes_the_address(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """fdj's ``offset`` is the flag's own address; delta is address minus it.

    So an address 0x40 past ``str.blob`` reads as ``str.blob + 0x40`` -- the
    nearest name plus how far in, which is what lets a search hit inside a blob
    still get anchored to a symbol.
    """
    addr = 0x2040
    afij: list[Any] = []
    fdj = {"offset": 0x2000, "name": "str.blob"}
    _patch_run(monkeypatch, afij, fdj)
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)

    flag = R2Client(None).resolve(binary, addr)["flag"]

    assert flag is not None
    assert flag["addr"] == 0x2000
    assert flag["delta"] == 0x40
    assert flag["address"]["va"] == 0x2000
    assert "realname" not in flag


def test_resolve_returns_null_flag_when_the_image_has_no_flags(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """fdj prints ``{}`` when there is nothing to resolve against.

    A fully stripped image with the address outside any function resolves to
    both a null function and a null flag -- an honest "nothing named here", and
    still a parsed result rather than a fault.
    """
    addr = 0x30
    _patch_run(monkeypatch, [], {})
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)

    result = R2Client(None).resolve(binary, addr)

    assert result["function"] is None
    assert result["flag"] is None
    assert result["parsed"] is True


def test_resolve_rejects_a_negative_address(tmp_path: Path) -> None:
    """A negative address is invalid_params before r2 is ever run."""
    binary = tmp_path / "x.bin"
    binary.write_bytes(b"\x00" * 64)
    with pytest.raises(R2Error) as excinfo:
        R2Client(None).resolve(binary, -1)
    assert excinfo.value.code == "invalid_params"


def test_decode_r2_values_reads_an_array_then_an_object_past_a_banner() -> None:
    """The two-stream parser must recover both values and skip r2's banners.

    resolve runs two commands: afij prints an array, fdj an object, back to
    back, sometimes after an ``[x] Analyzing`` progress line. parse_r2_json
    would stop at the array and parse_r2_arrays would drop the object; the
    dedicated decoder returns both in order and steps over the banner.
    """
    raw = '[x] Analyzing\n[{"offset":1,"name":"a"}]\n{"name":"b","realname":"b"}'
    values = _decode_r2_values(raw)
    assert values == [[{"offset": 1, "name": "a"}], {"name": "b", "realname": "b"}]


def test_afij_and_fdj_are_whitelisted_but_only_with_a_numeric_seek() -> None:
    """The command gate must admit both seeked commands and refuse the rest.

    afij/fdj are new on the whitelist; if they were missing the tool would fault
    every call. Guard that both pass with a hex or decimal seek, while a
    non-numeric seek (which could smuggle r2 syntax) and a look-alike command
    are refused as invalid_params -- the gate stays a whitelist, not a prefix
    match.
    """
    _require_allowed_command("afij @ 0x1160")
    _require_allowed_command("afij @ 4432")
    _require_allowed_command("fdj @ 0x2000")
    _require_allowed_command("fdj @ 8208")
    for bad in ("afij @ main", "afij", "fdj @", "afgj @ 0x10", "afij @ 0x10; i"):
        with pytest.raises(R2Error) as excinfo:
            _require_allowed_command(bad)
        assert excinfo.value.code == "invalid_params"


def test_resolve_service_wires_through_to_a_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The service method resolves against the session's binary and tags r2.

    End-to-end through AnalysisService: create a session, call r2_resolve, and
    confirm it returns the parsed function/flag with the radare2 backend tag --
    the wiring an MCP client depends on.
    """
    start = 0x1150
    addr = 0x1155
    afij = [{"offset": start, "name": "sym.main", "size": 56, "type": "sym"}]
    fdj = {"offset": start, "name": "sym.main", "realname": "main"}
    _patch_run(monkeypatch, afij, fdj)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.r2_resolve(session_id, addr)
        assert result.ok, result.error
        assert result.data is not None
        assert result.meta.get("backend") == "radare2"
        assert result.data["function"]["name"] == "sym.main"
        assert result.data["function"]["delta"] == 5
        assert result.data["flag"]["name"] == "sym.main"
    finally:
        service.close_all()


def test_resolve_docstring_frames_it_as_the_reverse_reader() -> None:
    """The docstring must tell an agent this is the address -> name direction.

    It has to name afij and fdj, the function/flag/delta fields it returns, and
    the null-function case for an address outside any function, so an agent
    reaches for it when holding a raw address from a search or an xref.
    """
    doc = _tool_docstring("r2.resolve")
    assert "afij" in doc
    assert "fdj" in doc
    assert "function" in doc
    assert "flag" in doc
    assert "delta" in doc
    assert "null" in doc
