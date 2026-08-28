"""r2.decompile must lift pdcj's code string and keep the pdc surface honest."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import (
    _MAX_DECOMPILE_CHARS,
    R2Client,
    R2Error,
    _require_allowed_command,
)
from headless_re_mcp.tools.r2 import build_r2_tools

_PSEUDO = (
    "int main (int esi, int edx) {\n"
    "    loc_0x1161:\n"
    "        // DATA XREF from entry0 @ 0x1078\n"
    "        sym.imp.printf ()\n"
    "        return eax;\n"
    "}\n"
)


def _pe_fixture(tmp_path: Path) -> Path:
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


def _client_with_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> tuple[R2Client, Path, list[list[str]]]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, stdout, b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    return R2Client(executable), _pe_fixture(tmp_path), launched


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


def test_decompile_lifts_code_and_maps_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pdcj answers {code, annotations}; the caller gets code, not info.

    Measured against r2 5.5.0: pdcj is an object, so the generic array
    mapping produces no items and stashes the dict under info. A caller
    reading info["code"] would couple to the raw pdcj shape; the tool
    promises a top-level code string with the request address mapped.
    """
    stdout = json.dumps({"code": _PSEUDO, "annotations": [{"start": 0}]}).encode()
    client, pe, launched = _client_with_stdout(tmp_path, monkeypatch, stdout)

    payload = client.decompile(pe, 0x140001161)

    assert payload["code"] == _PSEUDO
    assert "info" not in payload
    assert "code_truncated" not in payload
    assert payload["address"] == {
        "module": "demo64.exe",
        "rva": 0x1161,
        "va": 0x140001161,
        "architecture": "x64",
    }
    assert payload["address_va"] == 0x140001161
    assert "items" not in payload
    assert len(launched) == 1
    assert "pdcj @ 5368713569" in launched[0][3]


def test_decompile_empty_code_when_no_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No function at the address must read as code == "", not a KeyError."""
    client, pe, _ = _client_with_stdout(tmp_path, monkeypatch, b"{}")
    payload = client.decompile(pe, 0x140000000)
    assert payload["code"] == ""

    client2, pe2, _ = _client_with_stdout(tmp_path, monkeypatch, b"")
    payload2 = client2.decompile(pe2, 0x140000000)
    assert payload2["code"] == ""
    assert payload2["parsed"] is False


def test_decompile_bounds_giant_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A code string past the cap is cut with the cut said out loud."""
    giant = "x" * (_MAX_DECOMPILE_CHARS + 7)
    stdout = json.dumps({"code": giant, "annotations": []}).encode()
    client, pe, _ = _client_with_stdout(tmp_path, monkeypatch, stdout)

    payload = client.decompile(pe, 0x140001000)

    assert len(payload["code"]) == _MAX_DECOMPILE_CHARS
    assert payload["code_truncated"] is True
    assert payload["code_length"] == _MAX_DECOMPILE_CHARS + 7


def test_decompile_rejects_bad_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, pe, launched = _client_with_stdout(tmp_path, monkeypatch, b"{}")
    for bad in (-1, "16", 1.5, True, None):
        with pytest.raises(R2Error, match="non-negative int"):
            client.decompile(pe, bad)  # type: ignore[arg-type]
    assert launched == []


def test_pdcj_command_is_whitelisted() -> None:
    _require_allowed_command("pdcj @ 0x1161")
    _require_allowed_command("pdcj @ 4449")
    for bad in (
        "pdc @ 0x1161",
        "pdcj @ main",
        "pdcj @ -1",
        "pdcj 4 @ 0x1161",
        "pdcj @ 0x1161;!echo escaped",
        "pdcj @ 0x1161 && q",
    ):
        with pytest.raises(R2Error, match="not whitelisted"):
            _require_allowed_command(bad)


def test_decompile_schema_and_docstring() -> None:
    described = _tool_docstring("r2.decompile")
    assert "Answers with code" in described
    assert "ghidra.decompile" in described
    assert "code_truncated" in described
    assert "r2.functions" in described
    assert "no items" in described.replace("\n", " ")
