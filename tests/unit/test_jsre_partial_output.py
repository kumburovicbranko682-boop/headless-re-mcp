"""webcrack/wabt must not report a partial result as a complete artifact.

These one-shot tools exit non-zero when they fail on part of the input but
still write what they managed. ``_run``-based methods deliberately tolerate
that (they only fail hard when *nothing* came back), so the call succeeds --
but a caller reading ``code``/``files``/``wat``/``objdump`` as the whole thing
would miss that the tool gave up partway. These tests pin the ``partial``
disclosure that says so.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre.client import JsClient, JsReError, WasmClient
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _fake_run(returncode: int, stdout: bytes, stderr: bytes = b"") -> Any:
    def run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(returncode, stdout, stderr)

    return run


def test_deobfuscate_flags_a_non_zero_exit_that_still_produced_code(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    run = _fake_run(2, b"partial code", b"SyntaxError: could not parse module 3")
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["code"] == "partial code"
    assert payload["partial"] is True
    assert payload["exit_code"] == 2
    assert payload["note"]
    assert "could not parse module 3" in payload["stderr"]


def test_deobfuscate_clean_exit_is_not_partial(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", _fake_run(0, b"ok")):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["partial"] is False
    assert "exit_code" not in payload
    assert "note" not in payload
    assert "stderr" not in payload


def test_deobfuscate_non_zero_with_no_output_still_fails_hard(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", _fake_run(1, b"", b"boom")),
        pytest.raises(JsReError) as caught,
    ):
        JsClient(tool).deobfuscate(src)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


def test_unpack_bundle_flags_partial_but_keeps_pagination(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    for index in range(5):
        (out / f"m{index}.js").write_text("1", encoding="utf-8")

    run = _fake_run(1, b"", b"failed on chunk 9")
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", run):
        payload = JsClient(tool).unpack_bundle(src, out, offset=0, limit=3)

    assert payload["partial"] is True
    assert payload["exit_code"] == 1
    assert payload["note"]
    assert "failed on chunk 9" in payload["stderr"]
    # The partial disclosure rides alongside the existing pagination fields.
    assert payload["file_count"] == 5
    assert payload["count"] == 3
    assert payload["has_more"] is True


def test_unpack_bundle_clean_exit_is_not_partial(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "m.js").write_text("1", encoding="utf-8")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", _fake_run(0, b"")):
        payload = JsClient(tool).unpack_bundle(src, out)

    assert payload["partial"] is False
    assert "exit_code" not in payload


def test_wasm_wat_and_info_flag_a_non_zero_exit_with_output(tmp_path: Path) -> None:
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    objdump = tmp_path / "wasm-objdump.exe"
    objdump.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        _fake_run(3, b"(module)", b"warning: truncated section"),
    ):
        wat = WasmClient(tool).wat(module)
        # WasmClient resolves both tools from the same argument; reuse it.
        info = WasmClient(objdump).info(module)

    assert wat["partial"] is True
    assert wat["exit_code"] == 3
    assert wat["wat"] == "(module)"
    assert info["partial"] is True
    assert info["objdump"] == "(module)"


def test_tool_docstrings_name_the_partial_disclosure() -> None:
    for name in ("js.deobfuscate", "js.beautify", "js.unpack_bundle", "wasm.wat", "wasm.info"):
        assert "partial" in " ".join(_tool_docstring(name).split()), name
