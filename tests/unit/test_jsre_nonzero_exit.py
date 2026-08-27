"""A non-zero exit that still printed something must not read as clean.

webcrack exits non-zero on a partial deobfuscation while still emitting usable
code, and wasm-objdump can print sections before it trips on a later one. The
backend keeps that output on the "return what we got" path on purpose, but a
bail-out that happened to print something used to be indistinguishable from a
finished run: the reply carried no exit status. These lock in that a non-zero
exit is surfaced (exit_code / tool_failed / stderr) while a clean exit stays
free of that noise.
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


def test_deobfuscate_surfaces_a_nonzero_exit_with_partial_code(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    partial = "function a(){}" * 3

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, partial.encode("utf-8"), b"unexpected token at 42")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["code"] == partial
    assert payload["truncated"] is False
    assert payload["exit_code"] == 1
    assert payload["tool_failed"] is True
    assert payload["stderr"] == "unexpected token at 42"


def test_clean_exit_carries_no_failure_fields(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, b"clean output", b"noise on stderr is not a failure")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["code"] == "clean output"
    assert "exit_code" not in payload
    assert "tool_failed" not in payload
    assert "stderr" not in payload


def test_deobfuscate_still_raises_when_nonzero_and_nothing_printed(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(3, b"", b"fatal: cannot parse")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        JsClient(tool).deobfuscate(src)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 3


def test_unpack_bundle_raises_when_nonzero_and_nothing_was_written(tmp_path: Path) -> None:
    """A crash that left no files behind is a hard failure, not an empty listing.

    unpack_bundle keeps a partial unpack (nonzero exit but files on disk) on the
    return-what-we-got path, but with nothing written the run produced no usable
    result at all -- surfacing an empty ``files`` with a ``tool_failed`` flag would
    read as "this bundle unpacks to zero modules". It must fail closed instead.
    """
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(2, b"", b"unpack aborted before writing anything")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        JsClient(tool).unpack_bundle(src, out, offset=0, limit=10)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 2
    assert caught.value.details.get("stderr") == "unpack aborted before writing anything"


def test_wasm_wat_raises_when_nonzero_and_nothing_printed(tmp_path: Path) -> None:
    """wasm2wat that died without emitting any WAT fails closed, matching the
    webcrack contract: an empty conversion is never reported as a clean run."""
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"fatal: unknown section")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        WasmClient(tool).wat(module)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1
    assert caught.value.details.get("stderr") == "fatal: unknown section"


def test_wasm_info_raises_when_nonzero_and_nothing_printed(tmp_path: Path) -> None:
    """wasm-objdump that died without printing any section listing fails closed
    rather than returning an empty objdump dump as if it were the whole module."""
    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"fatal: bad magic")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        WasmClient(tool).info(module)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1
    assert caught.value.details.get("stderr") == "fatal: bad magic"


def test_unpack_bundle_surfaces_a_nonzero_exit_when_files_were_written(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "m0.js").write_text("1", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(2, b"", b"unpack aborted midway")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).unpack_bundle(src, out, offset=0, limit=10)

    assert payload["file_count"] == 1
    assert payload["files"] == ["m0.js"]
    assert payload["exit_code"] == 2
    assert payload["tool_failed"] is True
    assert payload["stderr"] == "unpack aborted midway"


def test_wasm_info_surfaces_a_nonzero_exit_with_partial_output(tmp_path: Path) -> None:
    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    text = "Sections:\n  Type start=0x0000000a\n"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, text.encode("utf-8"), b"error: invalid section id")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).info(module)

    assert payload["objdump"] == text
    assert payload["exit_code"] == 1
    assert payload["tool_failed"] is True
    assert payload["stderr"] == "error: invalid section id"


def test_wasm_wat_surfaces_a_nonzero_exit_with_partial_output(tmp_path: Path) -> None:
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    body = "(module (func))"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, body.encode("utf-8"), b"error: type mismatch")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).wat(module)

    assert payload["wat"] == body
    assert payload["exit_code"] == 1
    assert payload["tool_failed"] is True


def test_surfaced_stderr_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_STDERR", 16)
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"code", b"e" * 5000)

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = mod.JsClient(tool).deobfuscate(src)

    assert payload["stderr"] == "e" * 16


def test_docstrings_name_the_nonzero_exit_fields() -> None:
    for name in ("js.deobfuscate", "js.beautify", "js.unpack_bundle", "wasm.wat", "wasm.info"):
        doc = _tool_docstring(name)
        assert "exit_code" in doc
        assert "tool_failed" in doc
