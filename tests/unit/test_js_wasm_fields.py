"""js/wasm tool descriptions must name the fields the backends return."""

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


def test_wasm_info_puts_the_dump_in_objdump_not_sections(tmp_path: Path) -> None:
    """The catalog said sections; the reply has no such field.

    Measured: wasm-objdump stdout is returned as objdump. Looking for sections
    after a successful call reads as an empty module.
    """
    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    text = "Contents of section .text:\n 0000: 00 61 73 6d\n"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, text.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).info(module)

    assert "objdump" in payload
    assert payload["objdump"] == text
    assert "sections" not in payload
    assert "Answers with objdump" in _tool_docstring("wasm.info")


def test_wasm_wat_names_bytes_not_size(tmp_path: Path) -> None:
    """The catalog named wat and never named the length field.

    Measured: 80-byte wasm2wat stdout -> wat length 80, bytes 80, no size
    key. Looking for size after a successful conversion reads as a reply
    with no length.
    """
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    body = "(module)" * 10

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    from headless_re_mcp.backends.jsre.client import WasmClient

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).wat(module)

    assert "size" not in payload
    assert payload["bytes"] == len(body)
    assert payload["wat"] == body
    doc = _tool_docstring("wasm.wat")
    assert "bytes" in doc
    assert "Answers with wat" in doc


def test_js_deobfuscate_names_bytes_not_size(tmp_path: Path) -> None:
    """The catalog named code and never named the length field.

    Measured: 100-byte webcrack stdout -> code length 100, bytes 100, no
    size key. Looking for size after a successful deobfuscation reads as
    a reply with no length, so a cut cannot be distinguished from a short
    file.
    """
    from headless_re_mcp.backends.jsre.client import JsClient

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    body = "z" * 100

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert "size" not in payload
    assert payload["bytes"] == 100
    assert payload["code"] == body
    doc = _tool_docstring("js.deobfuscate")
    assert "bytes" in doc
    assert "Answers with code" in doc


def test_js_deobfuscate_applies_inline_limit_to_encoded_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.jsre import client as mod

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    body = "ééé"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    monkeypatch.setattr(mod, "_MAX_INLINE", 5)
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["code"] == "éé"
    assert payload["bytes"] == 6
    assert payload["truncated"] is True
    assert len(str(payload["code"]).encode("utf-8")) <= 5


def test_js_beautify_names_bytes_not_size(tmp_path: Path) -> None:
    """The catalog repeated code/truncated and never named bytes.

    Measured: beautify is deobfuscate: 100-byte stdout -> bytes 100, no
    size key. Looking for size after a successful beautify reads as a
    reply with no length.
    """
    from headless_re_mcp.backends.jsre.client import JsClient

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    body = "z" * 100

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).beautify(src)

    assert "size" not in payload
    assert payload["bytes"] == 100
    doc = _tool_docstring("js.beautify")
    assert "bytes" in doc


def test_js_wasm_descriptions_name_the_payload_fields() -> None:
    assert "Answers with code" in _tool_docstring("js.deobfuscate")
    assert "Answers with code" in _tool_docstring("js.beautify")
    assert "bytes" in _tool_docstring("js.beautify")
    assert "output_dir" in _tool_docstring("js.unpack_bundle")
    assert "has_more" in _tool_docstring("js.unpack_bundle")
    assert "Answers with wat" in _tool_docstring("wasm.wat")
    assert "bytes" in _tool_docstring("wasm.wat")
    assert "truncated" in _tool_docstring("wasm.info")
    assert "too_large" in _tool_docstring("js.deobfuscate")
    assert "too_large" in _tool_docstring("js.unpack_bundle")
    assert "too_large" in _tool_docstring("wasm.info")
    for name in ("js.deobfuscate", "js.beautify", "js.unpack_bundle", "wasm.wat", "wasm.info"):
        doc = _tool_docstring(name)
        assert "clean_exit" in doc, name
        assert "exit_code" in doc, name


def test_js_deobfuscate_reports_a_clean_run_as_clean(tmp_path: Path) -> None:
    """A zero-exit run is clean_exit True with exit_code 0 and no stderr key.

    This pins the common path so the honesty fields cannot silently invert:
    without a positive assertion, a later change could set clean_exit False on
    every run and no test would notice.
    """
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, b"clean", b"just a warning\n")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["code"] == "clean"
    assert payload["exit_code"] == 0
    assert payload["clean_exit"] is True
    # A clean run keeps stderr out of the payload; warnings do not muddy it.
    assert "stderr" not in payload


def test_js_deobfuscate_flags_a_nonzero_exit_that_still_printed_output(tmp_path: Path) -> None:
    """webcrack can exit non-zero yet still emit partial code.

    Before this, code != 0 with stdout returned code/bytes/truncated exactly
    like a clean run, so an unattended pass would read the fragment as the whole
    deobfuscated file. Now the failing exit_code, clean_exit False, and a stderr
    excerpt travel with the salvaged text.
    """
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(3, b"partial code", b"SyntaxError: unexpected token\n")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["code"] == "partial code"
    assert payload["exit_code"] == 3
    assert payload["clean_exit"] is False
    assert "SyntaxError" in payload["stderr"]


def test_js_deobfuscate_still_raises_when_a_nonzero_exit_printed_nothing(tmp_path: Path) -> None:
    """No output and a bad exit is a failure, not an empty clean result."""
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"boom\n")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        JsClient(tool).deobfuscate(src)

    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 1


def test_wasm_wat_flags_a_nonzero_exit_that_still_printed_output(tmp_path: Path) -> None:
    """wasm2wat can print partial WAT then exit non-zero on a malformed module."""
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"(module", b"error: unexpected end\n")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).wat(module)

    assert payload["wat"] == "(module"
    assert payload["exit_code"] == 1
    assert payload["clean_exit"] is False
    assert "unexpected end" in payload["stderr"]


def test_wasm_info_flags_a_nonzero_exit_that_still_printed_output(tmp_path: Path) -> None:
    """wasm-objdump likewise: a non-zero exit with a partial dump is not clean."""
    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(2, b"Sections:\n", b"error: bad section id\n")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).info(module)

    assert payload["objdump"] == "Sections:\n"
    assert payload["exit_code"] == 2
    assert payload["clean_exit"] is False
    assert "bad section id" in payload["stderr"]


def test_unpack_bundle_flags_a_nonzero_exit_that_still_wrote_files(tmp_path: Path) -> None:
    """A partial unpack (non-zero exit, some modules on disk) is not a clean run."""
    from headless_re_mcp.backends.jsre import client as mod

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.js").write_text("1", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(4, b"", b"error: unbalanced module\n")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = mod.JsClient(tool).unpack_bundle(src, out, offset=0, limit=10)

    assert payload["file_count"] == 1
    assert payload["exit_code"] == 4
    assert payload["clean_exit"] is False
    assert "unbalanced module" in payload["stderr"]


def test_unpack_bundle_says_when_the_file_list_was_cut(tmp_path: Path) -> None:
    """The catalog named output_dir, file_count and files, and stopped there.

    Measured against the live client: 2003 files on disk, files capped at
    2000, has_more True. An overnight pass that treated files as the whole
    bundle missed the rest and had no field to notice.
    """
    from headless_re_mcp.backends.jsre import client as mod

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    for index in range(5):
        (out / f"m{index}.js").write_text("1", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, b"", b"")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        patch("headless_re_mcp.backends.jsre.client._MAX_LISTED_FILES", 3),
    ):
        payload = mod.JsClient(tool).unpack_bundle(src, out, offset=0, limit=3)

    assert payload["file_count"] == 5
    assert payload["total"] == 5
    assert payload["count"] == 3
    assert len(payload["files"]) == 3
    assert payload["has_more"] is True
    assert "has_more" in _tool_docstring("js.unpack_bundle")


def test_js_deobfuscate_refuses_an_oversized_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """js.deobfuscate used to hand the file to webcrack with no size check.

    Measured: a 2,097,152-byte file still reached run_bounded (1 launch) and
    came back as code/truncated/bytes. An unattended pass that pointed this
    at a captured bundle would start node on hundreds of megabytes; only the
    stdout cap would hold, and the child would keep a core for the timeout.
    """
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_INPUT_BYTES", 1024)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        launched.append(list(cmd))
        return Completed(0, b"ok", b"")

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_bytes(b"x" * 2048)

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        JsClient(tool).deobfuscate(src)

    assert caught.value.code == "too_large"
    assert caught.value.details.get("size") == 2048
    assert caught.value.details.get("max_file_size") == 1024
    assert launched == []
    assert "too_large" in _tool_docstring("js.deobfuscate")


def test_wasm_wat_refuses_an_oversized_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """wasm.wat used the same unbounded path as js.deobfuscate.

    Measured: a 2,097,152-byte module still reached run_bounded. The output
    cap does not bind the child that has to load the file.
    """
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_INPUT_BYTES", 1024)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        launched.append(list(cmd))
        return Completed(0, b"(module)", b"")

    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"x" * 2048)

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        WasmClient(tool).wat(module)

    assert caught.value.code == "too_large"
    assert caught.value.details.get("size") == 2048
    assert launched == []
    assert "too_large" in _tool_docstring("wasm.wat")
