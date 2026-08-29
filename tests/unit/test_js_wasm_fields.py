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


def test_wasm_wat_spills_the_full_text_when_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WAT past the inline buffer must be recoverable in full on disk.

    wasm.wat caps the inline wat at the buffer with truncated set; unlike
    js.deobfuscate it has no unpack_bundle to fall back on, so before this the
    tail of a large module's disassembly was simply gone. Feed a body over a
    tiny cap and assert the reply is truncated, the inline text is capped, and
    output_path holds every byte wasm2wat emitted.
    """
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_INLINE", 8)
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    body = "(module (func $f))\n" * 50
    spill = tmp_path / "spill" / "wat-x.wat"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).wat(module, spill_path=spill)

    assert payload["truncated"] is True
    assert len(str(payload["wat"]).encode("utf-8")) <= 8
    assert payload["output_path"] == str(spill)
    assert spill.read_bytes() == body.encode("utf-8")
    assert payload["bytes"] == len(body.encode("utf-8"))


def test_wasm_wat_does_not_spill_when_the_text_fits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Output that fits the buffer must not leave a file or an output_path.

    The spill is a recovery path for a cut result, not an always-on write:
    a small module should return inline with no output_path and no file on
    disk, so retention is not fed a file per call.
    """
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_INLINE", 4096)
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    body = "(module)"
    spill = tmp_path / "spill" / "wat-x.wat"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).wat(module, spill_path=spill)

    assert payload["truncated"] is False
    assert "output_path" not in payload
    assert not spill.exists()


def test_wasm_info_spills_the_full_dump_when_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """wasm.info shares the spill path; a cut objdump is recoverable too."""
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_INLINE", 8)
    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    body = "Section Details:\n" * 40
    spill = tmp_path / "spill" / "objdump-x.txt"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).info(module, spill_path=spill)

    assert payload["truncated"] is True
    assert payload["output_path"] == str(spill)
    assert spill.read_bytes() == body.encode("utf-8")


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


def test_js_deobfuscate_names_where_a_web_session_saves_its_input() -> None:
    """js.deobfuscate's path can be a captured web artifact; the doc must say so.

    service_jsre's module docstring states these tools run "against a web
    session's saved artifacts", and js.deobfuscate accepts any file path, but the
    tool description named no producer -- an agent discovering js.deobfuscate on
    its own could not learn that web.script.source's source_path (a spilled
    script) and web.network.get's body_path (a fetched script body) are exactly
    the inputs it takes. This is the consumer end of the hand-off whose producer
    end is pinned on web.script.source, so the two directions read as one path.
    """
    doc = " ".join(_tool_docstring("js.deobfuscate").split())
    assert "web.script.source" in doc
    assert "source_path" in doc
    assert "web.network.get" in doc
    assert "body_path" in doc


def test_js_wasm_descriptions_name_the_payload_fields() -> None:
    assert "Answers with code" in _tool_docstring("js.deobfuscate")
    assert "Answers with code" in _tool_docstring("js.beautify")
    assert "bytes" in _tool_docstring("js.beautify")
    # A truncated result loses its tail in the reply, so both webcrack text
    # tools now name output_path where the full code landed -- the same in-run
    # recovery the wasm tools give, no second webcrack pass needed. Only
    # js.deobfuscate additionally points at js.unpack_bundle, for splitting a
    # bundle into one file per module (which output_path's single file is not).
    assert "output_path" in _tool_docstring("js.deobfuscate")
    assert "output_path" in _tool_docstring("js.beautify")
    assert "js.unpack_bundle" in _tool_docstring("js.deobfuscate")
    assert "output_dir" in _tool_docstring("js.unpack_bundle")
    assert "has_more" in _tool_docstring("js.unpack_bundle")
    # listing_truncated is produced by the client (the 50k counting cap) and
    # tested against the live backend, but was missing from the catalog: a
    # caller reading total as exact could not learn it was a floor.
    assert "listing_truncated" in _tool_docstring("js.unpack_bundle")
    assert "Answers with wat" in _tool_docstring("wasm.wat")
    assert "bytes" in _tool_docstring("wasm.wat")
    assert "truncated" in _tool_docstring("wasm.info")
    # The WASM tools have no unpack_bundle to fall back on, so a truncated
    # result must name where the full text landed or the tail is a dead end.
    assert "output_path" in _tool_docstring("wasm.wat")
    assert "output_path" in _tool_docstring("wasm.info")
    assert "too_large" in _tool_docstring("js.deobfuscate")
    assert "too_large" in _tool_docstring("js.unpack_bundle")
    assert "too_large" in _tool_docstring("wasm.info")


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


def test_looks_like_wasm_recognizes_the_magic(tmp_path: Path) -> None:
    from headless_re_mcp.backends.jsre.client import _looks_like_wasm

    good = tmp_path / "m.wasm"
    good.write_bytes(b"\x00asm\x01\x00\x00\x00")
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"MZ\x90\x00 not a module")
    short = tmp_path / "s.wasm"
    short.write_bytes(b"\x00as")
    assert _looks_like_wasm(good) is True
    assert _looks_like_wasm(bad) is False
    assert _looks_like_wasm(short) is False


def test_wasm_wat_refuses_a_non_wasm_file(tmp_path: Path) -> None:
    """wat used to hand any file to wasm2wat; a non-module is now caught first.

    Without the magic check a mistargeted path (a PE, a text file, a captured
    HTML response) launches wasm2wat only to fail cryptically; the child ran
    for nothing. The check turns that into a precise invalid_params.
    """
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        launched.append(list(cmd))
        return Completed(0, b"(module)", b"")

    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "not.wasm"
    module.write_bytes(b"MZ this is a PE, not a wasm module")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        WasmClient(tool).wat(module)

    assert caught.value.code == "invalid_params"
    assert launched == []


def test_wasm_info_refuses_a_non_wasm_file(tmp_path: Path) -> None:
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        launched.append(list(cmd))
        return Completed(0, b"", b"")

    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "not.wasm"
    module.write_bytes(b"\x7fELF and definitely not wasm")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run),
        pytest.raises(JsReError) as caught,
    ):
        WasmClient(tool).info(module)

    assert caught.value.code == "invalid_params"
    assert launched == []


def test_wasm_wat_accepts_a_real_module(tmp_path: Path) -> None:
    """The magic check must not block a genuine module reaching wasm2wat."""
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, b"(module)", b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = WasmClient(tool).wat(module)
    assert payload["wat"] == "(module)"
