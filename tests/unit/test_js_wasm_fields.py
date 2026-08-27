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


def test_wasm_info_refuses_when_objdump_is_missing_though_wat_is_present(
    tmp_path: Path,
) -> None:
    """available is gated on wasm2wat, but wasm.info needs wasm-objdump too.

    A wabt install that ships wasm2wat but not wasm-objdump (a partial unpack,
    a renamed binary) still reports available True, yet wasm.info has no tool to
    run. It must refuse with capability_unavailable -- before touching the input
    file or spawning anything -- rather than carry a None tool into a subprocess.
    The split state is forced directly so the check does not depend on whatever
    wabt happens to sit on the test host's PATH.
    """
    client = WasmClient()
    client._wasm2wat = tmp_path / "wasm2wat.exe"
    client._objdump = None
    assert client.available is True

    def explode(*_args: Any, **_kwargs: Any) -> Completed:
        raise AssertionError("a missing wasm-objdump must not reach a subprocess")

    with (
        patch("headless_re_mcp.backends.jsre.client.run_bounded", explode),
        pytest.raises(JsReError) as caught,
    ):
        client.info(tmp_path / "never-written.wasm")
    assert caught.value.code == "capability_unavailable"


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


def test_js_deobfuscate_spills_the_full_output_when_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the inline cap the rest used to be lost; now the whole output lands
    in the spill dir and code_path points to it, mirroring web.dom.snapshot."""
    from headless_re_mcp.backends.jsre import client as mod

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    spill = tmp_path / "spill"
    body = "z" * 50

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    monkeypatch.setattr(mod, "_MAX_INLINE", 10)
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src, spill_dir=spill)

    assert payload["truncated"] is True
    assert len(payload["code"]) == 10
    dest = Path(payload["code_path"])
    assert dest.is_file()
    assert dest.parent == spill
    assert dest.read_text(encoding="utf-8") == body
    assert dest.name.startswith("deob-")
    assert dest.suffix == ".js"


def test_js_deobfuscate_small_output_does_not_spill_even_with_a_dir(
    tmp_path: Path,
) -> None:
    """A result under the inline cap travels whole: no file, no code_path."""
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    spill = tmp_path / "spill"
    body = "short"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src, spill_dir=spill)

    assert payload["truncated"] is False
    assert "code_path" not in payload
    assert not spill.exists() or list(spill.iterdir()) == []


def test_js_deobfuscate_without_a_spill_dir_keeps_the_old_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller that passes no sink still gets a bare truncated flag, no path
    and no file -- the default path the backend field tests exercise."""
    from headless_re_mcp.backends.jsre import client as mod

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    body = "z" * 50

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    monkeypatch.setattr(mod, "_MAX_INLINE", 10)
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src)

    assert payload["truncated"] is True
    assert "code_path" not in payload


def test_deobfuscate_spill_over_the_per_file_cap_leaves_only_the_inline_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spill larger than the per-file ceiling must not be written or half-left
    on disk: the caller keeps the inline prefix and truncated, but no code_path
    and no stray file."""
    from headless_re_mcp.backends.jsre import client as mod

    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    spill = tmp_path / "spill"
    body = "z" * 50

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    monkeypatch.setattr(mod, "_MAX_INLINE", 10)
    monkeypatch.setattr(mod, "_MAX_SPILL_BYTES", 20)
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        payload = JsClient(tool).deobfuscate(src, spill_dir=spill)

    assert payload["truncated"] is True
    assert "code_path" not in payload
    assert not spill.exists() or list(spill.iterdir()) == []


def test_wasm_wat_and_info_spill_under_their_own_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spill path is named after the payload key, so wat -> wat_path (.wat)
    and objdump -> objdump_path (.txt), never a shared or generic field."""
    from headless_re_mcp.backends.jsre import client as mod

    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    spill = tmp_path / "spill"
    body = "(module)" * 20

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    monkeypatch.setattr(mod, "_MAX_INLINE", 10)

    wat_tool = tmp_path / "wasm2wat.exe"
    wat_tool.write_bytes(b"")
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        wat_payload = WasmClient(wat_tool).wat(module, spill_dir=spill)
    wat_dest = Path(wat_payload["wat_path"])
    assert wat_dest.is_file()
    assert wat_dest.read_text(encoding="utf-8") == body
    assert wat_dest.suffix == ".wat"

    objdump_tool = tmp_path / "wasm-objdump.exe"
    objdump_tool.write_bytes(b"")
    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        info_payload = WasmClient(objdump_tool).info(module, spill_dir=spill)
    info_dest = Path(info_payload["objdump_path"])
    assert info_dest.is_file()
    assert info_dest.read_text(encoding="utf-8") == body
    assert info_dest.suffix == ".txt"


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
    # The spill path each oversized reader offers is named after its key.
    assert "code_path" in _tool_docstring("js.deobfuscate")
    assert "code_path" in _tool_docstring("js.beautify")
    assert "wat_path" in _tool_docstring("wasm.wat")
    assert "objdump_path" in _tool_docstring("wasm.info")


def test_jsre_path_outputs_disclose_they_are_not_registered_artifacts() -> None:
    """A returned server path reads like something artifacts.read can open; it
    cannot, because these tools key by a file path and register nothing. Each
    one must say so, the way device.screenshot / device.pull do for their
    unregistered captures, or an agent burns a call on artifacts.read(code_path)
    and reads the not_found as a bug rather than the wrong tool.
    """
    for name in ("js.deobfuscate", "js.beautify", "wasm.wat", "wasm.info", "js.unpack_bundle"):
        # Collapse the docstring's line wrapping so the phrase matches whether or
        # not it happens to straddle a newline.
        doc = " ".join(_tool_docstring(name).split())
        assert "artifacts.read cannot open" in doc, name
        assert "not a registered artifact" in doc or "not the artifact table" in doc, name


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
