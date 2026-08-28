"""The stdlib WASM structural reader (summarize_wasm) and wasm.summary routing.

wasm.info / wasm.wat drive the wabt CLI, so the whole WebAssembly surface is
capability_unavailable on a host without wabt -- the common case on Linux. The
module structure an analyst reaches for first (sections, imports, exports,
custom section names) is defined by the binary format and reads with the stdlib
alone. These tests pin that reader on a hand-assembled module, its resilience to
malformed sections (a bad body is a warning, not a failure, and the walk
resumes), its refusal of a non-module, and the service routing that turns a bad
file into a precise envelope rather than a fault.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.common.wasm_format import (
    WasmParseError,
    summarize_wasm,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# --- a minimal WASM assembler, enough to exercise every parsed section --------


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


_HEADER = b"\x00asm\x01\x00\x00\x00"


def _realistic_module() -> bytes:
    types = _section(1, _vec([b"\x60\x00\x00"]))  # one () -> () type
    imports = _section(
        2,
        _vec(
            [
                _name("env") + _name("log") + b"\x00" + _uleb(0),  # func import
                _name("env") + _name("mem") + b"\x02" + b"\x00" + _uleb(1),  # memory
            ]
        ),
    )
    functions = _section(3, _vec([_uleb(0)]))
    memory = _section(5, _vec([b"\x00" + _uleb(1)]))
    globals_ = _section(6, _vec([b"\x7f\x01" + b"\x41\x00\x0b"]))  # i32 mut = 0
    exports = _section(
        7,
        _vec(
            [
                _name("run") + b"\x00" + _uleb(1),  # func export
                _name("memory") + b"\x02" + _uleb(0),  # memory export
            ]
        ),
    )
    code = _section(10, _vec([_uleb(2) + b"\x00\x0b"]))  # empty body
    custom = _section(0, _name("name"))
    return _HEADER + types + imports + functions + memory + globals_ + exports + code + custom


def test_realistic_module_summary() -> None:
    out = summarize_wasm(_realistic_module())
    assert out["version"] == 1
    assert [s["name"] for s in out["sections"]] == [
        "type",
        "import",
        "function",
        "memory",
        "global",
        "export",
        "code",
        "custom",
    ]
    assert out["counts"] == {
        "types": 1,
        "imports": 2,
        "functions": 1,
        "memories": 1,
        "globals": 1,
        "exports": 2,
        "custom": 1,
    }
    assert out["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "env", "name": "mem", "kind": "memory"},
    ]
    assert out["imports_total"] == 2
    assert out["imports_truncated"] is False
    assert out["exports"] == [
        {"name": "run", "kind": "func", "index": 1},
        {"name": "memory", "kind": "memory", "index": 0},
    ]
    assert out["exports_total"] == 2
    assert out["custom_sections"] == ["name"]
    assert out["has_names_section"] is True
    assert out["warnings"] == []


def test_header_only_module_is_empty_not_an_error() -> None:
    out = summarize_wasm(_HEADER)
    assert out["version"] == 1
    assert out["sections"] == []
    assert out["counts"] == {}
    assert out["imports"] == [] and out["exports"] == []
    assert out["warnings"] == []


def test_a_table_and_global_import_descriptor_are_skipped() -> None:
    # table import: reftype (funcref 0x70) + limits; global import: valtype + mut.
    imports = _section(
        2,
        _vec(
            [
                _name("env") + _name("tbl") + b"\x01" + b"\x70" + b"\x00" + _uleb(1),
                _name("env") + _name("g") + b"\x03" + b"\x7f\x00",
            ]
        ),
    )
    exports = _section(7, _vec([_name("g") + b"\x03" + _uleb(0)]))
    out = summarize_wasm(_HEADER + imports + exports)
    assert out["imports"] == [
        {"module": "env", "name": "tbl", "kind": "table"},
        {"module": "env", "name": "g", "kind": "global"},
    ]
    assert out["exports"] == [{"name": "g", "kind": "global", "index": 0}]


def test_a_section_that_overruns_the_file_is_a_warning_that_stops_the_walk() -> None:
    module = _HEADER + bytes([1]) + _uleb(200) + b"\x00"
    out = summarize_wasm(module)
    assert out["sections"] == []
    assert any("overruns" in w for w in out["warnings"])


def test_a_bad_section_body_does_not_sink_the_following_sections() -> None:
    # Import section declares one import but is truncated before the descriptor;
    # the custom "name" section after it must still be read.
    bad_import = _section(2, _vec([_name("env") + _name("f") + b"\x00"]))
    module = _HEADER + bad_import + _section(0, _name("name"))
    out = summarize_wasm(module)
    assert out["counts"]["imports"] == 1
    assert out["imports"] == []
    assert any("import section" in w for w in out["warnings"])
    # The walk resumed: the custom section after the broken one still read.
    assert out["custom_sections"] == ["name"]
    assert out["has_names_section"] is True


def test_long_names_are_bounded() -> None:
    huge = "z" * 20000
    imports = _section(2, _vec([_name("env") + _name(huge) + b"\x00" + _uleb(0)]))
    out = summarize_wasm(_HEADER + imports)
    assert len(out["imports"][0]["name"]) == 4096


def test_import_and_export_lists_are_capped_but_counts_are_whole() -> None:
    entries = [_name("m") + _name(f"f{i}") + b"\x00" + _uleb(0) for i in range(1100)]
    imports = _section(2, _vec(entries))
    out = summarize_wasm(_HEADER + imports)
    assert out["imports_total"] == 1100
    assert len(out["imports"]) == 1024
    assert out["imports_truncated"] is True


@pytest.mark.parametrize(
    "blob",
    [b"", b"\x00as", b"not a wasm module", b"MZ\x90\x00" + b"\x00" * 8],
)
def test_non_modules_raise(blob: bytes) -> None:
    with pytest.raises(WasmParseError):
        summarize_wasm(blob)


# --- service routing ----------------------------------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    from dataclasses import replace

    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_summarizes_a_wasm_file(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_realistic_module())
    result = _service(tmp_path).wasm_summary(str(module))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["imports_total"] == 2
    assert result.data["has_names_section"] is True


def test_service_refuses_a_non_module(tmp_path: Path) -> None:
    junk = tmp_path / "m.wasm"
    junk.write_bytes(b"<html>not wasm</html>")
    result = _service(tmp_path).wasm_summary(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).wasm_summary(str(tmp_path / "nope.wasm"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_refuses_an_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.client as client

    monkeypatch.setattr(client, "_MAX_INPUT_BYTES", 8)
    module = tmp_path / "m.wasm"
    module.write_bytes(_realistic_module())
    result = _service(tmp_path).wasm_summary(str(module))
    assert not result.ok
    assert result.error.code == "too_large"
