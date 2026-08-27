"""wasm.summary gate: the pure-Python parser driven through the real service.

wasm.summary needs no external tool, so the service-level test here always runs
-- it builds a valid module by hand (the same technique the wabt spill gate
trusts) and drives ``AnalysisService.wasm_summary`` end to end, proving both the
success envelope carries the structured surface and a non-module comes back as
an ``invalid_params`` envelope rather than an internal error. A second test
cross-checks against a genuinely toolchain-built module when wat2wasm is
installed, and skips with "skip != pass" when it is not.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService


def _leb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _vec(items: list[bytes]) -> bytes:
    return _leb128(len(items)) + b"".join(items)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _leb128(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _leb128(len(body)) + body


def _module_with_surface() -> bytes:
    """A section-framed module with an imported func, exports and a memory."""
    magic = b"\x00asm\x01\x00\x00\x00"
    type_sec = _section(1, _vec([b"\x60\x00\x00"]))
    import_sec = _section(
        2, _vec([_name("env") + _name("log") + b"\x00" + _leb128(0)])
    )
    func_sec = _section(3, _vec([_leb128(0)]))
    mem_sec = _section(5, _vec([b"\x01" + _leb128(4) + _leb128(64)]))
    export_sec = _section(
        7,
        _vec(
            [
                _name("run") + b"\x00" + _leb128(1),
                _name("mem") + b"\x02" + _leb128(0),
            ]
        ),
    )
    return magic + type_sec + import_sec + func_sec + mem_sec + export_sec


def _sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _active_data_segment(base: int, payload: bytes) -> bytes:
    """A flags=0 data segment: i32.const base ; end ; vec(byte) payload."""
    offset_expr = b"\x41" + _sleb128(base) + b"\x0b"
    return _leb128(0) + offset_expr + _leb128(len(payload)) + payload


def _module_with_data(base: int, payload: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + _section(11, _vec([_active_data_segment(base, payload)]))


def _subsection(sub_id: int, content: bytes) -> bytes:
    return bytes([sub_id]) + _leb128(len(content)) + content


def _function_names_sub(entries: list[tuple[int, str]]) -> bytes:
    body = _leb128(len(entries)) + b"".join(_leb128(idx) + _name(nm) for idx, nm in entries)
    return _subsection(1, body)


def _module_with_names(module_name: str, entries: list[tuple[int, str]]) -> bytes:
    name_body = _name("name") + _subsection(0, _name(module_name)) + _function_names_sub(entries)
    return b"\x00asm\x01\x00\x00\x00" + _section(0, name_body)


def _find(items: list[dict], **fields: object) -> dict | None:
    for item in items:
        if all(item.get(key) == value for key, value in fields.items()):
            return item
    return None


@pytest.mark.integration
def test_wasm_summary_drives_the_service_end_to_end(tmp_path: Path) -> None:
    module = tmp_path / "surface.wasm"
    module.write_bytes(_module_with_surface())

    service = AnalysisService()
    try:
        result = service.wasm_summary(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert _find(data["imports"], module="env", name="log", kind="func") is not None
        assert _find(data["exports"], name="run", kind="func") is not None
        assert _find(data["exports"], name="mem", kind="memory") is not None
        assert data["memory"] == {"initial": 4, "maximum": 64}
        assert data["counts"]["imported_functions"] == 1
        assert data["counts"]["functions"] == 1

        # A file that is not a module must come back as a clean error envelope,
        # not an internal error: this is the hostile-input contract the whole
        # tool surface holds to.
        bogus = tmp_path / "not.wasm"
        bogus.write_bytes(b"PK\x03\x04 this is a zip, not wasm")
        failed = service.wasm_summary(str(bogus))
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_strings_drives_the_service_end_to_end(tmp_path: Path) -> None:
    """wasm.strings must recover data-segment strings through the real service.

    Build a module whose data section holds a C2 URL and a key marker around
    non-printable padding, then drive AnalysisService.wasm_strings end to end:
    the success envelope must carry both strings with their linear-memory addr,
    a contains filter must narrow to matches, and a non-module must come back as
    an invalid_params envelope rather than an internal error.
    """
    base = 2048
    url = b"https://c2.example/beacon"
    key = b"API_KEY=hunter2"
    payload = url + b"\x00\x01\x02" + key + b"\x00"
    module = tmp_path / "strings.wasm"
    module.write_bytes(_module_with_data(base, payload))

    service = AnalysisService()
    try:
        result = service.wasm_strings(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        found = {item["string"]: item for item in data["strings"]}
        assert url.decode() in found
        assert key.decode() in found
        assert found[url.decode()]["addr"] == base
        assert found[key.decode()]["addr"] == base + payload.index(key)
        assert data["data_segments"] == 1

        filtered = service.wasm_strings(str(module), contains="c2.example")
        assert filtered.ok, filtered.error
        assert [item["string"] for item in filtered.data["strings"]] == [url.decode()]
        assert filtered.data["filtered"] is True

        bogus = tmp_path / "not.wasm"
        bogus.write_bytes(b"PK\x03\x04 this is a zip, not wasm")
        failed = service.wasm_strings(str(bogus))
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_sections_drives_the_service_end_to_end(tmp_path: Path) -> None:
    """wasm.sections must lay out the section table through the real service.

    Reuse the import/export/memory module and drive AnalysisService.wasm_sections
    end to end: the success envelope must name the standard sections in order,
    each offset must point inside the file and the offsets must strictly
    increase, and a non-module must come back as an invalid_params envelope.
    """
    module_bytes = _module_with_surface()
    module = tmp_path / "surface.wasm"
    module.write_bytes(module_bytes)

    service = AnalysisService()
    try:
        result = service.wasm_sections(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        names = [s["name"] for s in data["sections"]]
        assert names == ["type", "import", "function", "memory", "export"]
        prev = 7  # past the 8-byte header
        for section in data["sections"]:
            assert section["offset"] > prev
            assert section["offset"] + section["size"] <= len(module_bytes)
            prev = section["offset"]

        bogus = tmp_path / "not.wasm"
        bogus.write_bytes(b"PK\x03\x04 this is a zip, not wasm")
        failed = service.wasm_sections(str(bogus))
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_sections_reads_a_wat2wasm_built_module(tmp_path: Path) -> None:
    """Cross-check the section layout against a module a real toolchain produced."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — toolchain gate not run (skip != pass)")
    wat = tmp_path / "mod.wat"
    wat.write_text(
        "(module\n"
        '  (import "env" "log" (func $log (param i32)))\n'
        '  (memory (export "mem") 1)\n'
        '  (func (export "run") (param i32) (result i32) local.get 0)\n'
        '  (data (i32.const 0) "hi"))\n',
        encoding="utf-8",
    )
    module = tmp_path / "mod.wasm"
    built = subprocess.run(  # noqa: S603 - fixed argv, tool discovered on PATH
        [wat2wasm, str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if built.returncode != 0 or not module.is_file():
        detail = built.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"wat2wasm could not build the fixture ({detail}) — skip != pass")

    file_len = module.stat().st_size
    service = AnalysisService()
    try:
        result = service.wasm_sections(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        names = {s["name"] for s in data["sections"]}
        # A module with an import, a defined func with a body, a memory and a
        # data segment must show these standard sections in the layout.
        for want in ("type", "import", "function", "memory", "export", "code", "data"):
            assert want in names, f"{want} section missing from {sorted(names)}"
        for section in data["sections"]:
            assert 8 <= section["offset"] <= file_len
            assert section["offset"] + section["size"] <= file_len
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_names_drives_the_service_end_to_end(tmp_path: Path) -> None:
    """wasm.names must recover the name-section symbol table through the service.

    Build a module whose name section names the module and three functions (one
    of them never exported), then drive AnalysisService.wasm_names end to end:
    the success envelope must carry has_name_section, the module name and every
    (index, name) pair, a contains filter must narrow to matches, and a
    non-module must come back as an invalid_params envelope, not an internal
    error.
    """
    module = tmp_path / "names.wasm"
    module.write_bytes(
        _module_with_names(
            "app.wasm",
            [(0, "_start"), (3, "decryptPayload"), (7, "sendBeacon")],
        )
    )

    service = AnalysisService()
    try:
        result = service.wasm_names(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data["has_name_section"] is True
        assert data["module_name"] == "app.wasm"
        assert _find(data["functions"], index=3, name="decryptPayload") is not None
        assert _find(data["functions"], index=7, name="sendBeacon") is not None
        assert data["total"] == 3

        filtered = service.wasm_names(str(module), contains="decrypt")
        assert filtered.ok, filtered.error
        assert [item["name"] for item in filtered.data["functions"]] == ["decryptPayload"]
        assert filtered.data["filtered"] is True

        bogus = tmp_path / "not.wasm"
        bogus.write_bytes(b"PK\x03\x04 this is a zip, not wasm")
        failed = service.wasm_names(str(bogus))
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_names_reads_a_wat2wasm_built_module(tmp_path: Path) -> None:
    """Cross-check the name-section parser against a --debug-names build.

    wat2wasm emits the name section from the WAT function names only when asked
    with --debug-names, so this proves the parser reads a name section a real
    toolchain produced, not just the hand-framed fixtures.
    """
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — toolchain gate not run (skip != pass)")
    wat = tmp_path / "names.wat"
    wat.write_text(
        "(module\n"
        "  (func $decryptPayload (param i32) (result i32) local.get 0)\n"
        "  (func $sendBeacon)\n"
        '  (export "decryptPayload" (func $decryptPayload)))\n',
        encoding="utf-8",
    )
    module = tmp_path / "names.wasm"
    built = subprocess.run(  # noqa: S603 - fixed argv, tool discovered on PATH
        [wat2wasm, "--debug-names", str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if built.returncode != 0 or not module.is_file():
        detail = built.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"wat2wasm could not build the fixture ({detail}) — skip != pass")

    service = AnalysisService()
    try:
        result = service.wasm_names(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data["has_name_section"] is True
        names = {item["name"] for item in data["functions"]}
        # sendBeacon is never exported, so only the name section names it -- the
        # whole point of decoding this section.
        assert "decryptPayload" in names
        assert "sendBeacon" in names
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_strings_reads_a_wat2wasm_built_module(tmp_path: Path) -> None:
    """Cross-check the string scanner against a toolchain-built data segment."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — toolchain gate not run (skip != pass)")
    wat = tmp_path / "strs.wat"
    wat.write_text(
        "(module\n"
        "  (memory 1)\n"
        '  (data (i32.const 1024) "https://payload.example/x\\00SECRET_TOKEN_9\\00"))\n',
        encoding="utf-8",
    )
    module = tmp_path / "strs.wasm"
    built = subprocess.run(  # noqa: S603 - fixed argv, tool discovered on PATH
        [wat2wasm, str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if built.returncode != 0 or not module.is_file():
        detail = built.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"wat2wasm could not build the fixture ({detail}) — skip != pass")

    service = AnalysisService()
    try:
        result = service.wasm_strings(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        strings = {item["string"] for item in data["strings"]}
        assert "https://payload.example/x" in strings
        assert "SECRET_TOKEN_9" in strings
        # The first string sits at the segment's declared base; wat2wasm may add
        # its own data segments, so assert the URL's addr is the 1024 we placed.
        url_item = next(
            item for item in data["strings"] if item["string"] == "https://payload.example/x"
        )
        assert url_item["addr"] == 1024
    finally:
        service.close_all()


def _module_with_functions() -> bytes:
    """A module with two types, an imported func + memory, and two defined funcs."""
    magic = b"\x00asm\x01\x00\x00\x00"
    type_sec = _section(1, _vec([b"\x60\x00\x00", b"\x60\x01\x7f\x01\x7f"]))
    import_sec = _section(
        2,
        _vec(
            [
                _name("env") + _name("log") + b"\x00" + _leb128(1),  # func, type1
                _name("env") + _name("mem") + b"\x02" + b"\x00" + _leb128(1),  # memory
            ]
        ),
    )
    func_sec = _section(3, _vec([_leb128(0), _leb128(1)]))  # defined: type0, type1
    name_body = _name("name") + _function_names_sub([(1, "run"), (2, "helper")])
    name_sec = _section(0, name_body)
    return magic + type_sec + import_sec + func_sec + name_sec


@pytest.mark.integration
def test_wasm_functions_drives_the_service_end_to_end(tmp_path: Path) -> None:
    """wasm.functions must build the signature table through the real service.

    Build a module with an imported func (of an (i32)->(i32) type), an imported
    memory that must not consume a function index, and two defined funcs named
    in the name section, then drive AnalysisService.wasm_functions end to end:
    the imported/defined split, the resolved signatures, and the name-by-index
    join must all come back, a contains filter must narrow to matches, and a
    non-module must come back as an invalid_params envelope, not an internal
    error.
    """
    module = tmp_path / "functions.wasm"
    module.write_bytes(_module_with_functions())

    service = AnalysisService()
    try:
        result = service.wasm_functions(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data["imported_count"] == 1
        assert data["defined_count"] == 2
        assert data["total"] == data["count"] == 3

        imported = _find(data["functions"], index=0, kind="imported")
        assert imported is not None
        assert imported["module"] == "env"
        assert imported["import_name"] == "log"
        assert imported["params"] == ["i32"]
        assert imported["results"] == ["i32"]

        # The imported memory must not have shifted the defined function indices.
        run = _find(data["functions"], index=1, kind="defined", name="run")
        assert run is not None
        assert run["params"] == [] and run["results"] == []
        helper = _find(data["functions"], index=2, kind="defined", name="helper")
        assert helper is not None
        assert helper["params"] == ["i32"] and helper["results"] == ["i32"]

        filtered = service.wasm_functions(str(module), contains="helper")
        assert filtered.ok, filtered.error
        assert [fn["name"] for fn in filtered.data["functions"]] == ["helper"]
        assert filtered.data["filtered"] is True

        bogus = tmp_path / "not.wasm"
        bogus.write_bytes(b"PK\x03\x04 this is a zip, not wasm")
        failed = service.wasm_functions(str(bogus))
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_functions_reads_a_wat2wasm_built_module(tmp_path: Path) -> None:
    """Cross-check the function/signature join against a toolchain-built module."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — toolchain gate not run (skip != pass)")
    wat = tmp_path / "fns.wat"
    wat.write_text(
        "(module\n"
        '  (import "env" "log" (func $log (param i32)))\n'
        '  (func (export "run") (param i32 i32) (result i32) local.get 0)\n'
        "  (func $init))\n",
        encoding="utf-8",
    )
    module = tmp_path / "fns.wasm"
    built = subprocess.run(  # noqa: S603 - fixed argv, tool discovered on PATH
        [wat2wasm, "--debug-names", str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if built.returncode != 0 or not module.is_file():
        detail = built.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"wat2wasm could not build the fixture ({detail}) — skip != pass")

    service = AnalysisService()
    try:
        result = service.wasm_functions(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        # One imported func (index 0), two defined funcs ($run, $init) after it.
        assert data["imported_count"] == 1
        assert data["defined_count"] == 2
        imported = _find(data["functions"], index=0, kind="imported")
        assert imported is not None
        assert imported["module"] == "env" and imported["import_name"] == "log"
        assert imported["params"] == ["i32"]
        # $run takes (i32, i32) and returns i32 -- the signature the type/function
        # sections encode, resolved without any wabt help.
        run = _find(data["functions"], index=1, kind="defined")
        assert run is not None
        assert run["params"] == ["i32", "i32"]
        assert run["results"] == ["i32"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_summary_reads_a_wat2wasm_built_module(tmp_path: Path) -> None:
    """Cross-check the parser against a module a real toolchain produced."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — toolchain gate not run (skip != pass)")
    wat = tmp_path / "mod.wat"
    wat.write_text(
        "(module\n"
        '  (import "env" "log" (func $log (param i32)))\n'
        '  (import "js" "flag" (global $flag i32))\n'
        '  (memory (export "mem") 2 16)\n'
        '  (func (export "run") (param i32) (result i32) local.get 0)\n'
        "  (func $init)\n"
        "  (start $init))\n",
        encoding="utf-8",
    )
    module = tmp_path / "mod.wasm"
    built = subprocess.run(  # noqa: S603 - fixed argv, tool discovered on PATH
        [wat2wasm, str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if built.returncode != 0 or not module.is_file():
        detail = built.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"wat2wasm could not build the fixture ({detail}) — skip != pass")

    service = AnalysisService()
    try:
        result = service.wasm_summary(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert _find(data["imports"], module="env", name="log", kind="func") is not None
        assert _find(data["imports"], module="js", name="flag", kind="global") is not None
        assert _find(data["exports"], name="run", kind="func") is not None
        assert _find(data["exports"], name="mem", kind="memory") is not None
        assert data["memory"] == {"initial": 2, "maximum": 16}
        assert data["has_start"] is True
        # One function is imported; the two defined ($run, $init) come from the
        # module's own function section.
        assert data["counts"]["imported_functions"] == 1
        assert data["counts"]["functions"] == 2
    finally:
        service.close_all()
