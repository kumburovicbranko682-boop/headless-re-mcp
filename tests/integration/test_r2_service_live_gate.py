"""r2 portable backend proven through AnalysisService, not just the client.

test_m11_r2_live_gate.py drives R2Client directly. This gate exercises the same
radare2 analysis through the real entry point an agent uses -- create a session
on a PE, then r2.functions / r2.disasm / r2.xrefs off the service -- so the
wiring (settings discovery, session binary, address mapping, structured error
envelope) is proven on Linux too, not only the raw client. skip != pass when r2
is absent; the committed in-tree PE keeps it runnable on any host.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILT_FIXTURE = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
_COMMITTED_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"

# A named, un-inlinable function so the native (ELF) gate can find it by name,
# a distinctive string literal for r2.strings, and a libc call so r2.imports has
# a named import to recover. -O0 keeps re_mcp_triple from being inlined into main.
_ELF_MARKER = "re_mcp_marker"
_ELF_SOURCE = (
    "#include <stdio.h>\n"
    "int re_mcp_triple(int x) { return x * 3 + 1; }\n"
    "int main(void) {\n"
    "  int v = re_mcp_triple(7);\n"
    f'  printf("{_ELF_MARKER} %d\\n", v);\n'
    "  return v;\n"
    "}\n"
)


def _gate_fixture() -> Path:
    if _BUILT_FIXTURE.is_file():
        return _BUILT_FIXTURE
    if _COMMITTED_FIXTURE.is_file():
        return _COMMITTED_FIXTURE
    pytest.skip(f"no r2 fixture available: {_BUILT_FIXTURE} nor {_COMMITTED_FIXTURE}")


def _build_elf_fixture(tmp_path: Path) -> Path:
    """Compile a tiny ELF with the host C compiler, or skip (skip != pass)."""
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — native ELF Gate not run (skip != pass)")
    source = tmp_path / "re_mcp_probe.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    out = tmp_path / "re_mcp_probe.elf"
    try:
        completed = subprocess.run(
            [compiler, "-O0", "-o", str(out), str(source)],
            capture_output=True,
            timeout=120.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover - host dependent
        pytest.skip(f"C compiler unusable ({exc}) — native ELF Gate not run (skip != pass)")
    if completed.returncode != 0 or not out.is_file():
        pytest.skip(
            "C compiler produced no ELF "
            f"({completed.stderr.decode('utf-8', 'replace')[:200]}) — skip != pass"
        )
    return out


# A named, un-inlinable function main calls, so the Mach-O gate can recover it
# by name and follow the call as an xref. No libc string/import here: a
# zig-cross-linked Mach-O surfaces those differently than an ELF, and the point
# of this gate is the native Mach-O identity + r2 function/xref surface.
_MACHO_SOURCE = (
    "int re_mcp_triple(int x) { return x * 3 + 1; }\n"
    "int main(void) { return re_mcp_triple(7); }\n"
)
# Thin Mach-O magics (32/64-bit, either byte order); the fat magic is excluded
# on purpose, matching classify_target.
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
}


def _build_macho_fixture(tmp_path: Path) -> Path:
    """Compile a tiny Mach-O x86_64 executable, or skip (skip != pass).

    A Mach-O *executable* is required, not a bare object: r2 seeds its function
    analysis from the entrypoint, and on r2 6.x an object exposes neither an
    entry nor its symbol table, so nothing named comes back. On Linux ``zig cc
    -target x86_64-macos`` cross-links one without the macOS SDK; on a mac the
    host compiler emits Mach-O directly. Absent either, skip honestly.
    """
    source = tmp_path / "re_mcp_probe_macho.c"
    source.write_text(_MACHO_SOURCE, encoding="utf-8")
    out = tmp_path / "re_mcp_probe_macho"
    commands: list[list[str]] = []
    zig = shutil.which("zig")
    if zig is not None:
        commands.append([zig, "cc", "-target", "x86_64-macos", "-O0", "-o", str(out), str(source)])
    if sys.platform == "darwin":
        host = shutil.which("cc") or shutil.which("clang")
        if host is not None:
            commands.append([host, "-O0", "-o", str(out), str(source)])
    if not commands:
        pytest.skip("no Mach-O cross toolchain (zig / darwin cc) — skip != pass")
    last = ""
    for argv in commands:
        try:
            completed = subprocess.run(argv, capture_output=True, timeout=180.0)
        except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover - host dependent
            last = str(exc)
            continue
        if completed.returncode == 0 and out.is_file() and out.read_bytes()[:4] in _MACHO_MAGICS:
            return out
        last = completed.stderr.decode("utf-8", "replace")[:200]
    pytest.skip(f"no toolchain emitted a Mach-O executable ({last}) — skip != pass")


def _assert_mapped(address: object) -> None:
    assert isinstance(address, dict), address
    assert "va" in address or "rva" in address, address


@pytest.mark.integration
def test_r2_service_functions_disasm_xrefs_end_to_end() -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        opened = service.r2_open(session_id, timeout=60.0)
        assert opened.ok, opened.error

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok and funcs.data is not None, funcs.error
        assert funcs.data.get("parsed") is True
        assert funcs.data.get("count", 0) >= 1
        assert isinstance(funcs.data.get("architecture"), str) and funcs.data["architecture"]
        items = funcs.data["items"]
        # Every function the service hands back must be address-mapped, since an
        # agent pivots from this list straight into disasm/xrefs by address.
        for item in items:
            _assert_mapped(item.get("address"))

        # The documented integer function-start field must survive r2's key
        # drift (5.x ``offset`` vs 6.x ``addr``); the mapping aliases it back.
        for item in items:
            assert isinstance(item.get("offset"), int), item

        entry = int(items[0]["offset"])
        dis = service.r2_disasm(session_id, entry, count=8, timeout=60.0)
        assert dis.ok and dis.data is not None, dis.error
        assert dis.data.get("parsed") is True
        ops = dis.data.get("items") or []
        assert ops, "disassembly returned no instructions"
        for op in ops:
            _assert_mapped(op.get("address"))
            assert op.get("opcode"), op
            assert op.get("bytes"), op
        # Real code decodes cleanly: none of the rows are undecodable bytes.
        assert dis.data.get("invalid_count") == 0, dis.data

        xref = service.r2_xrefs(session_id, entry, timeout=60.0)
        assert xref.ok and xref.data is not None, xref.error
        assert xref.data.get("parsed") is True
        assert isinstance(xref.data.get("items"), list)
        # Every xref row names its direction and carries mapped edges, whichever
        # r2 command family (5.x axj dump / 6.x axtj+axfj) produced it.
        for row in xref.data["items"]:
            assert row.get("direction") in {"to", "from"}, row
            assert isinstance(row.get("from"), int) and isinstance(row.get("to"), int), row
            _assert_mapped(row.get("from_address"))
            _assert_mapped(row.get("to_address"))
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_lists_sections_with_permissions() -> None:
    """r2.sections must map the section table and name each section's perms.

    Where .text/.rodata/.data land, and whether any section is both writable
    and executable, is a first-move triage none of the other r2 readers answer.
    The committed PE has a .text section radare2 marks executable, so a green
    proves the section map decodes and the row is address-mapped. skip != pass
    when r2 is absent; the in-tree PE keeps it runnable on any host.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        sections = service.r2_sections(session_id, timeout=60.0)
        assert sections.ok and sections.data is not None, sections.error
        assert sections.data.get("parsed") is True
        rows = sections.data.get("items") or []
        assert rows, "no sections decoded"
        for row in rows:
            assert isinstance(row.get("name"), str), row
            assert isinstance(row.get("perm"), str) and row["perm"], row
        # The code section is present, named, and marked executable.
        text = next((row for row in rows if row.get("name") == ".text"), None)
        assert text is not None, [row.get("name") for row in rows]
        assert "x" in text["perm"], text
        _assert_mapped(text.get("address"))
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_lists_the_symbol_table() -> None:
    """r2.symbols must return the full symbol table, imports flagged and mapped.

    Unlike r2.exports, the symbol table carries every symbol radare2 read and
    tags each type/bind/is_imported. The committed PE resolves its API imports
    into the symbol table, so at least one row must be flagged is_imported and
    come back address-mapped, proving the reader decodes and enriches the whole
    table. skip != pass when r2 is absent; the in-tree PE keeps it runnable.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        symbols = service.r2_symbols(session_id, timeout=60.0)
        assert symbols.ok and symbols.data is not None, symbols.error
        assert symbols.data.get("parsed") is True
        rows = symbols.data.get("items") or []
        assert rows, "no symbols decoded"
        for row in rows:
            assert isinstance(row.get("name"), str) and row["name"], row
            assert isinstance(row.get("type"), str), row
        imported = [row for row in rows if row.get("is_imported")]
        assert imported, "PE symbol table names none of its imports"
        _assert_mapped(imported[0].get("address"))
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_lists_the_program_entrypoint() -> None:
    """r2.entrypoints must name where execution begins and map it.

    On a stripped target the program entry is the only address an agent can
    seed r2.disasm from, so the reader must decode at least the ``program``
    entry and hand it back address-mapped. The committed PE has exactly such an
    entry. skip != pass when r2 is absent; the in-tree PE keeps it runnable.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        entries = service.r2_entrypoints(session_id, timeout=60.0)
        assert entries.ok and entries.data is not None, entries.error
        assert entries.data.get("parsed") is True
        rows = entries.data.get("items") or []
        assert rows, "no entrypoints decoded"
        program = next((row for row in rows if row.get("type") == "program"), None)
        assert program is not None, [row.get("type") for row in rows]
        _assert_mapped(program.get("address"))
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_analyzes_a_native_elf_end_to_end(tmp_path: Path) -> None:
    """A native ELF must open as a session and analyse through r2 -- the portable
    backend's whole point on non-Windows targets.

    Before native classification, create_session rejected an ELF as "not a PE
    file", so this path was unreachable. Now it must classify as native, open,
    and let r2 recover the named function and disassemble it. skip != pass.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — native ELF Gate not run (skip≠pass)")
    elf = _build_elf_fixture(tmp_path)
    service = AnalysisService(Settings.load())
    created = service.create_session(str(elf))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session.get("target") == "native"
    # Native identity rides along at creation (stdlib header parse, no r2 yet).
    native = session.get("metadata", {}).get("native", {})
    assert native.get("format") == "elf"
    assert native.get("bits") in {32, 64}
    assert isinstance(native.get("machine"), str) and native["machine"]
    # The Architecture enum only models x86/x64, so on those hosts the session
    # names the arch and every r2 payload must echo it; on a non-x86 host (an
    # aarch64 runner) it is None and r2 simply carries no arch field. Deriving
    # the expectation from the session keeps this gate host-agnostic.
    expect_arch = session.get("architecture")
    session_id = str(session["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok and funcs.data is not None, funcs.error
        assert funcs.data.get("parsed") is True
        assert funcs.data.get("architecture") == expect_arch, funcs.data.get("architecture")
        by_name = {item.get("name"): item for item in funcs.data.get("items", [])}
        assert "main" in by_name, sorted(by_name)
        triple = next((n for n in by_name if "re_mcp_triple" in (n or "")), None)
        assert triple is not None, sorted(by_name)

        entry = int(by_name["main"]["offset"])
        dis = service.r2_disasm(session_id, entry, count=8, timeout=60.0)
        assert dis.ok and dis.data is not None, dis.error
        assert dis.data.get("parsed") is True
        assert dis.data.get("invalid_count") == 0, dis.data
        assert dis.data.get("items"), "main disassembled to nothing"

        # The whole r2 read surface must work on a native target, not just
        # functions/disasm, and every address it hands back must carry the
        # architecture an agent needs to interpret it. On ELF r2 reports
        # absolute vaddrs (no image base), so mapped means va, not rva.
        strings = service.r2_strings(session_id, timeout=60.0)
        assert strings.ok and strings.data is not None, strings.error
        assert strings.data.get("parsed") is True
        assert strings.data.get("architecture") == expect_arch
        literals = strings.data.get("items") or []
        marker = next((s for s in literals if _ELF_MARKER in (s.get("string") or "")), None)
        assert marker is not None, [s.get("string") for s in literals]
        _assert_mapped(marker.get("address"))
        assert marker["address"].get("architecture") == expect_arch, marker

        # r2.read is the data-side reader. Point it at the marker string's own
        # address -- a .rodata data address r2.disasm would only decode as a run
        # of invalid bytes -- and the exact bytes must come back, byte for byte.
        # This is the "follow a data xref to a blob, then read it" workflow the
        # code-facing readers cannot serve. The window is the marker length, so
        # the bytes must decode to exactly the marker with no short read.
        marker_va = int(marker["address"]["va"])
        want = _ELF_MARKER.encode("ascii")
        read = service.r2_read(session_id, marker_va, size=len(want), timeout=60.0)
        assert read.ok and read.data is not None, read.error
        assert read.data.get("encoding") == "hex"
        assert read.data.get("count") == len(want), read.data
        assert bytes.fromhex(read.data["data"]) == want, read.data
        assert read.data.get("address_va") == marker_va
        _assert_mapped(read.data.get("address"))
        assert read.data["address"].get("architecture") == expect_arch, read.data
        assert "short_read" not in read.data
        # The same address decoded as code is undecodable bytes: r2.disasm there
        # returns rows it flags invalid, which is exactly why the data reader
        # exists beside it. (Some bytes may chance-decode, so assert only that at
        # least one row is invalid, not that every one is.)
        as_code = service.r2_disasm(session_id, marker_va, count=len(want), timeout=60.0)
        assert as_code.ok and as_code.data is not None, as_code.error
        assert as_code.data.get("invalid_count", 0) >= 1, as_code.data

        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok and imports.data is not None, imports.error
        assert imports.data.get("parsed") is True
        assert imports.data.get("architecture") == expect_arch
        import_names = {item.get("name") for item in imports.data.get("items", [])}
        assert "printf" in import_names, sorted(n for n in import_names if n)

        exports = service.r2_exports(session_id, timeout=60.0)
        assert exports.ok and exports.data is not None, exports.error
        assert exports.data.get("parsed") is True
        exported = {item.get("name"): item for item in exports.data.get("items", [])}
        # Exports name the raw symbol (re_mcp_triple); the function list flags it
        # as sym.re_mcp_triple. Match on the substring so the prefix drift between
        # r2's symbol and flag namespaces does not make the gate brittle.
        exported_triple = next((n for n in exported if "re_mcp_triple" in (n or "")), None)
        assert exported_triple is not None, sorted(n for n in exported if n)
        _assert_mapped(exported[exported_triple].get("address"))

        # Sections map on the native target too, carrying the architecture: the
        # ELF .text section must come back executable and address-mapped.
        sections = service.r2_sections(session_id, timeout=60.0)
        assert sections.ok and sections.data is not None, sections.error
        assert sections.data.get("parsed") is True
        assert sections.data.get("architecture") == expect_arch
        sect_rows = sections.data.get("items") or []
        text_sect = next((row for row in sect_rows if row.get("name") == ".text"), None)
        assert text_sect is not None, [row.get("name") for row in sect_rows]
        assert "x" in (text_sect.get("perm") or ""), text_sect
        _assert_mapped(text_sect.get("address"))
        assert text_sect["address"].get("architecture") == expect_arch, text_sect

        # Symbols are the full table, a superset of exports: main and the CRT's
        # local helpers are here even though the export table never lists them.
        symbols = service.r2_symbols(session_id, timeout=60.0)
        assert symbols.ok and symbols.data is not None, symbols.error
        assert symbols.data.get("parsed") is True
        assert symbols.data.get("architecture") == expect_arch
        sym_rows = symbols.data.get("items") or []
        sym_main = next((row for row in sym_rows if row.get("name") == "main"), None)
        assert sym_main is not None, sorted(row.get("name") for row in sym_rows)
        assert sym_main.get("type") == "FUNC", sym_main
        _assert_mapped(sym_main.get("address"))
        assert sym_main["address"].get("architecture") == expect_arch, sym_main
        func_names = {row.get("name") for row in sym_rows if row.get("type") == "FUNC"}
        exported_names = set(exported)
        # The symbol table names functions the export table does not: that
        # superset is the whole reason r2.symbols exists beside r2.exports.
        assert func_names - exported_names, (sorted(func_names), sorted(exported_names))

        # The program entrypoint resolves on the native target too, carrying the
        # architecture: an ELF always has a program entry (_start), mapped.
        entries = service.r2_entrypoints(session_id, timeout=60.0)
        assert entries.ok and entries.data is not None, entries.error
        assert entries.data.get("parsed") is True
        assert entries.data.get("architecture") == expect_arch
        entry_rows = entries.data.get("items") or []
        program = next((row for row in entry_rows if row.get("type") == "program"), None)
        assert program is not None, [row.get("type") for row in entry_rows]
        _assert_mapped(program.get("address"))
        assert program["address"].get("architecture") == expect_arch, program

        # xrefs must resolve on the native target too: main calls re_mcp_triple,
        # so a "to" edge into the function has to come back with mapped endpoints.
        target = int(exported[exported_triple]["address"]["va"])
        xref = service.r2_xrefs(session_id, target, timeout=60.0)
        assert xref.ok and xref.data is not None, xref.error
        assert xref.data.get("parsed") is True
        rows = xref.data.get("items") or []
        assert any(row.get("direction") == "to" for row in rows), rows
        for row in rows:
            assert row.get("direction") in {"to", "from"}, row
            _assert_mapped(row.get("from_address"))
            _assert_mapped(row.get("to_address"))
            assert row["to_address"].get("architecture") == expect_arch, row
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_analyzes_a_native_macho_end_to_end(tmp_path: Path) -> None:
    """A native Mach-O must open as a session and analyse through r2 too.

    ELF is the common non-Windows target, but the native line also claims
    Mach-O: classify_target maps its magic to NATIVE and describe_native reads
    its header. Only synthetic headers exercised that until now. This builds a
    real Mach-O executable (zig cross-compile, or a mac host) and drives the
    same r2 surface the ELF gate does -- classification, functions, disasm,
    exports and an xref edge -- with every address carrying the architecture.
    skip != pass when r2 or a Mach-O toolchain is absent.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — native Mach-O Gate not run (skip≠pass)")
    macho = _build_macho_fixture(tmp_path)
    service = AnalysisService(Settings.load())
    created = service.create_session(str(macho))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session.get("target") == "native"
    native = session.get("metadata", {}).get("native", {})
    assert native.get("format") == "macho", native
    assert native.get("bits") in {32, 64}, native
    assert isinstance(native.get("machine"), str) and native["machine"]
    expect_arch = session.get("architecture")
    session_id = str(session["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok

        funcs = service.r2_functions(session_id, timeout=60.0)
        assert funcs.ok and funcs.data is not None, funcs.error
        assert funcs.data.get("parsed") is True
        assert funcs.data.get("architecture") == expect_arch, funcs.data.get("architecture")
        by_name = {item.get("name"): item for item in funcs.data.get("items", [])}
        # r2 flags the Mach-O entry as sym._main / entry0; match main by substring
        # so the flag-namespace prefix does not make the gate brittle.
        main_name = next((n for n in by_name if n and "main" in n), None)
        assert main_name is not None, sorted(by_name)
        triple = next((n for n in by_name if "re_mcp_triple" in (n or "")), None)
        assert triple is not None, sorted(by_name)

        entry = int(by_name[main_name]["offset"])
        dis = service.r2_disasm(session_id, entry, count=8, timeout=60.0)
        assert dis.ok and dis.data is not None, dis.error
        assert dis.data.get("parsed") is True
        assert dis.data.get("invalid_count") == 0, dis.data
        assert dis.data.get("items"), "main disassembled to nothing"

        exports = service.r2_exports(session_id, timeout=60.0)
        assert exports.ok and exports.data is not None, exports.error
        assert exports.data.get("parsed") is True
        assert exports.data.get("architecture") == expect_arch
        exported = {item.get("name"): item for item in exports.data.get("items", [])}
        exported_triple = next((n for n in exported if "re_mcp_triple" in (n or "")), None)
        assert exported_triple is not None, sorted(n for n in exported if n)
        addr = exported[exported_triple].get("address")
        _assert_mapped(addr)
        assert addr.get("architecture") == expect_arch, exported[exported_triple]

        # main calls re_mcp_triple, so a "to" edge must resolve on Mach-O as well.
        target = int(addr["va"])
        xref = service.r2_xrefs(session_id, target, timeout=60.0)
        assert xref.ok and xref.data is not None, xref.error
        assert xref.data.get("parsed") is True
        rows = xref.data.get("items") or []
        assert any(row.get("direction") == "to" for row in rows), rows
        for row in rows:
            assert row.get("direction") in {"to", "from"}, row
            _assert_mapped(row.get("from_address"))
            _assert_mapped(row.get("to_address"))

        # The rest of the static read surface must resolve on Mach-O too, at
        # parity with the ELF gate. Mach-O names sections __TEXT.__text (not
        # .text) and prefixes symbols with an underscore, so match by shape and
        # substring rather than the ELF spellings.
        sections = service.r2_sections(session_id, timeout=60.0)
        assert sections.ok and sections.data is not None, sections.error
        assert sections.data.get("parsed") is True
        assert sections.data.get("architecture") == expect_arch
        sect_rows = sections.data.get("items") or []
        exec_sect = next((row for row in sect_rows if "x" in (row.get("perm") or "")), None)
        assert exec_sect is not None, [row.get("name") for row in sect_rows]
        _assert_mapped(exec_sect.get("address"))

        symbols = service.r2_symbols(session_id, timeout=60.0)
        assert symbols.ok and symbols.data is not None, symbols.error
        assert symbols.data.get("parsed") is True
        assert symbols.data.get("architecture") == expect_arch
        sym_rows = symbols.data.get("items") or []
        sym_triple = next(
            (row for row in sym_rows if "re_mcp_triple" in (row.get("name") or "")), None
        )
        assert sym_triple is not None, sorted(r.get("name") for r in sym_rows if r.get("name"))
        _assert_mapped(sym_triple.get("address"))

        entries = service.r2_entrypoints(session_id, timeout=60.0)
        assert entries.ok and entries.data is not None, entries.error
        assert entries.data.get("parsed") is True
        assert entries.data.get("architecture") == expect_arch
        entry_rows = entries.data.get("items") or []
        program = next((row for row in entry_rows if row.get("type") == "program"), None)
        assert program is not None, [row.get("type") for row in entry_rows]
        _assert_mapped(program.get("address"))
        assert program["address"].get("architecture") == expect_arch, program
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_imports_name_the_resolving_library() -> None:
    """r2.imports must say which library each import resolves to.

    That association is the tool's whole purpose, and r2 6.x moved it from the
    documented ``lib`` key to ``libname``; the mapping aliases it back. The
    committed fixture links KERNEL32 imports, so at least one row must carry a
    non-empty ``lib`` string.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok and imports.data is not None, imports.error
        rows = imports.data.get("items") or []
        assert rows, "fixture imports at least one API"
        libs = [row.get("lib") for row in rows if isinstance(row.get("lib"), str) and row["lib"]]
        assert libs, "no import named its resolving library"
    finally:
        service.close_session(session_id)


def _xref_touches(item: dict, va: int) -> bool:
    """True when an xref row names ``va`` as its origin or its target.

    Mirrors the endpoint keys the service filters on (``from`` origin; ``to`` or,
    on r2 5.x, ``addr`` target), reading either the raw int or the mapped VA.
    """
    for key in ("from", "to", "addr"):
        value = item.get(key)
        if isinstance(value, int) and value == va:
            return True
    for key in ("from_address", "to_address", "address"):
        mapped = item.get(key)
        if isinstance(mapped, dict) and mapped.get("va") == va:
            return True
    return False


@pytest.mark.integration
def test_r2_service_xrefs_are_scoped_to_the_requested_address() -> None:
    """xrefs must answer for the address asked, not dump the whole DB.

    radare2's ``axj`` lists every cross reference and ignores the ``@`` seek, so
    before the fix ``r2.xrefs`` returned an identical program-wide list for 0x0,
    a real function, and a bogus VA alike -- the address argument did nothing.
    This proves the query is now scoped: a VA far outside the image resolves to
    zero references, at least one real function resolves to some, and every row
    that comes back actually touches the address that was requested.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok
        # Imported call targets are the reliable, fixture-neutral referenced
        # addresses: any PE that imports and calls an API has code pointing at
        # its import slots. (Function *entry* addresses are not themselves xref
        # targets here -- the calls land on the import thunks, not the entries.)
        imports = service.r2_imports(session_id, timeout=60.0)
        assert imports.ok and imports.data is not None, imports.error
        targets: list[int] = []
        for item in imports.data["items"]:
            mapped = item.get("address")
            if isinstance(mapped, dict) and isinstance(mapped.get("va"), int):
                targets.append(mapped["va"])
        assert targets, "no import addresses to pivot xrefs from"

        # A VA well past the image can reference nothing. Before the fix this
        # still returned the full axj dump; now it must be a clean empty list.
        bogus = service.r2_xrefs(session_id, 0xFFFFFFFFFFFF, timeout=60.0)
        assert bogus.ok and bogus.data is not None, bogus.error
        assert bogus.data["parsed"] is True
        assert bogus.data["count"] == 0
        assert bogus.data["items"] == []

        # Some referenced address must resolve to at least one xref, and every
        # row returned for it must actually involve that address -- otherwise the
        # "filter" is just passing the whole database through unchanged.
        found_with_refs = False
        for va in targets:
            result = service.r2_xrefs(session_id, va, timeout=60.0)
            assert result.ok and result.data is not None, result.error
            assert result.data["parsed"] is True
            request_va = result.data["address_va"]
            for row in result.data["items"]:
                assert _xref_touches(row, request_va), (va, row)
            if result.data["count"] >= 1:
                found_with_refs = True
        assert found_with_refs, "expected at least one import with resolvable xrefs"
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_xrefs_at_a_non_code_address_stay_empty() -> None:
    """A bad target must fail soft: a clean empty xref list, no internal_error.

    Agents point xrefs at addresses that turn out to be data, padding, or below
    the image base. 0x0 references nothing, so the envelope must come back parsed
    with zero items -- not an exception, not the whole-program dump the old axj
    behaviour produced, and not an internal_error.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok
        xref = service.r2_xrefs(session_id, 0x0, timeout=60.0)
        assert xref.ok and xref.data is not None, xref.error
        assert xref.data["parsed"] is True
        assert xref.data["count"] == 0
        assert xref.data["items"] == []
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_disasm_flags_non_code_bytes_as_invalid() -> None:
    """Disassembling data/unmapped memory must be legible as "not code".

    radare2 returns a row per byte at any address, each tagged invalid with no
    opcode, so a decoded-looking count/items envelope comes back for a header or
    a hole just as it does for a function. The service surfaces invalid_count so
    an agent can tell them apart: at 0x0 (no code, unmapped/header bytes) every
    returned row is invalid, and invalid_count equals count.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        assert service.r2_open(session_id, timeout=60.0).ok
        dis = service.r2_disasm(session_id, 0x0, count=6, timeout=60.0)
        assert dis.ok and dis.data is not None, dis.error
        assert dis.data["parsed"] is True
        # Every row at 0x0 is an undecodable byte, and it is said out loud.
        assert dis.data["count"] >= 1
        assert dis.data["invalid_count"] == dis.data["count"]
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_r2_service_refuses_a_closed_session_without_leaking() -> None:
    """A closed session must fail closed with a structured error, not a crash.

    The service guards state before touching r2; losing that guard would leak an
    internal exception (or worse, run r2 against a torn-down session) instead of
    the clean refusal an agent can branch on.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    service.close_session(session_id)

    clean_codes = {"invalid_request", "invalid_state", "session_not_found"}
    for call in (
        lambda: service.r2_functions(session_id, timeout=30.0),
        lambda: service.r2_disasm(session_id, 0x1000, count=4, timeout=30.0),
        lambda: service.r2_xrefs(session_id, 0x1000, timeout=30.0),
    ):
        result = call()
        assert not result.ok and result.error is not None
        assert result.error.code != "internal_error", result.error
        assert result.error.code in clean_codes, result.error
