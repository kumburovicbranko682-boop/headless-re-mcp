"""Ghidra live gate: analyze + bounded JSON export on any host. skip != pass.

Ghidra is a *portable* backend: analyzeHeadless plus a Java export script that
runs on Linux, macOS and Windows alike, unlike the Windows-only idalib/x64dbg
chain. This gate proves the whole surface end to end -- launcher discovery,
import/analyze, and the functions/symbols/xrefs/decompile exports -- against a
PE that is committed in-tree, so it actually runs on a Linux CI runner whenever
a Ghidra install is present instead of only on Windows.

It skips (never silently passes) when Ghidra is not configured, and prefers the
Windows-built fixture when that exists but falls back to the committed PE.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILT_FIXTURE = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
_COMMITTED_FIXTURE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "add_module.wasm"
# analyzeHeadless does a full import + auto-analysis per call, and each export
# tool re-imports, so give the JVM real headroom on a shared CI box.
_TIMEOUT = 300.0

# A named, un-inlinable function so the ELF cross-format gate can find it by name
# and check the decompiled body -- no committed binary blob, built on demand.
_ELF_SOURCE = (
    "int re_mcp_triple(int x) { return x * 3 + 1; }\n"
    "int main(void) { return re_mcp_triple(7); }\n"
)


def _client() -> GhidraClient:
    client = GhidraClient(home=getattr(Settings.load(), "ghidra_home", None))
    if not client.available:
        pytest.skip("Ghidra analyzeHeadless not configured — live Gate not run (skip != pass)")
    return client


def _wasm_client() -> GhidraClient:
    """Ghidra plus the configured WASM extension, or skip (skip != pass)."""
    settings = Settings.load()
    home = getattr(settings, "ghidra_home", None)
    plugin = getattr(settings, "ghidra_wasm_plugin", None)
    client = GhidraClient(home=home, wasm_plugin=plugin)
    if not client.available:
        pytest.skip("Ghidra analyzeHeadless not configured — WASM Gate not run (skip != pass)")
    if plugin is None:
        pytest.skip(
            "ghidra_wasm_plugin not configured (HEADLESS_RE_GHIDRA_WASM_PLUGIN) — skip != pass"
        )
    return client


def _build_elf_fixture(tmp_path: Path) -> Path:
    """Compile a tiny ELF with the host C compiler, or skip (skip != pass).

    Ghidra is the *portable* backend the non-PE lines lean on, but the rest of
    this gate only proves a PE. A native ELF -- the most common non-PE target --
    is compiled here at -O0 (no inlining) rather than committed as a binary blob,
    so a regression that broke ELF import/analysis while leaving PE intact is
    caught on any box with a compiler.
    """
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — ELF cross-format Gate not run (skip != pass)")
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
        pytest.skip(f"C compiler unusable ({exc}) — ELF cross-format Gate not run (skip != pass)")
    if completed.returncode != 0 or not out.is_file():
        pytest.skip(
            "C compiler produced no ELF "
            f"({completed.stderr.decode('utf-8', 'replace')[:200]}) — skip != pass"
        )
    return out


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
}


def _build_macho_fixture(tmp_path: Path) -> Path:
    """Compile a tiny Mach-O x86_64 executable, or skip (skip != pass).

    The other non-PE native format Ghidra claims is Mach-O. There is no host
    Mach-O toolchain on a Linux runner, so ``zig cc -target x86_64-macos``
    cross-links one (no macOS SDK needed for a headerless function); on a mac the
    host compiler emits Mach-O directly. Absent either, skip honestly.
    """
    source = tmp_path / "re_mcp_probe_macho.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    out = tmp_path / "re_mcp_probe_macho"
    commands: list[list[str]] = []
    zig = shutil.which("zig")
    # -dead_strip: zig statically links a large macOS runtime (~900 functions),
    # which both slows Ghidra's analysis and pushes the named function past any
    # reasonable list window. Dropping unreachable code keeps the fixture lean
    # and the reachable re_mcp_triple findable.
    if zig is not None:
        commands.append(
            [zig, "cc", "-target", "x86_64-macos", "-O0", "-Wl,-dead_strip",
             "-o", str(out), str(source)]
        )
    if sys.platform == "darwin":
        host = shutil.which("cc") or shutil.which("clang")
        if host is not None:
            commands.append([host, "-O0", "-Wl,-dead_strip", "-o", str(out), str(source)])
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


def _gate_fixture() -> Path:
    if _BUILT_FIXTURE.is_file():
        return _BUILT_FIXTURE
    if _COMMITTED_FIXTURE.is_file():
        return _COMMITTED_FIXTURE
    pytest.skip(f"no Ghidra fixture available: {_BUILT_FIXTURE} nor {_COMMITTED_FIXTURE}")


@pytest.mark.integration
def test_ghidra_analyze_imports_the_binary(tmp_path: Path) -> None:
    client = _client()
    fixture = _gate_fixture()
    result = client.analyze_binary(fixture, tmp_path / "proj", timeout=_TIMEOUT)
    # The project is deleted after analyze; the note is the contract the tool
    # descriptions promise (do not read what this produced).
    assert "deleted" in result["note"]


@pytest.mark.integration
def test_ghidra_functions_and_symbols_export(tmp_path: Path) -> None:
    client = _client()
    fixture = _gate_fixture()

    funcs = client.functions(fixture, tmp_path / "fn", limit=16, timeout=_TIMEOUT)
    assert funcs.get("count", 0) >= 1
    first = funcs["items"][0]
    # The Java export replaced a Jython script; assert the exact field contract
    # the client and tool catalog promise so a silent shape drift is caught.
    assert set(first) >= {"name", "entry", "body_size"}
    assert isinstance(first["body_size"], int)

    syms = client.symbols(fixture, tmp_path / "sym", limit=16, timeout=_TIMEOUT)
    assert syms.get("count", 0) >= 1
    sym = syms["items"][0]
    assert set(sym) >= {"name", "address", "type"}


@pytest.mark.integration
def test_ghidra_xrefs_and_decompile_at_a_real_function(tmp_path: Path) -> None:
    client = _client()
    fixture = _gate_fixture()

    funcs = client.functions(fixture, tmp_path / "fn", limit=64, timeout=_TIMEOUT)
    entry = funcs["items"][0]["entry"]

    xrefs = client.xrefs(fixture, tmp_path / "xr", entry, limit=16, timeout=_TIMEOUT)
    assert isinstance(xrefs.get("items"), list)
    assert isinstance(xrefs.get("has_more"), bool)
    for ref in xrefs["items"]:
        assert set(ref) >= {"from", "to", "type"}

    decompiled = client.decompile(fixture, tmp_path / "dc", entry, timeout=_TIMEOUT)
    assert "decompiled" in decompiled
    assert decompiled.get("truncated") is False
    assert decompiled.get("function")


@pytest.mark.integration
def test_ghidra_decompile_and_xrefs_at_a_non_function_address_stay_empty(tmp_path: Path) -> None:
    """A bad target must fail soft: empty result, no crash, no internal_error.

    Agents routinely point decompile/xrefs at an address that turns out to be
    data, padding, or below the image base. 0x0 is in no function and has no
    references, so the export must come back as a clean empty envelope -- not an
    exception and not a half-formed object. A regression that let the Java export
    throw (or the client surface internal_error) on a missing function would be
    caught here.
    """
    client = _client()
    fixture = _gate_fixture()

    decompiled = client.decompile(fixture, tmp_path / "dc0", "0x0", timeout=_TIMEOUT)
    assert decompiled["mode"] == "decompile"
    assert decompiled["decompiled"] == ""
    assert decompiled["truncated"] is False
    # No function contains 0x0, so the name/entry pair is omitted rather than
    # echoed as empty strings an agent might mistake for a real function.
    assert "function" not in decompiled

    xrefs = client.xrefs(fixture, tmp_path / "xr0", "0x0", limit=8, timeout=_TIMEOUT)
    assert xrefs["count"] == 0
    assert xrefs["items"] == []
    assert xrefs["has_more"] is False


@pytest.mark.integration
def test_ghidra_analyzes_a_native_elf_end_to_end(tmp_path: Path) -> None:
    """The portable backend must handle a non-PE format, not just the PE fixture.

    Ghidra is what the non-PE lines use for ELF/Mach-O/raw analysis, but every
    other test here feeds it a PE. This builds a native ELF and drives the same
    functions -> decompile -> xrefs surface against it: the named function is
    recovered, its decompiled C carries the *3+1 arithmetic, and the call from
    main resolves as a reference to its entry. A drift that broke ELF import
    while PE kept working would surface only here.
    """
    client = _client()
    elf = _build_elf_fixture(tmp_path)

    funcs = client.functions(elf, tmp_path / "fn", limit=256, timeout=_TIMEOUT)
    assert funcs.get("count", 0) >= 1
    by_name = {item["name"]: item for item in funcs.get("items", [])}
    assert "re_mcp_triple" in by_name, sorted(by_name)
    triple_entry = by_name["re_mcp_triple"]["entry"]

    decompiled = client.decompile(elf, tmp_path / "dc", triple_entry, timeout=_TIMEOUT)
    assert decompiled.get("function") == "re_mcp_triple"
    assert decompiled.get("truncated") is False
    body = decompiled.get("decompiled") or ""
    # Ghidra names the parameter itself, but the arithmetic is stable: x*3+1.
    assert "* 3" in body and "+ 1" in body, body[:200]

    xrefs = client.xrefs(elf, tmp_path / "xr", triple_entry, limit=32, timeout=_TIMEOUT)
    assert isinstance(xrefs.get("items"), list)
    assert xrefs.get("count", 0) >= 1, "expected the call from main to reference re_mcp_triple"
    for ref in xrefs["items"]:
        assert set(ref) >= {"from", "to", "type"}


@pytest.mark.integration
def test_ghidra_decompiles_a_wasm_module_via_the_configured_plugin(tmp_path: Path) -> None:
    """WASM structural decompilation is the plugin's whole reason to exist.

    ``HEADLESS_RE_GHIDRA_WASM_PLUGIN`` used to be a dead setting: nothing put the
    extension where analyzeHeadless looks, so a .wasm imported with no
    WebAssembly loader. With the client installing it, this drives the real path
    end to end -- the committed add module exports one ``add`` function whose
    decompiled C is a two-operand addition. Skips (never passes) when Ghidra or
    the plugin is not configured.
    """
    client = _wasm_client()
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"

    funcs = client.functions(_WASM_FIXTURE, tmp_path / "fn", limit=16, timeout=_TIMEOUT)
    assert funcs.get("count", 0) >= 1, "WASM loader did not engage — no functions recovered"
    names = {item["name"] for item in funcs.get("items", [])}
    assert "add" in names, sorted(names)
    entry = next(item["entry"] for item in funcs["items"] if item["name"] == "add")

    decompiled = client.decompile(_WASM_FIXTURE, tmp_path / "dc", entry, timeout=_TIMEOUT)
    assert decompiled.get("function") == "add"
    assert decompiled.get("truncated") is False
    body = decompiled.get("decompiled") or ""
    # The module adds its two parameters; the exact parameter names vary, the
    # addition does not.
    assert "+" in body, body[:200]


@pytest.mark.integration
def test_ghidra_analyzes_a_native_elf_through_the_service(tmp_path: Path) -> None:
    """The ELF must reach Ghidra through create_session, not only the client.

    The client-level ELF gate above bypasses session creation, which is exactly
    where an ELF used to be rejected as "not a PE file". This proves the real
    agent entry point now classifies the ELF as native, opens it, and lets
    ghidra.functions recover the named function. skip != pass.
    """
    if not GhidraClient(home=getattr(Settings.load(), "ghidra_home", None)).available:
        pytest.skip("Ghidra analyzeHeadless not configured — service ELF Gate (skip != pass)")
    elf = _build_elf_fixture(tmp_path)
    service = AnalysisService(Settings.load())
    created = service.create_session(str(elf))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session.get("target") == "native"
    assert session.get("metadata", {}).get("native", {}).get("format") == "elf"
    session_id = str(session["id"])
    try:
        funcs = service.ghidra_functions(session_id, timeout=_TIMEOUT)
        assert funcs.ok and funcs.data is not None, funcs.error
        names = {item.get("name") for item in funcs.data.get("items", [])}
        assert "re_mcp_triple" in names, sorted(names)
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_ghidra_analyzes_a_native_macho_end_to_end(tmp_path: Path) -> None:
    """Ghidra must handle Mach-O, the other non-PE native format it claims.

    The ELF gate proves one native format; Mach-O is the other. This builds a
    real Mach-O executable and drives the same functions -> decompile -> xrefs
    surface: the named function is recovered, its decompiled C carries the x*3+1
    arithmetic, and the call from main resolves as a reference to its entry.
    skip != pass when Ghidra or a Mach-O toolchain is absent.
    """
    client = _client()
    macho = _build_macho_fixture(tmp_path)

    # A cross-linked Mach-O carries the whole static runtime, so raise the list
    # window to the client's cap to guarantee the named function is included.
    funcs = client.functions(macho, tmp_path / "fn", limit=1024, timeout=_TIMEOUT)
    assert funcs.get("count", 0) >= 1
    by_name = {item["name"]: item for item in funcs.get("items", [])}
    # Mach-O symbols carry a leading underscore; match re_mcp_triple by substring.
    triple_name = next((n for n in by_name if "re_mcp_triple" in n), None)
    assert triple_name is not None, sorted(by_name)
    triple_entry = by_name[triple_name]["entry"]

    decompiled = client.decompile(macho, tmp_path / "dc", triple_entry, timeout=_TIMEOUT)
    assert decompiled.get("truncated") is False
    body = decompiled.get("decompiled") or ""
    assert "* 3" in body and "+ 1" in body, body[:200]

    xrefs = client.xrefs(macho, tmp_path / "xr", triple_entry, limit=32, timeout=_TIMEOUT)
    assert isinstance(xrefs.get("items"), list)
    assert xrefs.get("count", 0) >= 1, "expected the call from main to reference re_mcp_triple"
    for ref in xrefs["items"]:
        assert set(ref) >= {"from", "to", "type"}


@pytest.mark.integration
def test_ghidra_analyzes_a_native_macho_through_the_service(tmp_path: Path) -> None:
    """The Mach-O must reach Ghidra through create_session, not only the client.

    Mirrors the ELF service gate for the other native format: create_session
    classifies the Mach-O as native, and ghidra.functions recovers the named
    function through the real agent entry point. skip != pass.
    """
    if not GhidraClient(home=getattr(Settings.load(), "ghidra_home", None)).available:
        pytest.skip("Ghidra analyzeHeadless not configured — service Mach-O Gate (skip != pass)")
    macho = _build_macho_fixture(tmp_path)
    service = AnalysisService(Settings.load())
    created = service.create_session(str(macho))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session.get("target") == "native"
    assert session.get("metadata", {}).get("native", {}).get("format") == "macho"
    session_id = str(session["id"])
    try:
        # Raise the window past the static runtime the cross-link pulls in so the
        # named function is in the page (see the client Mach-O gate).
        funcs = service.ghidra_functions(session_id, limit=1024, timeout=_TIMEOUT)
        assert funcs.ok and funcs.data is not None, funcs.error
        names = {item.get("name") for item in funcs.data.get("items", [])}
        assert any("re_mcp_triple" in (n or "") for n in names), sorted(names)
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_ghidra_decompile_spills_full_c_when_truncated(tmp_path: Path) -> None:
    """A capped decompile must still surface the complete function body.

    Ghidra caps one function's decompiled C at 200 KB inline; the overflow used
    to be dropped, leaving only truncated=true and no way to get the rest.
    Forcing a tiny cap drives the same spill contract js/wasm use: the inline
    text is cut to the cap, and the full C lands in artifact_path with
    artifact_bytes. Uses the committed PE, so no plugin/compiler needed.
    skip != pass.
    """
    client = _client()
    fixture = _gate_fixture()

    funcs = client.functions(fixture, tmp_path / "fn", limit=64, timeout=_TIMEOUT)
    entry = funcs["items"][0]["entry"]
    full = client.decompile(fixture, tmp_path / "dc_full", entry, timeout=_TIMEOUT)
    full_c = full.get("decompiled") or ""
    assert full.get("truncated") is False
    cap = 16
    if len(full_c) <= cap:
        pytest.skip("first function's decompiled C is too short to force truncation")

    capped = client.decompile(
        fixture, tmp_path / "dc_cap", entry, timeout=_TIMEOUT, max_decompiled=cap
    )
    assert capped.get("truncated") is True
    inline = capped.get("decompiled") or ""
    assert len(inline) == cap
    assert inline == full_c[:cap]

    sidecar = capped.get("artifact_path")
    assert isinstance(sidecar, str) and Path(sidecar).is_file(), capped
    disk = Path(sidecar).read_text(encoding="utf-8")
    assert disk == full_c, "spilled C must be the complete, untruncated body"
    assert capped.get("artifact_bytes") == len(disk.encode("utf-8"))
