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
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings

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
