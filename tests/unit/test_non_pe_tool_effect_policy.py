"""The read/write effect of every non-PE tool is pinned against an independent
expectation, so a misfiling cannot slip through in silence.

`test_write_policy_surface.py` proves the write guard matches ``spec.write`` for
the whole surface -- but it derives "write" *from the classification itself*, so
it cannot catch a write tool refiled as read-only: such a tool simply drops out
of both the guarded set and the write-classified set, and the equality still
holds. The concrete failure that hides behind that is a security one: a
side-effecting non-PE tool (apk.sign flashing a rebuilt APK, device.push writing
to a device, proxy.start opening a listener, web.navigate driving a live
browser) refiled as ``READ_ONLY`` would stay callable in a ``read_only``
deployment, which is exactly what that mode exists to forbid. The build-time
policy check only enforces completeness and no-duplicates, not correctness.

This file is the independent source of truth: a human-reviewed map from each
non-PE tool to the effect it must carry. It fails if the catalog's classification
drifts from this map, and -- via the prefix sweep -- if a new or renamed non-PE
tool appears that nobody classified here, forcing the review rather than letting
it default silently.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.tools.catalog import CommandCatalog, CommandTransport, ToolEffect

# A pure query: no persistent state changes, safe to serve in a read-only
# deployment. For radare2/Frida these spin a bounded probe but neither writes a
# retrievable artifact nor mutates the target between calls.
_READ_ONLY = frozenset(
    {
        # Android static (apktool/androguard/dexlib parse in process).
        "apk.certificates",
        "apk.classes",
        "apk.components",
        "apk.manifest",
        "apk.methods",
        "apk.native_libs",
        "apk.open",
        "apk.permissions",
        "apk.strings",
        "apk.xrefs",
        # adb read probes.
        "device.current_activity",
        "device.info",
        "device.list",
        "device.logcat",
        "device.packages",
        "device.properties",
        # Frida read probes (attach briefly, read, detach; the debuggee/device
        # pid is inspected, never mutated).
        "frida.applications",
        "frida.devices",
        "frida.exports",
        "frida.java.classes",
        "frida.java.methods",
        "frida.memory.read",
        "frida.modules",
        # JS/WASM in-process transforms that return text, not files.
        "js.beautify",
        "js.deobfuscate",
        "wasm.info",
        "wasm.wat",
        # mitmproxy read views over the captured ring.
        "proxy.flow.get",
        "proxy.flows",
        "proxy.status",
        # Browser read views over the live page and its captures.
        "web.console",
        "web.dom.snapshot",
        "web.har.read",
        "web.network.get",
        "web.network.list",
        "web.script.source",
        "web.scripts",
        "web.wasm.list",
        # radare2 read commands (whitelisted, inline results).
        "r2.disasm",
        "r2.exports",
        "r2.functions",
        "r2.imports",
        "r2.info",
        "r2.strings",
        "r2.xrefs",
        # Ghidra read exports (query the headless project; the raw export is
        # registered as an artifact but the tool is a static read).
        "ghidra.decompile",
        "ghidra.functions",
        "ghidra.symbols",
        "ghidra.xrefs",
        # Workspace profile read.
        "workspace.mode.get",
    }
)

# Changes observable state -- a device, a live browser, a proxy listener, a
# session's backend binding -- without writing a retrievable file. Must be
# refused in a read-only deployment.
_STATE_CHANGE = frozenset(
    {
        "device.connect",
        "device.force_stop",
        "device.forward",
        "device.install",
        "device.launch",
        "device.push",
        "device.uninstall",
        "frida.attach",
        "frida.device.connect",
        "frida.hook.template",
        "frida.server.ensure",
        "frida.spawn",
        "proxy.ca.install_android",
        "proxy.replay",
        "proxy.start",
        "proxy.stop",
        "r2.open",
        "web.close",
        "web.navigate",
        "web.open",
        "workspace.mode.set",
    }
)

# Writes a file the caller can retrieve (a rebuilt/decoded/decompiled tree, a
# pulled file, a screenshot, an exported HAR, an unpacked bundle, a Ghidra
# project). Carries both STATE_CHANGE and FILE_WRITE and must be refused in a
# read-only deployment.
_FILE_WRITE = frozenset(
    {
        "apk.decode",
        "apk.decompile",
        "apk.export_sources",
        "apk.repack",
        "apk.sign",
        "device.pull",
        "device.screenshot",
        "ghidra.analyze",
        "js.unpack_bundle",
        "proxy.export_har",
        "web.har.export",
        "web.screenshot",
    }
)

# Every non-PE track's tool namespace. A tool whose name starts with one of
# these but is missing from the maps above trips the completeness check.
_NON_PE_PREFIXES = (
    "apk.",
    "device.",
    "frida.",
    "js.",
    "wasm.",
    "proxy.",
    "web.",
    "r2.",
    "ghidra.",
    "workspace.mode.",
)

_EXPECTED: dict[str, frozenset[ToolEffect]] = {
    **{name: frozenset({ToolEffect.READ_ONLY}) for name in _READ_ONLY},
    **{name: frozenset({ToolEffect.STATE_CHANGE}) for name in _STATE_CHANGE},
    **{
        name: frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE})
        for name in _FILE_WRITE
    },
}


def _specs_by_name() -> dict[str, object]:
    catalog = CommandCatalog()
    seen: dict[str, object] = {}
    for transport in CommandTransport:
        for spec in catalog.for_transport(transport):
            seen[spec.name] = spec
    return seen


def test_the_three_expectation_sets_do_not_overlap() -> None:
    # A tool named in two buckets would make the map's own intent ambiguous.
    assert not (_READ_ONLY & _STATE_CHANGE)
    assert not (_READ_ONLY & _FILE_WRITE)
    assert not (_STATE_CHANGE & _FILE_WRITE)


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_each_non_pe_tool_carries_the_effect_it_should(name: str) -> None:
    specs = _specs_by_name()
    spec = specs.get(name)
    assert spec is not None, f"{name} is expected but not present in the catalog"
    effects = spec.effects  # type: ignore[attr-defined]
    assert effects == _EXPECTED[name], (
        f"{name} is classified {sorted(e.value for e in effects)} but the "
        f"reviewed policy expects {sorted(e.value for e in _EXPECTED[name])}"
    )


def test_write_tools_are_refused_read_only_and_reads_are_not() -> None:
    # Tie the map back to the enforced guard: FILE_WRITE/STATE_CHANGE are writes
    # (guarded), READ_ONLY is not. This is what makes a misfiling a security bug
    # rather than a cosmetic one.
    specs = _specs_by_name()
    for name, expected in _EXPECTED.items():
        spec = specs[name]
        is_write = spec.write  # type: ignore[attr-defined]
        should_write = expected != frozenset({ToolEffect.READ_ONLY})
        assert is_write is should_write, name


def test_every_non_pe_tool_in_the_catalog_is_classified_here() -> None:
    # The prefix sweep: a new or renamed non-PE tool that nobody added to the
    # maps above fails here, so the read/write review cannot be skipped by simply
    # forgetting it.
    specs = _specs_by_name()
    in_catalog = {
        name for name in specs if name.startswith(_NON_PE_PREFIXES)
    }
    expected = set(_EXPECTED)
    missing_from_map = in_catalog - expected
    stale_in_map = expected - in_catalog
    assert missing_from_map == set(), (
        f"non-PE tools missing an effect expectation: {sorted(missing_from_map)}"
    )
    assert stale_in_map == set(), (
        f"effect expectations for tools no longer in the catalog: {sorted(stale_in_map)}"
    )
