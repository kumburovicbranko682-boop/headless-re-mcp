"""The non-PE tools' write/read effect must match what each one actually does.

Read-only deployments (``local_full_access=false``) refuse any tool whose
``CommandSpec.write`` is true and serve every tool whose ``write`` is false. Two
existing suites guard that machinery but neither pins the *ground truth* of a
single tool's effect:

* ``test_write_policy.py`` drives the guard on a synthetic one-tool catalog -- it
  proves a STATE_CHANGE tool is refused and a READ_ONLY tool is served, but never
  looks at the real surface.
* ``test_write_policy_surface.py`` proves the guarded set *equals* the
  write-classified set across the whole real surface -- consistency between the
  guard and the classification, whatever that classification happens to say.

The hole both leave open is a tool filed under the wrong effect. ``catalog.py``
lists all 265 names across three frozensets and asserts the union size, so an
omission or duplicate is caught -- but moving ``device.uninstall`` from
``_STATE_CHANGE_NAMES`` into ``_READ_ONLY_NAMES`` keeps the count at 265, keeps
the guarded set equal to the (now smaller) write set, and makes
``test_write_policy_surface``'s read-tool check pass because the tool now merely
fails on a bad serial instead of returning ``write_disabled``. The net effect: a
tool that uninstalls an app off a device would run in a deployment that asked to
be read-only, silently. The non-PE lines are where this bites hardest -- they
added the device/process/network/file mutations that a read-only operator most
needs held back.

This test pins the effect ground truth for the non-PE surface as an explicit
table: every device/frida/proxy/web/apk/js/wasm/ghidra/r2 tool that mutates a
device, a target process, the network, or the disk must be a write; every one
that only reads must not be. A misfile in either direction flips exactly one
entry and fails here, naming the tool and the direction, while the count- and
consistency-based guards stay green.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.tools.catalog import CommandCatalog

# --- Ground truth: non-PE tools that change external state or write files. -----
# Each of these does something a read-only deployment must be able to refuse:
# mutate a device, a target process, the network, or the local disk. Filing any
# of them as read-only would leave it runnable when writes are disabled.
_NON_PE_WRITES = frozenset(
    {
        # adb device control -- installs, launches, stops, moves files, forwards.
        "device.connect",
        "device.force_stop",
        "device.forward",
        "device.install",
        "device.launch",
        "device.push",
        "device.uninstall",
        "device.pull",
        "device.screenshot",
        # frida -- attaches to / spawns / hooks a live process, pushes a server.
        "frida.attach",
        "frida.device.connect",
        "frida.server.ensure",
        "frida.spawn",
        "frida.hook.template",
        # mitmproxy -- binds a port, replays a request, pushes a CA to a device.
        "proxy.ca.install_android",
        "proxy.replay",
        "proxy.start",
        "proxy.stop",
        "proxy.export_har",
        # headless browser -- opens/navigates/closes a real browser, writes files.
        "web.close",
        "web.navigate",
        "web.open",
        "web.har.export",
        "web.screenshot",
        # apk tooling -- decodes/rebuilds/signs an APK, all writing to disk.
        "apk.decode",
        "apk.decompile",
        "apk.export_sources",
        "apk.repack",
        "apk.sign",
        # js/wasm and cross-platform static -- write unpacked output / a project.
        "js.unpack_bundle",
        "ghidra.analyze",
        "r2.open",
    }
)

# --- Ground truth: non-PE tools that only read. --------------------------------
# A read-only deployment must keep serving these; equally, none may acquire the
# write guard, or read-only mode would refuse a read it is supposed to answer.
_NON_PE_READS = frozenset(
    {
        # apk static analysis.
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
        # adb read-only queries.
        "device.current_activity",
        "device.info",
        "device.list",
        "device.logcat",
        "device.packages",
        "device.properties",
        # frida enumeration / inspection (no process mutation).
        "frida.applications",
        "frida.devices",
        "frida.java.classes",
        "frida.java.methods",
        "frida.exports",
        "frida.memory.read",
        "frida.modules",
        # js/wasm inspection.
        "js.beautify",
        "js.deobfuscate",
        "wasm.info",
        "wasm.wat",
        # mitmproxy inspection of already-captured flows.
        "proxy.flow.get",
        "proxy.flows",
        "proxy.status",
        # headless browser inspection of the loaded page.
        "web.console",
        "web.dom.snapshot",
        "web.network.get",
        "web.network.list",
        "web.script.source",
        "web.scripts",
        "web.wasm.list",
        # cross-platform static backends (read paths).
        "ghidra.decompile",
        "ghidra.functions",
        "ghidra.symbols",
        "ghidra.xrefs",
        "r2.disasm",
        "r2.exports",
        "r2.functions",
        "r2.imports",
        "r2.info",
        "r2.strings",
        "r2.xrefs",
    }
)


def test_the_two_ground_truth_tables_are_disjoint() -> None:
    """A tool cannot be both a read and a write; a typo that lands in both sets
    would otherwise make the two per-tool checks contradict each other silently."""
    overlap = _NON_PE_WRITES & _NON_PE_READS
    assert overlap == set(), overlap


@pytest.mark.parametrize("name", sorted(_NON_PE_WRITES))
def test_a_state_or_file_mutating_nonpe_tool_is_classified_as_a_write(name: str) -> None:
    """It must be refusable in a read-only deployment.

    ``spec is None`` means the name is gone or renamed -- the table has to be kept
    in step with the surface, so that fails here rather than skipping quietly. A
    ``write`` of false is the misfile this test exists to catch: the tool would run
    when the deployment disabled writes.
    """
    spec = CommandCatalog().get(name)
    assert spec is not None, f"{name} is not a catalog tool (renamed or removed?)"
    assert spec.write is True, f"{name} mutates state/disk but is filed as read-only"


@pytest.mark.parametrize("name", sorted(_NON_PE_READS))
def test_a_read_only_nonpe_tool_is_not_classified_as_a_write(name: str) -> None:
    """It must keep being served when writes are disabled.

    A read tool that acquires the write guard would make a read-only deployment
    refuse the very inspection it is meant to answer -- the reverse misfile, pinned
    with the same table.
    """
    spec = CommandCatalog().get(name)
    assert spec is not None, f"{name} is not a catalog tool (renamed or removed?)"
    assert spec.write is False, f"{name} only reads but is filed as a write"
