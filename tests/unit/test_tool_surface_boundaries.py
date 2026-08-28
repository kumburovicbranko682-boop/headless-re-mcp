"""The tool surface stays named and restricted -- no free-form command escape.

The security boundary stated in SECURITY.md and the README is that every
capability is a named, argument-validated tool: there is deliberately no
`dynamic.command`, no `device.shell`, no `web.evaluate`, and no tool that runs a
caller-supplied script. That boundary is easy to erode one convenient tool at a
time, so it is pinned here: a future tool that reintroduces an arbitrary
command/eval surface, or ships without the metadata clients route on, fails.
"""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandTransport,
    ToolEffect,
)

# The non-PE lines (Android device, Frida, proxy, web, APK static, JS) reach out
# to real devices, browsers, networks and the local disk, so every state change
# or file write on them must leave a trace an operator can review after an
# unattended run. Two mechanisms carry that: a durable "audit" row that survives
# session-timeline trimming (used for session-less or high-stakes device
# mutations) and a session "timeline" entry (used for session-scoped changes).
# The value is (mechanism, emitted event/action name); the declared name equals
# the tool name. Two tools write both mechanisms -- proxy.ca.install_android and
# frida.hook.template also emit a session timeline entry -- and are declared here
# by their durable audit, the stronger cross-session guarantee. This map is
# pinned against the live catalog below, so a new non-PE write tool cannot ship
# without a deliberate decision about how it is observed, and dropping an
# existing tool's instrumentation trips the wiring check.
_NON_PE_WRITE_TRACES: dict[str, tuple[str, str]] = {
    # APK static line -- session timeline.
    "apk.decode": ("timeline", "apk.decode"),
    "apk.decompile": ("timeline", "apk.decompile"),
    "apk.export_sources": ("timeline", "apk.export_sources"),
    "apk.repack": ("timeline", "apk.repack"),
    "apk.sign": ("timeline", "apk.sign"),
    # Android device line -- durable audit (keyed by serial, no session).
    "device.connect": ("audit", "device.connect"),
    "device.force_stop": ("audit", "device.force_stop"),
    "device.forward": ("audit", "device.forward"),
    "device.install": ("audit", "device.install"),
    "device.launch": ("audit", "device.launch"),
    "device.pull": ("audit", "device.pull"),
    "device.push": ("audit", "device.push"),
    "device.screenshot": ("audit", "device.screenshot"),
    "device.uninstall": ("audit", "device.uninstall"),
    # Frida line -- timeline for pure probes, durable audit for the code-injecting
    # and device-mutating ops (hook.template loads a script inside the target,
    # spawn launches a process, server.ensure pushes and starts frida-server).
    "frida.attach": ("timeline", "frida.attach"),
    "frida.device.connect": ("timeline", "frida.device.connect"),
    "frida.hook.template": ("audit", "frida.hook.template"),
    "frida.server.ensure": ("audit", "frida.server.ensure"),
    "frida.spawn": ("audit", "frida.spawn"),
    # JS line -- durable audit (keyed by file path, no session).
    "js.unpack_bundle": ("audit", "js.unpack_bundle"),
    # Proxy line -- session timeline, except the CA push, which also writes a
    # durable audit row (an adb device mutation, like frida.server.ensure).
    "proxy.ca.install_android": ("audit", "proxy.ca.install_android"),
    "proxy.export_har": ("timeline", "proxy.export_har"),
    "proxy.replay": ("timeline", "proxy.replay"),
    "proxy.start": ("timeline", "proxy.start"),
    "proxy.stop": ("timeline", "proxy.stop"),
    # Web line -- session timeline.
    "web.click": ("timeline", "web.click"),
    "web.close": ("timeline", "web.close"),
    "web.har.export": ("timeline", "web.har.export"),
    "web.navigate": ("timeline", "web.navigate"),
    "web.open": ("timeline", "web.open"),
    "web.screenshot": ("timeline", "web.screenshot"),
    "web.type": ("timeline", "web.type"),
    # Workspace line -- durable audit (session-less global config change).
    "workspace.mode.set": ("audit", "workspace.mode.set"),
}

_NON_PE_LINES = ("apk.", "device.", "frida.", "js.", "proxy.", "web.", "workspace.")

# Names that would each amount to an arbitrary command/eval passthrough. The
# project calls these out by name as things it intentionally does not offer, so
# their reappearance in the catalog is the regression to catch.
FORBIDDEN_TOOL_NAMES = frozenset(
    {
        "dynamic.command",
        "dynamic.exec",
        "dynamic.execute",
        "device.shell",
        "device.exec",
        "adb.shell",
        "shell.run",
        "shell.exec",
        "web.evaluate",
        "web.eval",
        "js.eval",
        "frida.eval",
        "frida.script",
    }
)


def _all_specs(catalog: CommandCatalog) -> list:
    seen: dict[str, object] = {}
    for transport in CommandTransport:
        for spec in catalog.for_transport(transport):
            seen[spec.name] = spec
    return list(seen.values())


def test_no_free_form_command_or_eval_tool_is_registered() -> None:
    catalog = CommandCatalog()
    names = {spec.name for spec in _all_specs(catalog)}
    present = FORBIDDEN_TOOL_NAMES & names
    assert present == set(), (
        "the catalog exposes a free-form command/eval tool, which breaks the "
        f"'every capability is a named tool' boundary: {sorted(present)}"
    )


def test_every_declared_tool_is_classified_exactly_once() -> None:
    catalog = CommandCatalog()
    specs = _all_specs(catalog)
    assert specs, "the catalog is empty"

    uncategorized = catalog.uncategorized_names()
    assert uncategorized == (), uncategorized

    for spec in specs:
        assert spec.effects, spec.name
        # write is state_change/file_write; read is read_only alone. The two are
        # complementary, so a tool cannot be simultaneously both or neither.
        is_read = spec.effects == frozenset({ToolEffect.READ_ONLY})
        assert spec.write != is_read, (
            f"{spec.name} has an ambiguous effect set: {sorted(spec.effects)}"
        )
        if spec.write:
            assert ToolEffect.READ_ONLY not in spec.effects, (
                f"{spec.name} mixes read_only with a write effect"
            )


def test_every_tool_has_a_bounded_resource_policy() -> None:
    """Unattended runs depend on every tool having a finite deadline and cap.

    A tool that reached the surface with a zero, negative or non-finite timeout
    (or output cap) would run unbounded -- exactly the hang an unattended
    mission cannot recover from -- so the whole surface is pinned rather than
    trusting each call site to pass a sane number.
    """
    import math

    catalog = CommandCatalog()
    specs = _all_specs(catalog)
    assert specs, "the catalog is empty"

    for spec in specs:
        policy = spec.resource_policy
        assert math.isfinite(policy.timeout_seconds), spec.name
        assert policy.timeout_seconds > 0, spec.name
        assert policy.max_result_bytes > 0, spec.name


def test_every_bound_tool_carries_a_description_and_object_schema() -> None:
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.assembly import bind_all_tools

    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        missing_doc: list[str] = []
        bad_schema: list[str] = []
        for binding in bindings:
            spec = catalog.get(binding.name)
            assert spec is not None
            description = (spec.description or "").strip()
            # A blank or name-only description leaves an MCP client with nothing
            # to route on; bind_all_tools falls back to the name, so require more.
            if not description or description == binding.name:
                missing_doc.append(binding.name)
            schema = spec.input_schema
            if not isinstance(schema, dict) or schema.get("type") != "object":
                bad_schema.append(binding.name)
        assert missing_doc == [], missing_doc
        assert bad_schema == [], bad_schema
    finally:
        analysis.close_all()


def _non_pe_write_tool_names(catalog: CommandCatalog) -> set[str]:
    return {
        spec.name
        for spec in _all_specs(catalog)
        if spec.write and spec.name.startswith(_NON_PE_LINES)
    }


def test_every_non_pe_write_tool_declares_an_observability_trace() -> None:
    """Every non-PE state change or file write must be pinned to a trace.

    Unlike a PE unpack, these tools touch a real device, browser, network or the
    local disk, and an operator reviewing an unattended run needs a record that
    they ran and what they did. The trace map is pinned to equal the live non-PE
    write surface, so a newly added tool on any of these lines fails here until
    it is given an audit row or a timeline entry -- the same forcing function the
    file-write autonomy denylist uses -- rather than silently shipping with no
    observability. A renamed or reclassified tool trips it too.
    """
    catalog = CommandCatalog()
    declared = set(_NON_PE_WRITE_TRACES)
    actual = _non_pe_write_tool_names(catalog)

    missing = actual - declared
    dead = declared - actual
    assert missing == set(), f"non-PE write tools with no declared trace: {sorted(missing)}"
    assert dead == set(), f"trace map names a tool that is not a non-PE write: {sorted(dead)}"

    for name, (mechanism, _event) in _NON_PE_WRITE_TRACES.items():
        assert mechanism in {"audit", "timeline"}, (name, mechanism)


# How each mechanism actually reaches disk in the service layer. The event
# literal is passed either straight into ``append_audit(action=...)`` /
# ``append_session_timeline(event=...)`` or through a thin per-line helper
# (``_audit_device`` / ``_audit_frida`` for durable rows, ``_timeline_append`` /
# ``_note_web_action`` for session entries) that forwards to those. ``[^()]*?``
# lets the literal sit anywhere in a possibly multi-line argument list up to the
# first nested call -- the event is always an early positional, ahead of any
# ``kwarg=f(...)`` -- and ``[^()]``/``\s`` both match newlines, so a call split
# across lines is still found.
def _emits_audit(source: str, event: str) -> bool:
    literal = re.escape(event)
    return any(
        re.search(pattern, source) is not None
        for pattern in (
            rf'action\s*=\s*"{literal}"',
            rf'_audit_device\([^()]*?"{literal}"',
            rf'_audit_frida\([^()]*?"{literal}"',
        )
    )


def _emits_timeline(source: str, event: str) -> bool:
    literal = re.escape(event)
    return any(
        re.search(pattern, source) is not None
        for pattern in (
            rf'event\s*=\s*"{literal}"',
            rf'_timeline_append\([^()]*?"{literal}"',
            rf'_note_web_action\([^()]*?"{literal}"',
        )
    )


def test_declared_observability_traces_are_actually_wired() -> None:
    """The declared trace is real *and of the declared kind*: an audit tool emits
    an audit row, a timeline tool emits a timeline entry.

    The map above is only bookkeeping unless the promised call site exists, so
    this reads the service layer's source and asserts each declared event reaches
    disk through the mechanism it claims -- not merely that the literal appears
    somewhere. That distinction is the point: several tools carry both an audit
    row and a timeline entry (frida.hook.template, frida.spawn, frida.server.ensure,
    proxy.ca.install_android) and are declared by the durable audit, the stronger
    cross-session guarantee. A refactor that dropped the audit call but kept the
    timeline one would leave the literal in the source, so a bare substring check
    would still pass while an operator quietly lost the row that survives session
    trimming. Requiring the audit emit specifically catches that downgrade, along
    with the two coarser rots: a tool added to the map but never instrumented, and
    instrumentation removed while the map still claims it.
    """
    import headless_re_mcp.core as core_pkg

    core_dir = Path(core_pkg.__file__).parent
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(core_dir.glob("service*.py"))
    )
    assert source, "no service source found to check trace wiring against"

    wrong: list[str] = []
    for name, (mechanism, event) in _NON_PE_WRITE_TRACES.items():
        emits = _emits_audit if mechanism == "audit" else _emits_timeline
        if not emits(source, event):
            wrong.append(f"{name}: declares {mechanism} but no {mechanism} emit for {event!r}")
    assert wrong == [], f"declared traces not wired to their mechanism: {wrong}"
