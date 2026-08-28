"""The capability catalog must stay pinned to the real tools and probes.

``_CORE_CAPABILITIES`` hardcodes, as string literals, the tool names each
capability exposes and the doctor probe that reports its status. Nothing else
ties those strings to reality, so a rename in ``tools/catalog.py`` or
``doctor.py`` would leave the capability advertising a tool that no longer
exists or a probe that never resolves -- and ``list_capabilities`` would report
it as permanently ``missing`` with no error. These pin both directions, plus the
status mapping and the two filters, against the shipped surface.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core import capabilities_catalog
from headless_re_mcp.core.capabilities_catalog import (
    _CORE_CAPABILITIES,
    describe_capability,
    list_capabilities,
)
from headless_re_mcp.doctor import DoctorReport, Probe, ProbeStatus, run_doctor
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport


def _real_tool_names() -> set[str]:
    return {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}


def test_every_advertised_tool_name_is_a_real_catalog_tool() -> None:
    real = _real_tool_names()
    stale: dict[str, list[str]] = {}
    for cap in _CORE_CAPABILITIES:
        missing = [name for name in cap["tools"] if name not in real]
        if missing:
            stale[cap["id"]] = missing
    assert not stale, f"capability catalog names tools that no longer exist: {stale}"


def test_every_status_probe_matches_a_real_doctor_probe() -> None:
    probe_names = {probe.name for probe in run_doctor(None).probes}
    stale = {
        cap["id"]: cap["status_probe"]
        for cap in _CORE_CAPABILITIES
        if cap.get("status_probe") and cap["status_probe"] not in probe_names
    }
    assert not stale, f"capability catalog names probes doctor does not emit: {stale}"


def test_apk_signing_is_probed_by_apksigner_not_apktool() -> None:
    """apk.sign's status must follow the apksigner probe, not apktool.

    The apktool client signs via apksigner and checks signer_available (apksigner)
    independently of apktool availability, so a host with apktool but no apksigner
    (or the reverse) makes the two diverge. If apk.sign were advertised under the
    apktool probe, capabilities.search would report it ready when only apktool is
    present -- a call that then fails capability_unavailable -- or hide it when
    only apksigner is present. This pins each apk build tool to the probe that
    actually gates it.
    """
    by_tool = {
        tool: cap["status_probe"]
        for cap in _CORE_CAPABILITIES
        for tool in cap["tools"]
        if cap["backend"] == "apk"
    }
    assert by_tool["apk.sign"] == "apksigner"
    assert by_tool["apk.decode"] == "apktool"
    assert by_tool["apk.repack"] == "apktool"


def test_androguard_capability_advertises_the_whole_parse_surface() -> None:
    """apk.androguard must list every ApkClient parse tool, not a subset.

    certificates, components and native_libs route through the same ApkClient
    parse layer (_apk_call) and androguard probe as manifest/permissions, yet
    were once omitted from the capability while the rest of the parse surface was
    listed. That left capabilities.describe("apk.androguard") under-reporting the
    Android static line -- an agent enumerating the capability would never learn
    those tools exist. Pin the full androguard-gated parse surface so a later add
    to service_apk that forgets the catalog fails here.
    """
    by_id = {cap["id"]: cap for cap in _CORE_CAPABILITIES}
    tools = set(by_id["apk.androguard"]["tools"])
    for name in ("apk.certificates", "apk.components", "apk.native_libs"):
        assert name in tools, f"{name} is androguard-gated but missing from apk.androguard"


def test_web_cdp_capability_advertises_the_cdp_observation_surface() -> None:
    """web.cdp must list the CDP observation tools that share its probe.

    console, wasm.list, dom.snapshot and har.export are the same Playwright/CDP
    observation surface as network.*/scripts/screenshot and ride the same
    playwright probe, but were left off the capability while their siblings were
    advertised -- so capabilities.describe("web.cdp") under-reported the Web line.
    web.close is a lifecycle op (no capability advertises a close), so it stays
    out; pin that too so the boundary is deliberate. web.wasm.list is CDP live
    enumeration and belongs here, not under the wabt static wasm.wabt line.
    """
    by_id = {cap["id"]: cap for cap in _CORE_CAPABILITIES}
    tools = set(by_id["web.cdp"]["tools"])
    for name in ("web.console", "web.wasm.list", "web.dom.snapshot", "web.har.export"):
        assert name in tools, f"{name} is a CDP observation tool missing from web.cdp"
    assert "web.close" not in tools
    # web.wasm.list is the CDP capability's, not the wabt static line's.
    assert "web.wasm.list" not in set(by_id["wasm.wabt"]["tools"])


def test_wasm_tools_are_probed_by_the_binary_that_actually_runs_them() -> None:
    """wasm.wat must follow the wasm2wat probe and wasm.info the wasm-objdump one.

    WasmClient resolves wasm2wat and wasm-objdump independently and guards each
    tool with its own capability_unavailable path, so a host with wasm2wat but no
    wasm-objdump (a partial wabt install) makes them diverge. When both tools sat
    under a single wabt probe keyed on wasm2wat, capabilities.search advertised
    wasm.info ready on such a host -- a call that then failed capability_unavailable.
    Pin each wasm tool to the probe for the binary that runs it, mirroring the
    apk.sign/apktool split.
    """
    by_tool = {
        tool: cap["status_probe"]
        for cap in _CORE_CAPABILITIES
        for tool in cap["tools"]
        if cap["backend"] == "web" and tool.startswith("wasm.")
    }
    assert by_tool["wasm.wat"] == "wabt"
    assert by_tool["wasm.info"] == "wabt_objdump"


def test_each_capability_has_the_required_shape_and_a_unique_id() -> None:
    seen: set[str] = set()
    for cap in _CORE_CAPABILITIES:
        cid = cap["id"]
        assert cid and cid not in seen, f"duplicate or empty capability id: {cid}"
        seen.add(cid)
        assert cap["backend"], cid
        assert cap["summary"], cid
        assert isinstance(cap["tools"], list) and cap["tools"], cid
        # status_probe must be present as a key (may be None for always-ready ones).
        assert "status_probe" in cap, cid


def _stub_report() -> DoctorReport:
    return DoctorReport(
        probes=(
            Probe("ida_idalib", ProbeStatus.READY, "stub ready"),
            Probe("diec", ProbeStatus.MISSING, "stub missing"),
            Probe("win32_ui", ProbeStatus.READY, "stub ready"),
        )
    )


def test_list_capabilities_maps_probe_status_and_honors_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capabilities_catalog, "run_doctor", lambda settings=None: _stub_report())

    by_id = {cap["id"]: cap for cap in list_capabilities()}

    # A ready probe surfaces as ready; a missing probe as missing.
    assert by_id["ida.idalib"]["status"] == "ready"
    assert by_id["detect.die"]["status"] == "missing"
    # ui.win32 is pinned to the win32_ui probe since Linux support landed, so
    # its status follows the probe like every other capability.
    assert by_id["ui.win32"]["status"] == "ready"
    # A status_probe of None (no probe to consult) is always ready.
    assert capabilities_catalog._probe_status(_stub_report(), None) == "ready"
    # A probe absent from the report falls back to missing rather than raising.
    assert by_id["unpack.upx"]["status"] == "missing"

    # Backend filter returns only that backend's capabilities.
    apk = list_capabilities(backend="apk")
    assert apk and {cap["backend"] for cap in apk} == {"apk"}

    # Status filter returns only matching entries.
    ready = {cap["id"] for cap in list_capabilities(status="ready")}
    assert "ida.idalib" in ready and "ui.win32" in ready
    assert "detect.die" not in ready


def test_describe_capability_finds_known_ids_and_none_for_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capabilities_catalog, "run_doctor", lambda settings=None: _stub_report())

    described = describe_capability("ida.idalib")
    assert described is not None and described["id"] == "ida.idalib"
    assert described["status"] == "ready"

    assert describe_capability("does.not.exist") is None
