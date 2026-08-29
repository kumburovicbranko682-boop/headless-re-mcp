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


# The tool-name prefixes whose capabilities are meant to list every tool they
# expose. r2.pipe/ghidra.headless/jsre.webcrack/wasm.wabt already do (all 8 r2
# tools, all 5 ghidra, all 3 js, both wasm), which is what makes the omissions
# on the sibling backends drift rather than curation. web owns three prefixes
# (its CDP, webcrack and wabt capabilities). The PE/Windows backends (static.,
# dynamic., ui., windbg., ...) are curated to headline tools and are out of the
# non-PE scope this reverse check guards.
_NONPE_TOOL_PREFIXES = (
    "r2.",
    "ghidra.",
    "frida.",
    "apk.",
    "device.",
    "web.",
    "js.",
    "wasm.",
    "proxy.",
)


def test_every_nonpe_backend_tool_is_advertised_by_a_capability() -> None:
    """The forward check catches a stale name; nothing caught a missing one.

    ``test_every_advertised_tool_name_is_a_real_catalog_tool`` proves the
    catalog names no ghost tool, but a real tool added to a backend and never
    listed in its capability is invisible to that one-way check -- and that is
    exactly how apk.certificates, device.pull, web.har.export, frida.applications
    and proxy.stop came to be shipped, callable, and gated on their backend, yet
    absent from the capability that an operator reads to learn what installing
    that backend buys. This pins the reverse direction for the non-PE backends
    whose lists are exhaustive by design, so the next added tool must join its
    capability or fail here.
    """
    real = _real_tool_names()
    advertised: set[str] = set()
    for cap in _CORE_CAPABILITIES:
        advertised.update(cap["tools"])
    unadvertised: dict[str, list[str]] = {}
    for prefix in _NONPE_TOOL_PREFIXES:
        missing = sorted(
            name for name in real if name.startswith(prefix) and name not in advertised
        )
        if missing:
            unadvertised[prefix] = missing
    assert not unadvertised, (
        f"non-PE tools registered but not advertised by any capability: {unadvertised}"
    )


def test_every_status_probe_matches_a_real_doctor_probe() -> None:
    probe_names = {probe.name for probe in run_doctor(None).probes}
    stale = {
        cap["id"]: cap["status_probe"]
        for cap in _CORE_CAPABILITIES
        if cap.get("status_probe") and cap["status_probe"] not in probe_names
    }
    assert not stale, f"capability catalog names probes doctor does not emit: {stale}"


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


def test_apk_sign_capability_is_keyed_on_apksigner_not_apktool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """apk.sign must not read ready off apktool when apksigner is absent.

    apktool (decode/repack) and apksigner (sign) are separate binaries with
    separate HEADLESS_RE_* settings and separate doctor probes. While apk.sign
    lived inside the apktool-keyed capability, a host with apktool but no
    apksigner advertised the sign workflow as ready and then failed the call
    with capability_unavailable -- the words/actions split this catalog exists
    to prevent. Drive a report where exactly that holds and assert the two
    capabilities now diverge.
    """
    report = DoctorReport(
        probes=(
            Probe("apktool", ProbeStatus.DETECTED, "apktool present"),
            Probe("apksigner", ProbeStatus.MISSING, "apksigner absent"),
        )
    )
    monkeypatch.setattr(capabilities_catalog, "run_doctor", lambda settings=None: report)

    by_id = {cap["id"]: cap for cap in list_capabilities()}

    assert by_id["apk.apktool"]["status"] == "detected"
    assert by_id["apk.apktool"]["tools"] == ["apk.decode", "apk.repack"]
    assert by_id["apk.apksigner"]["status"] == "missing"
    assert by_id["apk.apksigner"]["tools"] == ["apk.sign"]


def test_describe_capability_finds_known_ids_and_none_for_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capabilities_catalog, "run_doctor", lambda settings=None: _stub_report())

    described = describe_capability("ida.idalib")
    assert described is not None and described["id"] == "ida.idalib"
    assert described["status"] == "ready"

    assert describe_capability("does.not.exist") is None
