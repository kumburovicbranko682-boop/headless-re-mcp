"""ScyllaHide profile control: live plugins dir, whitelist, architecture lock."""

from __future__ import annotations

from headless_re_mcp.backends.x64dbg.stealth import (
    StealthError,
    apply_profile,
    canonical_profile_id,
    inspect_layout,
    layout_for_headless,
    profile_from_candidates,
    read_current_section,
    stealth_hint_profile,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, BackendKind
from headless_re_mcp.core.service import AnalysisService, DynamicWorker
from headless_re_mcp.doctor import ProbeStatus, probe_x64dbg_scyllahide
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _write_minimal_pe,
)


def _plugin_headless(tmp_path, architecture: Architecture):
    root = tmp_path / f"x64dbg-{architecture.value}"
    plugins = root / "plugins"
    plugins.mkdir(parents=True)
    headless = root / "headless.exe"
    headless.write_bytes(b"MZ")
    layout = layout_for_headless(headless, architecture)
    assert layout is not None
    layout.plugin.write_bytes(b"plugin")
    layout.hook_library.write_bytes(b"hook")
    return headless


def _settings_with_plugins(
    tmp_path,
    *,
    x86: bool = False,
    x64: bool = True,
    enabled: bool = True,
) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=_plugin_headless(tmp_path, Architecture.X64) if x64 else None,
        x64dbg_headless_x86=_plugin_headless(tmp_path, Architecture.X86) if x86 else None,
        artifact_root=tmp_path / "artifacts",
        debug_event_background_drain=False,
        x64dbg_stealth_enabled=enabled,
        x64dbg_stealth_profile="vmp",
    )


def test_canonical_profile_aliases_and_unknown() -> None:
    assert canonical_profile_id("VMProtect") == "vmp"
    assert canonical_profile_id("disabled") == "off"
    assert canonical_profile_id("tmd") == "themida"
    assert canonical_profile_id("WinLicense") == "themida"
    assert canonical_profile_id("Oreans") == "themida"
    assert canonical_profile_id("Themida x86/x64") == "themida"
    try:
        canonical_profile_id("titan")
    except StealthError as exc:
        assert exc.code == "invalid_params"
    else:
        raise AssertionError("unknown profile must be invalid_params")


def test_apply_profile_writes_disabled_and_quiets_server(tmp_path) -> None:
    headless = _plugin_headless(tmp_path, Architecture.X64)
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    applied = apply_profile(layout, "vmp", require_plugin=True)
    assert applied["section"] == "VMProtect x86/x64"
    apply_profile(layout, "off", require_plugin=False)
    assert read_current_section(layout.ini) == "Disabled"
    text = layout.ini.read_text(encoding="utf-8")
    assert "AutostartServer=0" in text
    assert "ServerPort=0" in text
    assert "AutostartServer=1" not in text


def test_armadillo_rejected_on_x64(tmp_path) -> None:
    headless = _plugin_headless(tmp_path, Architecture.X64)
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    try:
        apply_profile(layout, "armadillo", require_plugin=True)
    except StealthError as exc:
        assert exc.code == "invalid_params"
    else:
        raise AssertionError("x64 armadillo must be invalid_params")


def test_missing_plugin_fails_when_required(tmp_path) -> None:
    root = tmp_path / "x64dbg-x64"
    (root / "plugins").mkdir(parents=True)
    headless = root / "headless.exe"
    headless.write_bytes(b"MZ")
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    try:
        apply_profile(layout, "vmp", require_plugin=True)
    except StealthError as exc:
        assert exc.code == "plugin_missing"
    else:
        raise AssertionError("missing plugin must fail closed")


def test_doctor_probe_follows_live_headless_dir(tmp_path) -> None:
    empty = probe_x64dbg_scyllahide(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    assert empty.status == ProbeStatus.MISSING
    settings = _settings_with_plugins(tmp_path)
    ready = probe_x64dbg_scyllahide(settings)
    assert ready.status == ProbeStatus.READY
    assert ready.details["x64"]["plugin_present"] is True


def test_stealth_set_refused_when_architecture_worker_is_live(tmp_path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    settings = _settings_with_plugins(tmp_path)
    worker = FakeDynamicWorker()
    service = AnalysisService(settings, dynamic_worker_factory=lambda session, cfg: worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    refused = service.dynamic_stealth_set("themida", session_id=session_id)
    assert not refused.ok
    assert refused.error is not None
    assert refused.error.code == "debugger_already_open"
    service.close_all()


def test_launch_stealth_profile_opens_when_backend_is_closed(tmp_path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    settings = _settings_with_plugins(tmp_path)
    worker = FakeDynamicWorker()

    def factory(session: object, cfg: Settings) -> DynamicWorker:
        del session, cfg
        return worker

    service = AnalysisService(settings, dynamic_worker_factory=factory)
    session_id = _create(service, binary)
    launched = service.dynamic_launch(session_id, stealth_profile="themida")
    assert launched.ok and launched.data is not None
    assert launched.data["stealth_profile"] == "themida"
    assert launched.data["stealth_applied"] is True
    layout = layout_for_headless(settings.x64dbg_headless_x64, Architecture.X64)
    assert layout is not None
    assert read_current_section(layout.ini) == "Themida x86/x64"
    assert BackendKind.X64DBG in service.registry.get(session_id).backends
    mismatch = service.dynamic_launch(session_id, stealth_profile="vmp")
    assert not mismatch.ok
    assert mismatch.error is not None
    assert mismatch.error.code == "debugger_already_open"
    service.close_all()


def test_enabled_false_writes_disabled_on_open(tmp_path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    settings = _settings_with_plugins(tmp_path, enabled=False)
    layout = layout_for_headless(settings.x64dbg_headless_x64, Architecture.X64)
    assert layout is not None
    apply_profile(layout, "vmp", require_plugin=True)
    worker = FakeDynamicWorker()
    service = AnalysisService(settings, dynamic_worker_factory=lambda session, cfg: worker)
    session_id = _create(service, binary)
    opened = service.open_dynamic(session_id)
    assert opened.ok and opened.data is not None
    assert opened.data["stealth_profile"] == "off"
    assert read_current_section(layout.ini) == "Disabled"
    launched = service.dynamic_launch(session_id)
    assert launched.ok and launched.data is not None
    assert launched.data["stealth_profile"] == "off"
    assert launched.data["stealth_applied"] is False
    service.close_all()


def test_status_does_not_expose_listen_port(tmp_path) -> None:
    settings = _settings_with_plugins(tmp_path)
    service = AnalysisService(settings)
    status = service.dynamic_stealth_status()
    assert status.ok and status.data is not None
    dumped = str(status.data)
    assert "1337" not in dumped
    assert "ServerPort" not in dumped
    inspected = inspect_layout(
        layout_for_headless(settings.x64dbg_headless_x64, Architecture.X64)
    )
    assert inspected["plugin_present"] is True
    service.close_all()


def test_profile_from_candidates_maps_tmd_and_ignores_upx() -> None:
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "Themida / WinLicense", "confidence": 0.9}]
        )
        == "themida"
    )
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "TMD", "summary": "Oreans", "confidence": 0.8}]
        )
        == "themida"
    )
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "VMProtect 3.x", "confidence": 0.9}]
        )
        == "vmp"
    )
    assert (
        profile_from_candidates(
            [{"category": "packer", "name": "UPX", "summary": "Packer: UPX", "confidence": 1.0}]
        )
        is None
    )
    assert (
        profile_from_candidates(
            [{"category": "protector", "name": "Armadillo", "confidence": 0.7}],
            architecture=Architecture.X64,
        )
        == "basic"
    )


def test_launch_applies_themida_from_classify_without_explicit_profile(tmp_path) -> None:
    from datetime import UTC, datetime

    from headless_re_mcp.detection import (
        DetectionEvidence,
        DetectionFinding,
        DetectionSource,
        FindingCategory,
        ScanMode,
    )
    from headless_re_mcp.detection.die import DieScanResult
    from tests.unit.test_detection_service import _write_pe

    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    diec = tmp_path / "diec.exe"
    diec.write_bytes(b"placeholder")
    plugins = _settings_with_plugins(tmp_path)
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=plugins.x64dbg_headless_x64,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        debug_event_background_drain=False,
        x64dbg_stealth_enabled=True,
        x64dbg_stealth_profile="vmp",
        diec=diec,
    )
    finding = DetectionFinding(
        id="die:0:0",
        category=FindingCategory.PROTECTOR,
        name="Themida",
        summary="Protector: Themida / WinLicense",
        confidence=1.0,
        source="diec",
        evidence=(
            DetectionEvidence(
                kind="die_signature",
                description="Protector: Themida",
                details={"type": "Protector"},
            ),
        ),
    )

    def die_scanner(executable, path, *, mode, timeout):
        del executable, mode, timeout
        return DieScanResult(
            path=path,
            size=path.stat().st_size,
            mode=ScanMode.NORMAL,
            findings=(finding,),
            source=DetectionSource(
                name="diec", status="completed", version="3.21", summary="Themida"
            ),
            raw={"detects": []},
            raw_json='{"detects": []}',
            stdout='{"detects": []}',
            stderr="",
            returncode=0,
            scanned_at=datetime.now(UTC),
        )

    worker = FakeDynamicWorker()
    service = AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: worker,
        die_scanner=die_scanner,
    )
    session_id = _create(service, binary)
    launched = service.dynamic_launch(session_id)
    assert launched.ok and launched.data is not None
    assert launched.data["stealth_profile"] == "themida"
    assert launched.data["stealth_source"] == "detection"
    assert launched.data["stealth_applied"] is True
    assert stealth_hint_profile(service.registry.get(session_id).metadata) == "themida"
    layout = layout_for_headless(settings.x64dbg_headless_x64, Architecture.X64)
    assert layout is not None
    assert read_current_section(layout.ini) == "Themida x86/x64"
    service.close_all()

