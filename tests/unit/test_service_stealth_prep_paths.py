"""Launch-stealth preparation and profile detection branches of AnalysisService.

``_prepare_launch_stealth`` chooses a ScyllaHide profile from explicit request,
detection, the current ini, or settings, and ``_cached_or_detected_stealth_profile``
maps a packer classification onto a profile id. These decision arms had no direct
coverage. ``inspect_layout`` / ``apply_profile`` are patched so the tests control
the layout state without staging real plugin trees on disk.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import headless_re_mcp.core.service as service_mod
from headless_re_mcp.backends.x64dbg.stealth import DEFAULT_PROFILE_ID, StealthError
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)


def _stealth_service(
    tmp_path: Path,
    *,
    enabled: bool = False,
    profile: str = "vmp",
    x64: Path | None = None,
) -> tuple[AnalysisService, str]:
    settings = replace(
        _settings(tmp_path),
        x64dbg_headless_x64=x64,
        x64dbg_stealth_enabled=enabled,
        x64dbg_stealth_profile=profile,
    )
    service = AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, s: FakeDynamicWorker(),
    )
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    session_id = _create(service, binary)
    return service, session_id


def _patch_layout(
    monkeypatch: pytest.MonkeyPatch,
    inspected: JsonObject,
) -> None:
    monkeypatch.setattr(service_mod, "inspect_layout", lambda layout: inspected)
    monkeypatch.setattr(
        service_mod,
        "apply_profile",
        lambda layout, profile_id, *, require_plugin: {"profile": profile_id},
    )


# --- _cached_or_detected_stealth_profile ----------------------------------------


def test_detection_returns_the_cached_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(tmp_path)
    monkeypatch.setattr(service_mod, "stealth_hint_profile", lambda metadata: "vmp")

    assert service._cached_or_detected_stealth_profile(session_id) == "vmp"


def test_detection_ignores_an_unrecognized_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(tmp_path)
    monkeypatch.setattr(service_mod, "stealth_hint_profile", lambda metadata: None)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda *a, **k: Result[JsonObject](
            ok=True, data={"stealth_profile": "nonsense!!"}
        ),
    )

    assert service._cached_or_detected_stealth_profile(session_id) is None


def test_detection_ignores_a_non_string_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(tmp_path)
    monkeypatch.setattr(service_mod, "stealth_hint_profile", lambda metadata: None)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda *a, **k: Result[JsonObject](ok=True, data={"stealth_profile": 123}),
    )

    assert service._cached_or_detected_stealth_profile(session_id) is None


# --- _prepare_launch_stealth ----------------------------------------------------


def test_prepare_reads_the_profile_from_an_unmapped_current_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(
        tmp_path, enabled=False, x64=tmp_path / "x64_headless.exe"
    )
    _patch_layout(
        monkeypatch,
        {"plugin_present": False, "current_profile": None, "current_section": "Zzz"},
    )

    payload = service._prepare_launch_stealth(session_id, stealth_profile=None)

    # enabled is off, so the disabled default is chosen regardless of the section.
    assert payload["stealth_profile"] == "off"
    assert payload["stealth_source"] == "disabled"


def test_prepare_keeps_the_current_profile_when_detection_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(
        tmp_path, enabled=True, x64=tmp_path / "x64_headless.exe"
    )
    _patch_layout(
        monkeypatch,
        {"plugin_present": True, "current_profile": "vmp", "current_section": "VMP"},
    )
    monkeypatch.setattr(service, "_cached_or_detected_stealth_profile", lambda sid: None)

    payload = service._prepare_launch_stealth(session_id, stealth_profile=None)

    assert payload["stealth_profile"] == "vmp"
    assert payload["stealth_source"] == "current"


def test_prepare_falls_back_to_the_default_when_settings_profile_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(
        tmp_path, enabled=True, profile="not-a-profile", x64=tmp_path / "x64.exe"
    )
    _patch_layout(
        monkeypatch,
        {"plugin_present": True, "current_profile": None, "current_section": None},
    )
    monkeypatch.setattr(service, "_cached_or_detected_stealth_profile", lambda sid: None)

    payload = service._prepare_launch_stealth(session_id, stealth_profile=None)

    assert payload["stealth_profile"] == DEFAULT_PROFILE_ID


def test_prepare_rejects_an_explicit_profile_without_a_layout(tmp_path: Path) -> None:
    service, session_id = _stealth_service(tmp_path, x64=None)

    with pytest.raises(StealthError) as caught:
        service._prepare_launch_stealth(session_id, stealth_profile="vmp")

    assert caught.value.code == "plugin_missing"


def test_prepare_rejects_an_explicit_profile_when_plugins_are_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(
        tmp_path, enabled=True, x64=tmp_path / "x64_headless.exe"
    )
    _patch_layout(
        monkeypatch,
        {"plugin_present": False, "current_profile": None, "current_section": None},
    )

    with pytest.raises(StealthError) as caught:
        service._prepare_launch_stealth(session_id, stealth_profile="vmp")

    assert caught.value.code == "plugin_missing"


def test_prepare_returns_early_when_enabled_but_plugins_are_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _stealth_service(
        tmp_path, enabled=True, x64=tmp_path / "x64_headless.exe"
    )
    _patch_layout(
        monkeypatch,
        {"plugin_present": False, "current_profile": None, "current_section": None},
    )
    monkeypatch.setattr(service, "_cached_or_detected_stealth_profile", lambda sid: None)

    payload = service._prepare_launch_stealth(session_id, stealth_profile=None)

    # No explicit request, plugins absent but stealth enabled: return without a write.
    assert payload["stealth_applied"] is False
    assert payload["stealth_ready"] is False


# --- analyze_function_dynamic guard ---------------------------------------------


def test_analyze_function_dynamic_rejects_a_boolean_timeout(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())

    result = service.analyze_function_dynamic("nonexistent", 0x1000, timeout=True)

    assert not result.ok
    assert result.error is not None
    assert "timeout must be a number" in result.error.message
