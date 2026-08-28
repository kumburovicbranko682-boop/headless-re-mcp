"""Profile-selection arcs of ``_prepare_launch_stealth`` and its helpers.

``test_xdbg_stealth`` covers the end-to-end open/launch happy paths; this file
pins the branch arms of ``_prepare_launch_stealth`` that pick the desired
profile (explicit / disabled / detection / current-section / configured-default
fallback) and the layout guards (unconfigured headless, missing plugin), plus
the ``_cached_or_detected_stealth_profile`` and ``_live_stealth_sessions``
edge returns. They call the composition-root helpers directly against on-disk
ScyllaHide layouts so no debugger process is involved.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.x64dbg.stealth import (
    StealthError,
    apply_profile,
    layout_for_headless,
)
from headless_re_mcp.core.models import Architecture, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _settings,
    _write_minimal_pe,
)


def _headless(tmp_path: Path, *, plugin: bool) -> Path:
    root = tmp_path / "x64dbg-x64"
    plugins = root / "plugins"
    plugins.mkdir(parents=True, exist_ok=True)
    headless = root / "headless.exe"
    headless.write_bytes(b"MZ")
    if plugin:
        layout = layout_for_headless(headless, Architecture.X64)
        assert layout is not None
        layout.plugin.write_bytes(b"plugin")
        layout.hook_library.write_bytes(b"hook")
    return headless


def _service(
    tmp_path: Path,
    *,
    headless: Path | None,
    enabled: bool = True,
    default_profile: str = "vmp",
) -> tuple[AnalysisService, str]:
    settings = replace(
        _settings(tmp_path),
        x64dbg_headless_x64=headless,
        x64dbg_stealth_enabled=enabled,
        x64dbg_stealth_profile=default_profile,
    )
    service = AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: FakeDynamicWorker(),
    )
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    session_id = _create(service, binary)
    return service, session_id


# --- _prepare_launch_stealth: current-section derived id ------------------------


def test_prepare_derives_current_id_from_an_unknown_section(tmp_path: Path) -> None:
    headless = _headless(tmp_path, plugin=True)
    service, session_id = _service(tmp_path, headless=headless)
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    # Seed a full ini, then point CurrentProfile at a section that maps to no
    # known profile id: current_profile is None but current_section is a string.
    apply_profile(layout, "vmp", require_plugin=True)
    text = layout.ini.read_text(encoding="utf-8")
    assert "CurrentProfile=VMProtect x86/x64" in text
    layout.ini.write_text(
        text.replace("CurrentProfile=VMProtect x86/x64", "CurrentProfile=Bogus"),
        encoding="utf-8",
    )

    prepared = service._prepare_launch_stealth(session_id, stealth_profile="vmp")

    assert prepared["stealth_profile"] == "vmp"
    assert prepared["stealth_source"] == "explicit"


# --- _prepare_launch_stealth: reuse the current profile -------------------------


def test_prepare_reuses_the_current_profile_when_no_detection(tmp_path: Path) -> None:
    headless = _headless(tmp_path, plugin=True)
    service, session_id = _service(tmp_path, headless=headless)
    layout = layout_for_headless(headless, Architecture.X64)
    assert layout is not None
    apply_profile(layout, "themida", require_plugin=True)

    prepared = service._prepare_launch_stealth(session_id, stealth_profile=None)

    assert prepared["stealth_source"] == "current"
    assert prepared["stealth_profile"] == "themida"


# --- _prepare_launch_stealth: configured-default fallback -----------------------


def test_prepare_falls_back_to_default_when_configured_profile_is_invalid(
    tmp_path: Path,
) -> None:
    headless = _headless(tmp_path, plugin=True)
    # No ini exists yet, so current_id is None; an invalid configured profile
    # forces the DEFAULT_PROFILE_ID fallback.
    service, session_id = _service(
        tmp_path, headless=headless, default_profile="titan"
    )

    prepared = service._prepare_launch_stealth(session_id, stealth_profile=None)

    assert prepared["stealth_source"] == "default"
    assert prepared["stealth_profile"] == "vmp"


# --- _prepare_launch_stealth: layout guards ------------------------------------


def test_prepare_refuses_an_explicit_profile_without_a_configured_headless(
    tmp_path: Path,
) -> None:
    service, session_id = _service(tmp_path, headless=None)

    with pytest.raises(StealthError) as exc:
        service._prepare_launch_stealth(session_id, stealth_profile="vmp")

    assert exc.value.code == "plugin_missing"


def test_prepare_refuses_an_explicit_profile_when_the_plugin_is_missing(
    tmp_path: Path,
) -> None:
    headless = _headless(tmp_path, plugin=False)
    service, session_id = _service(tmp_path, headless=headless)

    with pytest.raises(StealthError) as exc:
        service._prepare_launch_stealth(session_id, stealth_profile="vmp")

    assert exc.value.code == "plugin_missing"
    assert exc.value.details["architecture"] == "x64"


def test_prepare_returns_unapplied_when_enabled_but_plugin_missing(
    tmp_path: Path,
) -> None:
    headless = _headless(tmp_path, plugin=False)
    service, session_id = _service(
        tmp_path, headless=headless, enabled=True, default_profile="off"
    )

    prepared = service._prepare_launch_stealth(session_id, stealth_profile=None)

    assert prepared["stealth_ready"] is False
    assert prepared["stealth_applied"] is False


# --- _cached_or_detected_stealth_profile ---------------------------------------


def test_cached_profile_is_returned_from_session_metadata(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path, headless=None)
    service.registry.update_metadata(session_id, {"stealth_hint": {"profile": "themida"}})

    assert service._cached_or_detected_stealth_profile(session_id) == "themida"


def test_detected_profile_that_is_unknown_becomes_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path, headless=None)
    monkeypatch.setattr(
        AnalysisService,
        "packer_classify",
        lambda self, sid, **kw: Result[JsonObject](
            ok=True, data={"stealth_profile": "titan"}
        ),
    )

    assert service._cached_or_detected_stealth_profile(session_id) is None


def test_detected_profile_that_is_not_a_string_becomes_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path, headless=None)
    monkeypatch.setattr(
        AnalysisService,
        "packer_classify",
        lambda self, sid, **kw: Result[JsonObject](
            ok=True, data={"stealth_profile": 123}
        ),
    )

    assert service._cached_or_detected_stealth_profile(session_id) is None


# --- _live_stealth_sessions ----------------------------------------------------


def test_live_stealth_sessions_skips_a_vanished_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.core.session import SessionNotFound

    service, session_id = _service(tmp_path, headless=None)
    assert service.open_dynamic(session_id).ok
    # The runtime is still registered as active, but the session lookup races
    # with teardown and misses: the arch scan must skip it, not crash.
    original = type(service.registry).get

    def racing_get(self: object, sid: str) -> object:
        if sid == session_id:
            raise SessionNotFound(sid)
        return original(self, sid)

    monkeypatch.setattr(type(service.registry), "get", racing_get)

    assert service._live_stealth_sessions(Architecture.X64) == ()
