from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ui import _ui_finalize_windows


def test_dynamic_attach_defaults_pause_after_attach_false() -> None:
    sig = inspect.signature(AnalysisService.dynamic_attach)
    assert sig.parameters["pause_after_attach"].default is False


def test_ui_finalize_windows_empty_hints_children(monkeypatch) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ui.is_pid_alive",
        lambda pid: True,
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates",
        lambda pid, list_windows_fn=None: [
            {"pid": 99, "image": "x", "window_count": 1, "visible_count": 1, "titles": ["T"], "same_image": True}
        ],
    )
    out = _ui_finalize_windows(
        {"windows": []},
        {"allowed": frozenset({1}), "debuggee_pid": 1, "debugger_pid": 2},
    )
    assert out["hint"] == "windows_on_child_pids"
    assert out["suggested_child_pids"] == [99]


def test_ui_process_tree_method_exists() -> None:
    assert hasattr(AnalysisService, "ui_process_tree")


def _attached_service(tmp_path: Path, monkeypatch, probe) -> AnalysisService:  # type: ignore[no-untyped-def]
    """A service whose attach succeeds without a debugger, probing via `probe`."""
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings)
    monkeypatch.setattr("headless_re_mcp.core.service.is_pid_alive", lambda pid: True)

    def fake_request(self: AnalysisService, session_id: str, method: str, params: Any = None, **kwargs: Any):  # type: ignore[no-untyped-def]
        return _success(
            {"submitted": {"method": method}, "state": {"state": "running"}},
            session_id=session_id,
        )

    monkeypatch.setattr(AnalysisService, "_dynamic_request", fake_request)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates", probe
    )
    return service


def test_attach_says_when_the_child_window_probe_crashed(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """A crashed probe must not read as "probed, no child windows".

    The probe is best-effort enrichment, so its exception must not fail the
    attach -- but swallowing it silently left the exact reply of a probe that
    looked and found nothing. For a launcher whose real window lives on a
    child pid, that told the caller to interact with the wrong process. The
    reply now carries child_window_probe_failed with a bounded error so the
    caller knows to run ui.process_tree themselves.
    """

    def exploding_probe(pid: int, *, list_windows_fn: Any = None) -> list[dict[str, Any]]:
        raise OSError("access denied\n  reading /proc children " + "x" * 400)

    service = _attached_service(tmp_path, monkeypatch, exploding_probe)
    result = service.dynamic_attach("sess-probe-crash", 4242)

    assert result.ok, "the probe is enrichment; its crash must not fail the attach"
    data = result.data
    assert isinstance(data, dict)
    assert data["child_window_probe_failed"] is True
    error = data["child_window_probe_error"]
    assert isinstance(error, str)
    assert error.startswith("OSError:")
    assert "access denied" in error
    # Whitespace-collapsed and bounded, so a giant message cannot flood the reply.
    assert "\n" not in error
    assert len(error) <= 300
    # The hint fields stay absent: a failed probe suggests nothing.
    assert "child_windows_hint" not in data
    assert "suggested_child_pids" not in data


def test_attach_stays_clean_when_the_probe_found_no_child_windows(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """Probed-and-found-nothing carries neither hint nor failure fields.

    With the failure flag reserved for crashes, an unmarked reply now means
    the probe ran and the windows really are on the debuggee pid.
    """
    service = _attached_service(
        tmp_path, monkeypatch, lambda pid, *, list_windows_fn=None: []
    )
    result = service.dynamic_attach("sess-probe-empty", 4242)

    assert result.ok
    data = result.data
    assert isinstance(data, dict)
    assert "child_window_probe_failed" not in data
    assert "child_window_probe_error" not in data
    assert "child_windows_hint" not in data


def test_attach_keeps_the_hint_when_the_probe_found_children(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    """The existing hint arc is unchanged by the failure disclosure."""
    candidate = {
        "pid": 77,
        "image": "child.exe",
        "window_count": 1,
        "visible_count": 1,
        "titles": ["Main"],
        "same_image": False,
    }
    service = _attached_service(
        tmp_path, monkeypatch, lambda pid, *, list_windows_fn=None: [candidate]
    )
    result = service.dynamic_attach("sess-probe-found", 4242)

    assert result.ok
    data = result.data
    assert isinstance(data, dict)
    assert data["child_windows_hint"] == "windows_on_child_pids"
    assert data["suggested_child_pids"] == [77]
    assert data["child_candidates"] == [candidate]
    assert "child_window_probe_failed" not in data


def test_an_empty_window_list_on_a_hidden_desktop_says_why() -> None:
    """"No windows" and "not on this desktop" are different answers.

    ui.windows.list enumerates the desktop the service runs on. Under
    hidden_desktop the debuggee's windows live on a separate Win32 desktop
    object, so the list comes back empty -- and an unattended caller reading
    count=0 concludes the sample has no user interface and stops looking.
    hidden_desktop is the setting an unattended deployment is most likely to
    have on, so this is the configuration where the answer misleads.
    """
    from headless_re_mcp.core.service_ui import _ui_finalize_windows

    ctx = {"allowed": frozenset({4242}), "debuggee_pid": 0, "debugger_pid": 1}

    on_visible_desktop = _ui_finalize_windows({"windows": []}, ctx, hidden_desktop=False)
    assert "hint" not in on_visible_desktop, "an ordinary empty list needs no excuse"

    on_hidden_desktop = _ui_finalize_windows({"windows": []}, ctx, hidden_desktop=True)
    assert on_hidden_desktop["hint"] == "windows_on_hidden_desktop"
    assert "ui.virtual_desktop.snapshot" in on_hidden_desktop["suggestion"]

    found = _ui_finalize_windows(
        {"windows": [{"pid": 4242, "hwnd": 7, "title": "x"}]}, ctx, hidden_desktop=True
    )
    assert found["count"] == 1
    assert "hint" not in found, "the hint is for the empty case only"