"""Cover the native launcher's argument dispatch.

``python -m headless_re_mcp.native_app`` parses a small flag set and either runs
the terminal setup wizard (``--cli``) or the GUI. The GUI module needs PySide6,
which is absent on the Linux test host, so the default path is exercised by
injecting a fake ``gui`` module into ``sys.modules`` before the lazy import runs.
"""

from __future__ import annotations

import sys
import types

import pytest

import headless_re_mcp.native_app.__main__ as entry


def _install_fake_gui(monkeypatch: pytest.MonkeyPatch, result: int) -> list[bool]:
    calls: list[bool] = []
    fake = types.ModuleType("headless_re_mcp.native_app.gui")

    def run_native_gui() -> int:
        calls.append(True)
        return result

    fake.run_native_gui = run_native_gui  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "headless_re_mcp.native_app.gui", fake)
    return calls


def test_default_routes_to_native_gui(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_fake_gui(monkeypatch, result=7)
    import headless_re_mcp.native_app.bootstrap as bootstrap

    monkeypatch.setattr(
        bootstrap,
        "run_cli_setup",
        lambda **_: pytest.fail("default path must not run the CLI wizard"),
    )

    assert entry._main([]) == 7
    assert calls == [True]


def test_cli_flag_routes_to_wizard_with_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    import headless_re_mcp.native_app.bootstrap as bootstrap

    def fake_run_cli_setup(**kwargs: object) -> int:
        captured.update(kwargs)
        return 3

    monkeypatch.setattr(bootstrap, "run_cli_setup", fake_run_cli_setup)

    assert entry._main(["--cli"]) == 3
    assert captured == {"skip_pip": False, "non_interactive": False, "activate_ida": True}


def test_cli_flags_map_to_wizard_kwargs(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    import headless_re_mcp.native_app.bootstrap as bootstrap

    def fake_run_cli_setup(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(bootstrap, "run_cli_setup", fake_run_cli_setup)

    entry._main(["--cli", "--skip-pip", "--non-interactive", "--no-activate-ida"])

    # --no-activate-ida inverts to activate_ida=False.
    assert captured == {"skip_pip": True, "non_interactive": True, "activate_ida": False}


def test_main_runs_under_the_error_boundary_with_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    import headless_re_mcp.error_boundary as error_boundary

    def fake_run_cli_safely(action: object, *, context: str) -> int:
        seen["context"] = context
        return action()  # type: ignore[operator]

    monkeypatch.setattr(error_boundary, "run_cli_safely", fake_run_cli_safely)
    _install_fake_gui(monkeypatch, result=5)

    assert entry.main([]) == 5
    assert seen["context"] == "native-app"
