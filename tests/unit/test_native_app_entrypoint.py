"""Coverage for the native launcher entry point (``native_app.__main__``).

The GUI import is lazy and pulls in PySide6, which the hosted job does not
have, so the CLI branch is driven with a patched ``run_cli_setup`` and the GUI
branch with a fake ``native_app.gui`` module injected into ``sys.modules``.
That keeps the argument plumbing and the error boundary honest without Qt.
"""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any

import pytest

import headless_re_mcp.native_app.bootstrap as bootstrap
from headless_re_mcp.native_app import __main__ as entry


def test_cli_flag_runs_the_terminal_wizard(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}

    def fake_run_cli_setup(*, skip_pip: bool, non_interactive: bool, activate_ida: bool) -> int:
        calls.update(skip_pip=skip_pip, non_interactive=non_interactive, activate_ida=activate_ida)
        return 0

    monkeypatch.setattr(bootstrap, "run_cli_setup", fake_run_cli_setup)

    code = entry._main(["--cli"])

    assert code == 0
    assert calls == {"skip_pip": False, "non_interactive": False, "activate_ida": True}


def test_cli_flags_are_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, Any] = {}

    def fake_run_cli_setup(*, skip_pip: bool, non_interactive: bool, activate_ida: bool) -> int:
        calls.update(skip_pip=skip_pip, non_interactive=non_interactive, activate_ida=activate_ida)
        return 2

    monkeypatch.setattr(bootstrap, "run_cli_setup", fake_run_cli_setup)

    code = entry._main(["--cli", "--skip-pip", "--non-interactive", "--no-activate-ida"])

    assert code == 2
    assert calls == {"skip_pip": True, "non_interactive": True, "activate_ida": False}


def _inject_fake_gui(monkeypatch: pytest.MonkeyPatch, run_native_gui: Any) -> None:
    module = ModuleType("headless_re_mcp.native_app.gui")
    module.run_native_gui = run_native_gui  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "headless_re_mcp.native_app.gui", module)


def test_default_path_launches_the_native_gui(monkeypatch: pytest.MonkeyPatch) -> None:
    launched: list[bool] = []

    def fake_gui() -> int:
        launched.append(True)
        return 7

    _inject_fake_gui(monkeypatch, fake_gui)

    code = entry._main([])

    assert code == 7 and launched == [True], "no --cli must launch the GUI"


def test_main_runs_through_the_error_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run_cli_safely(func: Any, *, context: str) -> int:
        seen["context"] = context
        return int(func())

    import headless_re_mcp.error_boundary as error_boundary

    monkeypatch.setattr(error_boundary, "run_cli_safely", fake_run_cli_safely)
    monkeypatch.setattr(
        bootstrap,
        "run_cli_setup",
        lambda *, skip_pip, non_interactive, activate_ida: 0,
    )

    code = entry.main(["--cli"])

    assert code == 0
    assert seen["context"] == "native-app", "the boundary must tag the native-app context"


def test_main_boundary_contains_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real boundary must turn an exception into a non-zero exit, not raise."""

    def boom() -> int:
        raise RuntimeError("gui blew up")

    _inject_fake_gui(monkeypatch, boom)

    code = entry.main([])

    assert isinstance(code, int) and code != 0, "a crash becomes an exit code, never a traceback"
