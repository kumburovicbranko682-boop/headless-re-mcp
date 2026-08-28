"""The package-level ``run_native_gui`` defers its PySide6 import until called.

``headless_re_mcp.native_app.run_native_gui`` (in the package ``__init__``) exists
so ``from headless_re_mcp.native_app import bootstrap`` stays importable on the
hosted quality job, which never installs the native extra: the ``gui`` import is
performed inside the function body rather than at module load. The ``__main__``
entry point imports ``gui`` on its own path, so nothing in the suite exercised
the package-level wrapper -- its lazy import and return were uncovered, and a
regression that imported ``gui`` at package load (breaking collection) or dropped
the return value would have gone unnoticed. Faking the ``gui`` submodule lets this
run on Linux, where PySide6 is absent.
"""

from __future__ import annotations

import sys
import types

import pytest

import headless_re_mcp.native_app as native_app


def test_run_native_gui_defers_to_the_gui_submodule(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []
    fake = types.ModuleType("headless_re_mcp.native_app.gui")

    def run_native_gui() -> int:
        calls.append(True)
        return 42

    fake.run_native_gui = run_native_gui  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "headless_re_mcp.native_app.gui", fake)

    # The package-level wrapper must forward to the submodule and return its code.
    assert native_app.run_native_gui() == 42
    assert calls == [True]


def test_importing_the_package_does_not_import_gui() -> None:
    # The whole point of the lazy import: importing the package (done at the top
    # of this module) must not have pulled in the PySide6-backed gui submodule.
    # If it had, collection would fail on machines without the native extra.
    assert "headless_re_mcp.native_app.gui" not in sys.modules
