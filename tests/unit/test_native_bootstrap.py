"""First-run CLI must not wait forever on a hung pip install."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import run_bounded as real_run_bounded
from headless_re_mcp.native_app import bootstrap


def test_importing_bootstrap_does_not_load_the_qt_gui() -> None:
    """Package __init__ used to import gui.py, which imports PySide6.

    Hosted quality installs .[test,dev,web] and has no Qt, so collection
    died on ModuleNotFoundError before any test ran.
    """
    assert "headless_re_mcp.native_app.gui" not in sys.modules


def test_pip_install_editable_kills_a_hung_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured: the same call shape as pip_install_editable (no timeout)
    left a sleeper alive after 3.01s (pid still poll() is None). A stalled
    index or hung wheel build then holds the first-run wizard for the rest
    of the night. Bound it and kill the tree.
    """
    sleeper = [sys.executable, "-c", "import time; time.sleep(30)"]

    def wrapped(cmd: list[str], **kwargs: object) -> object:
        return real_run_bounded(sleeper, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(bootstrap, "run_bounded", wrapped)
    t0 = time.perf_counter()
    code = bootstrap.pip_install_editable(tmp_path, timeout=0.8)
    elapsed = time.perf_counter() - t0
    assert elapsed < 8.0
    assert code == 124
