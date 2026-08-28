"""Coverage for the package's ``python -m headless_re_mcp`` entry point.

``__main__.py`` is only executed when the package is run as a module, so the
unit suite never imports it and it sits at 0% despite being the real launch
path. Running it via ``runpy`` with the CLI entry stubbed proves the module
wires ``cli.main`` to ``SystemExit`` with its return code, without starting a
server.
"""

from __future__ import annotations

import runpy
from collections.abc import Sequence

import pytest

import headless_re_mcp.cli as cli


def test_module_entrypoint_exits_with_the_cli_return_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Sequence[str] | None] = []

    def _fake_main(argv: Sequence[str] | None = None) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(cli, "main", _fake_main)

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("headless_re_mcp", run_name="__main__")

    # The entry point forwards the CLI's exit code and calls it exactly once.
    assert excinfo.value.code == 0
    assert calls == [None]


def test_module_entrypoint_propagates_a_nonzero_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "main", lambda argv=None: 3)

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("headless_re_mcp", run_name="__main__")

    assert excinfo.value.code == 3
