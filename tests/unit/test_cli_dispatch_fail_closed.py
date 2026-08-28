"""Fail-closed coverage for the CLI dispatcher's unhandled-command guards.

``test_cli_command_dispatch.py`` pins every routed command through the real
parser, which also means it can never reach the two AssertionError guards at
the bottom of ``_main``: argparse refuses unknown commands before dispatch.
These substitute the parser to prove that a command the dispatcher does not
route fails loudly rather than falling off the end and returning success.
"""

from __future__ import annotations

import argparse

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.config import Settings


class _StubParser:
    def __init__(self, namespace: argparse.Namespace) -> None:
        self._namespace = namespace

    def parse_args(self, argv: object = None) -> argparse.Namespace:
        return self._namespace


def _stub_dispatch(monkeypatch: pytest.MonkeyPatch, namespace: argparse.Namespace) -> None:
    monkeypatch.setattr(cli_module, "build_parser", lambda: _StubParser(namespace))
    monkeypatch.setattr(Settings, "load", staticmethod(lambda _path=None: object()))


def test_an_unrouted_command_raises_instead_of_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_dispatch(monkeypatch, argparse.Namespace(command="bogus", config=None))
    with pytest.raises(AssertionError, match="unhandled command: bogus"):
        cli_module._main([])


def test_an_unrouted_config_subcommand_raises_instead_of_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = argparse.Namespace(command="config", config_command="bogus", config=None)
    _stub_dispatch(monkeypatch, namespace)
    with pytest.raises(AssertionError, match="unhandled config command: bogus"):
        cli_module._main([])
