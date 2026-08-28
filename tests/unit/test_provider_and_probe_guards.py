"""Guard and edge-branch coverage for small provider/backends/doctor helpers.

These drive the remaining uncovered arcs in three otherwise-complete modules:

* ``agent/providers/openai_compatible.py`` -- the empty-thinking-delta skips in
  ``_hidden_texts`` and the already-reported branch of ``build_client``.
* ``backends/common/subprocess_rpc.py`` -- the Windows-only ``STARTUPINFO`` arm
  of ``no_window_popen_kwargs`` (exercised on any host by faking ``os.name`` and
  supplying a stand-in ``subprocess.STARTUPINFO``).
* ``doctor.py`` -- the DETECTED return of ``probe_python_module``.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

import pytest

import headless_re_mcp.backends.common.subprocess_rpc as subprocess_rpc
from headless_re_mcp.agent.providers import openai_compatible
from headless_re_mcp.agent.providers.openai_compatible import _hidden_texts, build_client
from headless_re_mcp.doctor import ProbeStatus, probe_python_module


def test_hidden_texts_skips_empty_reasoning_dict() -> None:
    # reasoning is a dict but carries no text/content/summary, so _plain_text
    # returns "" and the append is skipped (58->60).
    assert _hidden_texts({"reasoning": {}}) == []


def test_hidden_texts_skips_non_dict_google_extra() -> None:
    # extra_content is a dict, but its ``google`` entry is not, so the google
    # branch is skipped (65->69).
    assert _hidden_texts({"extra_content": {"google": "not-a-dict"}}) == []


def test_hidden_texts_skips_empty_google_thought() -> None:
    # google is a dict but its thought/thoughts are empty, so nothing is
    # appended (67->69).
    assert _hidden_texts({"extra_content": {"google": {"thought": ""}}}) == []


def test_hidden_texts_collects_reasoning_and_google() -> None:
    texts = _hidden_texts(
        {
            "reasoning": {"summary": "why"},
            "extra_content": {"google": {"thoughts": "hmm"}},
        }
    )
    # ``reasoning`` is both a hidden-delta key and handled explicitly, so its
    # text lands twice, followed by the google thought.
    assert texts == ["why", "why", "hmm"]


class _FakeInvalidURL(Exception):
    """Stand-in for ``httpx.InvalidURL``."""


class _FakeHttpx:
    """Minimal httpx stub whose first AsyncClient build rejects the proxy env."""

    InvalidURL = _FakeInvalidURL

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create_ssl_context(self) -> str:
        return "ssl-context"

    def AsyncClient(self, **options: Any) -> tuple[str, dict[str, Any]]:
        self.calls.append(options)
        if "trust_env" not in options:
            raise _FakeInvalidURL("Invalid port: ':1'")
        return ("client", options)


def test_build_client_skips_alert_when_already_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With the module flag already set, the bad-proxy alert is not emitted a
    # second time; build_client goes straight to the trust_env=False retry
    # (288->297).
    monkeypatch.setattr(openai_compatible, "_reported_bad_proxy_env", True)

    def _fail_alert(*args: Any, **kwargs: Any) -> None:  # pragma: no cover - guard
        raise AssertionError("record_alert must not be called when already reported")

    monkeypatch.setattr(openai_compatible, "record_alert", _fail_alert)

    fake = _FakeHttpx()
    # A supplied transport skips the shared-SSL branch, keeping the global
    # _ssl_context cache untouched.
    client, options = build_client(fake, transport="sentinel")
    assert client == "client"
    assert options["trust_env"] is False
    assert options["transport"] == "sentinel"


def test_no_window_popen_kwargs_windows_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # subprocess_rpc reads os.name / subprocess.STARTUPINFO from the shared
    # stdlib module objects, so patching them here is what the helper observes.
    monkeypatch.setattr(os, "name", "nt")

    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow: int | None = None

    monkeypatch.setattr(subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 0x1, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    kwargs = subprocess_rpc.no_window_popen_kwargs()

    startupinfo = kwargs["startupinfo"]
    assert isinstance(startupinfo, _FakeStartupInfo)
    assert startupinfo.dwFlags == 0x1
    assert startupinfo.wShowWindow == 0
    assert kwargs["creationflags"] == 0x08000000


def test_probe_python_module_reports_present_module() -> None:
    probe = probe_python_module("os-probe", "os")
    assert probe.status is ProbeStatus.DETECTED
    assert probe.name == "os-probe"
    assert "origin" in probe.details
