"""apk.* calls must not spill androguard's loguru flood onto stderr.

androguard 4.x logs prolifically through loguru -- measured ~233 DEBUG records
for a single apk.strings on a two-class APK, thousands for a real app -- all onto
the process's stderr on every call. The apk backend silences androguard's own
records via loguru.disable() when androguard is present. These pin that contract
with fake loguru/androguard modules so they run in CI even without the android
extra installed (where neither library is present).
"""

from __future__ import annotations

import sys
import types

import pytest

import headless_re_mcp.backends.apk.client as apk_client


def _fake_loguru(calls: list[str]) -> types.ModuleType:
    module = types.ModuleType("loguru")
    module.logger = types.SimpleNamespace(disable=calls.append)  # type: ignore[attr-defined]
    return module


def test_silence_disables_androguard_and_apkinspector_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setitem(sys.modules, "loguru", _fake_loguru(calls))
    monkeypatch.setattr(apk_client, "_ANDROGUARD_LOGS_SILENCED", False)

    apk_client._silence_androguard_logs()

    # Scoped by record name: androguard's own logs and its apkInspector parser
    # dependency, nothing else -- a host app's loguru logging is untouched.
    assert "androguard" in calls
    assert "apkInspector" in calls


def test_silence_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setitem(sys.modules, "loguru", _fake_loguru(calls))
    monkeypatch.setattr(apk_client, "_ANDROGUARD_LOGS_SILENCED", False)

    apk_client._silence_androguard_logs()
    first = len(calls)
    apk_client._silence_androguard_logs()

    # The guard means the second call does no work at all.
    assert first > 0
    assert len(calls) == first


def test_silence_survives_a_missing_loguru(monkeypatch: pytest.MonkeyPatch) -> None:
    """loguru rides with androguard; if it is somehow absent, silencing no-ops."""
    monkeypatch.setitem(sys.modules, "loguru", None)  # import loguru -> ImportError
    monkeypatch.setattr(apk_client, "_ANDROGUARD_LOGS_SILENCED", False)

    apk_client._silence_androguard_logs()  # must not raise

    assert apk_client._ANDROGUARD_LOGS_SILENCED is True


def test_apkclient_init_silences_when_androguard_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setitem(sys.modules, "loguru", _fake_loguru(calls))
    monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))
    monkeypatch.setattr(apk_client, "_ANDROGUARD_LOGS_SILENCED", False)

    client = apk_client.ApkClient()

    # androguard imported -> backend available -> flood silenced before any parse.
    assert client.available is True
    assert "androguard" in calls
