"""Contract tests for the IDA worker RPC client against a scripted fake worker.

``IdaWorkerClient`` launches ``sys.executable -m headless_re_mcp.backends.ida.worker``
and speaks newline-delimited JSON with it. These tests shadow that worker module
with a scripted stand-in via ``PYTHONPATH`` so the full transport — handshake,
request correlation, error mapping, timeout/overflow retirement, close
semantics, and analyzer-window gating — runs against a real subprocess on every
platform without idalib installed.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from headless_re_mcp.backends.ida import client as client_mod
from headless_re_mcp.backends.ida.client import (
    IdaWorkerClient,
    IdaWorkerError,
    next_receive_deadline,
    startup_receive_remaining,
)
from headless_re_mcp.config import Settings

_PRELUDE = """\
import json
import sys
import time


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\\n")
    sys.stdout.flush()


def requests():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


"""

_READY = 'emit({"event": "ready", "data": {"capabilities": ["ida.decompile"], "backend": "ida"}})\n'

_SERVE = """\
for req in requests():
    if req["command"] == "close":
        emit({"id": req["id"], "ok": True, "data": {}})
        break
    emit({"id": req["id"], "ok": True,
          "data": {"echo": req["command"], "params": req["params"]}})
"""


def _install_fake_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    """Shadow the real worker module so the client launches the scripted fake.

    The child resolves ``headless_re_mcp.backends.ida.worker`` through
    ``PYTHONPATH`` before the installed package, so the same fake runs on every
    platform without touching the interpreter or needing shebang scripts.
    """
    root = tmp_path / "fake_modules"
    pkg = root / "headless_re_mcp" / "backends" / "ida"
    pkg.mkdir(parents=True)
    for init in (
        root / "headless_re_mcp" / "__init__.py",
        root / "headless_re_mcp" / "backends" / "__init__.py",
        pkg / "__init__.py",
    ):
        init.write_text("", encoding="utf-8")
    (pkg / "worker.py").write_text(_PRELUDE + body, encoding="utf-8")
    existing = os.environ.get("PYTHONPATH", "")
    joined = str(root) + (os.pathsep + existing if existing else "")
    monkeypatch.setenv("PYTHONPATH", joined)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=tmp_path / "ida",
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _binary(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ")
    return target


def _spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    *,
    startup_timeout: float = 30.0,
) -> IdaWorkerClient:
    _install_fake_worker(tmp_path, monkeypatch, body)
    return IdaWorkerClient(_binary(tmp_path), _settings(tmp_path), startup_timeout=startup_timeout)


def _wait_for(condition: Callable[[], bool], *, deadline_s: float = 15.0) -> None:
    started = time.monotonic()
    while not condition():
        if time.monotonic() - started > deadline_s:
            raise AssertionError("condition did not become true in time")
        time.sleep(0.02)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_from_payload_rejects_non_dict_payloads() -> None:
    error = IdaWorkerError.from_payload(["not", "a", "dict"])
    assert error.code == "worker_protocol_error"
    assert error.retryable is False


def test_from_payload_reads_fields_and_drops_non_dict_details() -> None:
    error = IdaWorkerError.from_payload(
        {
            "code": "license_error",
            "message": "no seat",
            "details": ["not-a-dict"],
            "retryable": True,
        }
    )
    assert error.code == "license_error"
    assert str(error) == "no seat"
    assert error.details == {}
    assert error.retryable is True

    defaulted = IdaWorkerError.from_payload({})
    assert defaulted.code == "backend_error"
    assert str(defaulted) == "IDA worker failed"


def test_next_receive_deadline_slides_only_on_progress() -> None:
    slid = next_receive_deadline(
        now=100.0,
        deadline=101.0,
        idle_timeout=10.0,
        absolute_deadline=105.0,
        message={"event": "progress"},
        extend_on_progress=True,
    )
    assert slid == 105.0  # capped by the absolute deadline

    unchanged = next_receive_deadline(
        now=100.0,
        deadline=101.0,
        idle_timeout=10.0,
        absolute_deadline=105.0,
        message={"event": "other"},
        extend_on_progress=True,
    )
    assert unchanged == 101.0

    not_extending = next_receive_deadline(
        now=100.0,
        deadline=101.0,
        idle_timeout=10.0,
        absolute_deadline=105.0,
        message={"event": "progress"},
        extend_on_progress=False,
    )
    assert not_extending == 101.0


def test_startup_receive_remaining_waits_on_the_absolute_cap() -> None:
    # A worker holding the GIL inside open_database cannot emit progress, so
    # startup waits out the absolute cap rather than idle silence.
    assert (
        startup_receive_remaining(
            now=100.0,
            idle_deadline=101.0,
            absolute_deadline=140.0,
            extend_on_progress=True,
        )
        == 40.0
    )
    assert (
        startup_receive_remaining(
            now=100.0,
            idle_deadline=101.0,
            absolute_deadline=140.0,
            extend_on_progress=False,
        )
        == 1.0
    )


# ---------------------------------------------------------------------------
# Startup handshake
# ---------------------------------------------------------------------------


def test_missing_ida_home_refuses_before_launching_anything(tmp_path: Path) -> None:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    with pytest.raises(IdaWorkerError) as caught:
        IdaWorkerClient(_binary(tmp_path), settings)
    assert caught.value.code == "backend_unavailable"


def test_ready_handshake_then_request_then_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _spawn(tmp_path, monkeypatch, _READY + _SERVE)
    try:
        assert client.capabilities == frozenset({"ida.decompile"})
        assert client.pid > 0
        assert client.exit_code is None
        assert client.analyzer_windows == ()

        metadata = client.metadata
        assert metadata["backend"] == "ida"
        metadata["backend"] = "mutated"
        assert client.metadata["backend"] == "ida"

        data = client.request("ping", {"value": 7}, timeout=15.0)
        assert data == {"echo": "ping", "params": {"value": 7}}
    finally:
        client.close(timeout=15.0)

    _wait_for(lambda: client.exit_code is not None)
    # A closed client refuses further work and a second close is a no-op.
    with pytest.raises(IdaWorkerError) as caught:
        client.request("ping")
    assert caught.value.code == "session_closed"
    client.close(timeout=15.0)


def test_fatal_startup_event_raises_its_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = (
        'emit({"event": "fatal", "error": {"code": "license_error", '
        '"message": "no seat", "retryable": True}})\n'
        "time.sleep(60)\n"
    )
    with pytest.raises(IdaWorkerError) as caught:
        _spawn(tmp_path, monkeypatch, body)
    assert caught.value.code == "license_error"
    assert caught.value.retryable is True


def test_ready_without_a_data_object_is_a_protocol_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = 'emit({"event": "ready", "data": "not-a-dict"})\ntime.sleep(60)\n'
    with pytest.raises(IdaWorkerError) as caught:
        _spawn(tmp_path, monkeypatch, body)
    assert caught.value.code == "worker_protocol_error"


def test_non_list_capabilities_stay_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = 'emit({"event": "ready", "data": {"capabilities": "oops"}})\n' + _SERVE
    client = _spawn(tmp_path, monkeypatch, body)
    try:
        assert client.capabilities == frozenset()
    finally:
        client.terminate()


def test_startup_tolerates_junk_progress_and_unsolicited_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = (
        'print("this is not json", flush=True)\n'
        "emit([1, 2, 3])\n"
        'emit({"event": "progress", "data": {"stage": "auto_wait"}})\n'
        'emit({"note": "unsolicited"})\n' + _READY + _SERVE
    )
    client = _spawn(tmp_path, monkeypatch, body)
    try:
        assert client.capabilities == frozenset({"ida.decompile"})
        log = list(client._stdout_log)
        assert "this is not json" in log
        assert "[1, 2, 3]" in log
        assert any("unsolicited" in line for line in log)
    finally:
        client.terminate()


def test_worker_that_dies_before_ready_reports_the_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = 'print("boot failure", file=sys.stderr, flush=True)\nsys.exit(9)\n'
    with pytest.raises(IdaWorkerError) as caught:
        _spawn(tmp_path, monkeypatch, body)
    assert caught.value.code == "worker_exited"
    assert caught.value.retryable is True
    assert "boot failure" in caught.value.details.get("stderr", [])


# ---------------------------------------------------------------------------
# Request/response mapping
# ---------------------------------------------------------------------------


def test_error_response_maps_to_a_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _READY + (
        "for req in requests():\n"
        '    emit({"id": req["id"], "ok": False, "error": {"code": "bad_address",'
        ' "message": "nope", "details": {"address": 5}, "retryable": True}})\n'
    )
    client = _spawn(tmp_path, monkeypatch, body)
    try:
        with pytest.raises(IdaWorkerError) as caught:
            client.request("memory.read", timeout=15.0)
        assert caught.value.code == "bad_address"
        assert caught.value.details == {"address": 5}
        assert caught.value.retryable is True
    finally:
        client.terminate()


def test_ok_response_without_data_object_is_a_protocol_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _READY + (
        'for req in requests():\n    emit({"id": req["id"], "ok": True, "data": [1]})\n'
    )
    client = _spawn(tmp_path, monkeypatch, body)
    try:
        with pytest.raises(IdaWorkerError) as caught:
            client.request("info", timeout=15.0)
        assert caught.value.code == "worker_protocol_error"
    finally:
        client.terminate()


def test_request_timeout_retires_the_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A timed-out worker is still inside Hex-Rays; the client must kill it
    # rather than let the next request reuse a wedged process.
    body = _READY + "for req in requests():\n    time.sleep(120)\n"
    client = _spawn(tmp_path, monkeypatch, body)
    with pytest.raises(IdaWorkerError) as caught:
        client.request("decompile", timeout=0.4)
    assert caught.value.code == "worker_timeout"
    assert caught.value.retryable is True
    assert caught.value.details["pid"] == client.pid
    _wait_for(lambda: client.exit_code is not None)


def test_worker_exit_mid_request_reports_worker_exited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _READY + "next(requests())\nsys.exit(7)\n"
    client = _spawn(tmp_path, monkeypatch, body)
    try:
        with pytest.raises(IdaWorkerError) as caught:
            client.request("anything", timeout=15.0)
        assert caught.value.code == "worker_exited"
        assert caught.value.retryable is True
    finally:
        client.terminate()


def test_request_after_worker_death_fails_fast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _spawn(tmp_path, monkeypatch, _READY + "sys.exit(0)\n")
    try:
        _wait_for(lambda: client.exit_code is not None)
        with pytest.raises(IdaWorkerError) as caught:
            client.request("anything")
        assert caught.value.code == "worker_exited"
    finally:
        client.terminate()


def test_unsolicited_flood_overflows_and_retires_the_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # More unread messages than the queue holds must be dropped and surfaced,
    # not accumulated on the heap.
    body = _READY + ('for i in range(1500):\n    emit({"note": i})\ntime.sleep(120)\n')
    client = _spawn(tmp_path, monkeypatch, body)
    _wait_for(client._message_overflow.is_set)
    with pytest.raises(IdaWorkerError) as caught:
        client.request("anything", timeout=15.0)
    assert caught.value.code == "worker_output_overflow"
    assert caught.value.retryable is True
    assert caught.value.details["messages_dropped"] >= 1
    _wait_for(lambda: client.exit_code is not None)


# ---------------------------------------------------------------------------
# Close semantics
# ---------------------------------------------------------------------------


def test_close_after_worker_death_is_quiet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _spawn(tmp_path, monkeypatch, _READY + "sys.exit(0)\n")
    _wait_for(lambda: client.exit_code is not None)
    client.close(timeout=15.0)
    with pytest.raises(IdaWorkerError) as caught:
        client.request("anything")
    assert caught.value.code == "session_closed"


def test_close_kills_a_worker_that_acknowledges_but_never_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _READY + (
        "for req in requests():\n"
        '    if req["command"] == "close":\n'
        '        emit({"id": req["id"], "ok": True, "data": {}})\n'
        "        break\n"
        "time.sleep(120)\n"
    )
    client = _spawn(tmp_path, monkeypatch, body)
    client.close(timeout=0.6)
    _wait_for(lambda: client.exit_code is not None)


def test_close_with_an_unresponsive_worker_raises_and_still_retires_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _READY + "for req in requests():\n    time.sleep(120)\n"
    client = _spawn(tmp_path, monkeypatch, body)
    with pytest.raises(IdaWorkerError) as caught:
        client.close(timeout=0.4)
    assert caught.value.code == "worker_timeout"
    _wait_for(lambda: client.exit_code is not None)
    client.close(timeout=15.0)  # already closed; must be a no-op


# ---------------------------------------------------------------------------
# Analyzer-window gating
# ---------------------------------------------------------------------------


def test_an_analyzer_window_blocks_the_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _spawn(tmp_path, monkeypatch, _READY + _SERVE)
    try:
        monkeypatch.setattr(
            client_mod,
            "describe_process_windows",
            lambda pid: {"0x1:Dialog:License expired"},
        )
        with pytest.raises(IdaWorkerError) as caught:
            client.request("ping", timeout=15.0)
        assert caught.value.code == "analyzer_window_detected"
        assert caught.value.details["windows"] == ["0x1:Dialog:License expired"]
        assert client.analyzer_windows == ("0x1:Dialog:License expired",)

        # A re-sighting of the same window still refuses the call without
        # inflating the history.
        with pytest.raises(IdaWorkerError) as again:
            client.request("ping", timeout=15.0)
        assert again.value.code == "analyzer_window_detected"
        assert client.analyzer_windows == ("0x1:Dialog:License expired",)
    finally:
        client.terminate()


def test_an_analyzer_window_during_startup_fails_the_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        client_mod,
        "describe_process_windows",
        lambda pid: {"0x2:Dialog:First run wizard"},
    )
    with pytest.raises(IdaWorkerError) as caught:
        _spawn(tmp_path, monkeypatch, _READY + _SERVE)
    assert caught.value.code == "analyzer_window_detected"
