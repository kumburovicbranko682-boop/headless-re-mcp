"""windbg and cdb/ghidra CLI timeouts must be clamped before run_bounded.

Every windbg/ghidra tool schema declares 0 < timeout <= N, but FastMCP only
enforces that on the MCP path. The agent transport calls handlers straight
from model arguments (CommandCatalog.invoke -> spec.handler(**arguments)), so
the deadline reaching run_bounded is only bounded when the client clamps it --
which r2/jadx/apktool/jsre already do and these two did not. Left unclamped a
model-supplied 1e9 holds a worker (and, for ghidra, the project lock) for that
long, and a non-positive/NaN value makes run_bounded kill the child at once and
report a timeout for what is really a bad parameter.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.ghidra import client as ghidra_client
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.backends.windbg import client as windbg_client
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


class _Recorder:
    """Stand in for run_bounded, capturing the timeout it was handed."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, _cmd: list[str], **kwargs: Any) -> Completed:
        self.calls.append(kwargs["timeout"])
        return Completed(returncode=0, stdout=b"", stderr=b"")


@pytest.fixture
def cdb_file(tmp_path: Path) -> Path:
    path = tmp_path / "cdb.exe"
    path.write_bytes(b"stub")
    return path


@pytest.fixture
def dump_file(tmp_path: Path) -> Path:
    path = tmp_path / "crash.dmp"
    path.write_bytes(b"stub")
    return path


def test_windbg_dump_timeout_is_clamped_to_the_schema_max(
    monkeypatch: pytest.MonkeyPatch, cdb_file: Path, dump_file: Path
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(windbg_client, "run_bounded", recorder)
    client = WindbgClient(cdb=cdb_file)

    client.threads(dump_file, timeout=1e9)

    assert recorder.calls == [300.0]


def test_windbg_live_timeout_is_clamped_to_the_lower_live_max(
    monkeypatch: pytest.MonkeyPatch, cdb_file: Path
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(windbg_client, "run_bounded", recorder)
    client = WindbgClient(cdb=cdb_file)

    client.live_threads(4242, allowed_pid=4242, timeout=1e9)

    assert recorder.calls == [120.0]


def test_windbg_in_range_timeout_passes_through(
    monkeypatch: pytest.MonkeyPatch, cdb_file: Path, dump_file: Path
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(windbg_client, "run_bounded", recorder)
    client = WindbgClient(cdb=cdb_file)

    client.threads(dump_file, timeout=45.0)

    assert recorder.calls == [45.0]


@pytest.mark.parametrize("bad", [0, -1.0, math.nan], ids=["zero", "negative", "nan"])
def test_windbg_dump_bad_timeout_is_refused_before_launch(
    monkeypatch: pytest.MonkeyPatch, cdb_file: Path, dump_file: Path, bad: float
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(windbg_client, "run_bounded", recorder)
    client = WindbgClient(cdb=cdb_file)

    with pytest.raises(WindbgError) as excinfo:
        client.threads(dump_file, timeout=bad)

    assert excinfo.value.code == "invalid_params"
    assert recorder.calls == []


@pytest.mark.parametrize("bad", [0, -1.0, math.nan], ids=["zero", "negative", "nan"])
def test_windbg_live_bad_timeout_is_refused_before_launch(
    monkeypatch: pytest.MonkeyPatch, cdb_file: Path, bad: float
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(windbg_client, "run_bounded", recorder)
    client = WindbgClient(cdb=cdb_file)

    with pytest.raises(WindbgError) as excinfo:
        client.live_threads(4242, allowed_pid=4242, timeout=bad)

    assert excinfo.value.code == "invalid_params"
    assert recorder.calls == []


def _ghidra_client(analyze: Path) -> GhidraClient:
    client = GhidraClient()
    client.analyze = analyze
    client.java = analyze
    return client


def test_ghidra_headless_timeout_is_clamped_to_the_schema_max(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(ghidra_client, "run_bounded", recorder)
    analyze = tmp_path / "analyzeHeadless"
    analyze.write_bytes(b"stub")
    client = _ghidra_client(analyze)

    client._run_headless(
        tmp_path / "proj",
        binary=tmp_path / "sample.bin",
        extra=[],
        timeout=1e9,
        max_heap="2G",
        delete_project=False,
    )

    assert recorder.calls == [600.0]


def test_ghidra_in_range_timeout_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(ghidra_client, "run_bounded", recorder)
    analyze = tmp_path / "analyzeHeadless"
    analyze.write_bytes(b"stub")
    client = _ghidra_client(analyze)

    client._run_headless(
        tmp_path / "proj",
        binary=tmp_path / "sample.bin",
        extra=[],
        timeout=200.0,
        max_heap="2G",
        delete_project=False,
    )

    assert recorder.calls == [200.0]


@pytest.mark.parametrize("bad", [0, -5.0, math.nan], ids=["zero", "negative", "nan"])
def test_ghidra_bad_timeout_is_refused_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad: float
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(ghidra_client, "run_bounded", recorder)
    analyze = tmp_path / "analyzeHeadless"
    analyze.write_bytes(b"stub")
    client = _ghidra_client(analyze)

    with pytest.raises(GhidraError) as excinfo:
        client._run_headless(
            tmp_path / "proj",
            binary=tmp_path / "sample.bin",
            extra=[],
            timeout=bad,
            max_heap="2G",
            delete_project=False,
        )

    assert excinfo.value.code == "invalid_params"
    assert recorder.calls == []
