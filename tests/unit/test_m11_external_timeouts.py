"""External optional-backend timeout / abnormal-exit unit coverage.

Every CLI-backed client classifies a bounded-runner TimedOut as code
``timeout`` (with the killed pids, so an operator can audit the reaping) and a
launch OSError as ``backend_error``. Only r2 and windbg were pinned; the jsre,
jadx, apktool, and ghidra handlers -- each carrying a deliberate rationale
comment about binding the JVM / node child, not just the launcher script --
had no coverage, so a handler dropped in a refactor would let TimedOut escape
as an internal_error incident. run_bounded is the seam in all of them: it
kills the tree before raising, so the timeout a caller sees is what these pin.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.backends.jsre.client import JsClient, JsReError, WasmClient
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def test_r2_timeout_maps_to_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with patch(
        "headless_re_mcp.backends.r2.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_r2_nonzero_exit_maps_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    fake = Completed(returncode=2, stdout=b"", stderr=b"boom")
    with patch("headless_re_mcp.backends.r2.client.run_bounded", return_value=fake):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "backend_error"


def test_windbg_dump_timeout_maps_to_timeout(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    # The bounded runner is the seam now: it kills the tree before it raises, so
    # the timeout a caller sees is the one it reports here.
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(WindbgError) as exc:
            client.open_dump(dump, ["lm"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_windbg_live_timeout_maps_to_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(WindbgError) as exc:
            client.attach(1234, allowed_pid=1234, timeout=1.0)
    assert exc.value.code == "timeout"


def test_webcrack_timeout_maps_to_timeout(tmp_path: Path) -> None:
    """webcrack runs under node, which the launcher starts as a child; the
    handler promises the deadline reaches it and reports what it killed."""
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("var x = 1;", encoding="utf-8")
    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(JsReError) as exc:
            JsClient(tool).deobfuscate(src, timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_wasm2wat_timeout_maps_to_timeout(tmp_path: Path) -> None:
    """wat shares jsre's _run, but must reach it: the magic precheck runs
    first, so a valid module is what exercises the timeout classification."""
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(JsReError) as exc:
            WasmClient(tool).wat(module, timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_webcrack_launch_failure_maps_to_backend_error(tmp_path: Path) -> None:
    """A tool that is configured but cannot start (unmarked executable, wrong
    arch) is a backend fault, not a timeout and not an unclassified crash."""
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("var x = 1;", encoding="utf-8")
    with patch(
        "headless_re_mcp.backends.jsre.client.run_bounded",
        side_effect=OSError("exec format error"),
    ):
        with pytest.raises(JsReError) as exc:
            JsClient(tool).deobfuscate(src, timeout=1.0)
    assert exc.value.code == "backend_error"
    assert "exec format error" in exc.value.message


def test_jadx_timeout_maps_to_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "jadx.exe"
    stub.write_bytes(b"")
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK\x03\x04")
    with patch(
        "headless_re_mcp.backends.jadx.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(JadxError) as exc:
            JadxClient(stub).export_sources(apk, tmp_path / "out", timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_apktool_timeout_maps_to_timeout(tmp_path: Path) -> None:
    """apktool is a script that starts a JVM; killed_pids is how the handler
    proves the deadline bound the JVM too, not just the wrapper."""
    stub = tmp_path / "apktool.bat"
    stub.write_text("x\n", encoding="utf-8")
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    with patch(
        "headless_re_mcp.backends.apktool.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(ApktoolError) as exc:
            ApktoolClient(stub, None).decode(apk, tmp_path / "out", timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_ghidra_analyze_timeout_maps_to_timeout(tmp_path: Path) -> None:
    """analyzeHeadless starts a JVM that outlives a killed launcher; the
    handler exists so a timed-out analysis reports timeout with the reaped
    pids instead of leaving the JVM holding the project directory."""
    client = GhidraClient()
    stub = tmp_path / "analyzeHeadless"
    stub.write_text("x\n", encoding="utf-8")
    client.analyze = stub
    client.java = stub
    client.uses_pyghidra = False

    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    with patch(
        "headless_re_mcp.backends.ghidra.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(GhidraError) as exc:
            client.analyze_binary(binary, tmp_path / "proj", timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]
