"""The external-unpacker CLI surface must gate capability, input drift and cancel.

``UnpackCliMixin`` wraps the optional UPX/XVLKC/VMPDump/Scylla executables. Each
op refuses to run when the tool is not configured, refuses when the session
input changed on disk after creation, never overwrites the input, and maps a
bounded cancel or a tool-specific error onto a structured ``Result`` rather than
an internal-error incident. The real executables are absent here, so the
injected runner ports are faked and the guards are driven directly.
"""

from __future__ import annotations

import dataclasses
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.scylla import ScyllaError
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError
from headless_re_mcp.unpack.xvlkc import XvlkcError
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _settings,
)

JsonObject = dict[str, Any]


def _write_pe(path: Path) -> None:
    """A minimal but scannable x64 PE (one .text section)."""
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _write_pe_x86(path: Path) -> None:
    """A minimal but scannable x86 PE32 (one .text section)."""
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x10B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 92, 16)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _bare_service(tmp_path: Path) -> AnalysisService:
    """A service with no external unpackers configured."""
    return AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=lambda session, settings: FakeDynamicWorker(),
    )


def _tool_service(tmp_path: Path, **runners: Any) -> AnalysisService:
    """A service with every optional unpacker configured to a dummy executable."""
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    paths: dict[str, Path] = {}
    for name in ("upx", "diec", "xvlkc", "vmp_dumper", "scylla"):
        exe = tools / name
        exe.write_bytes(b"#!/bin/sh\n")
        paths[name] = exe
    settings = dataclasses.replace(
        _settings(tmp_path),
        upx=paths["upx"],
        diec=paths["diec"],
        xvlkc=paths["xvlkc"],
        vmp_dumper=paths["vmp_dumper"],
        scylla=paths["scylla"],
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, settings: FakeDynamicWorker(),
        **runners,
    )


def _session(
    service: AnalysisService, tmp_path: Path, name: str = "sample.exe"
) -> tuple[str, Path]:
    binary = tmp_path / name
    _write_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"]), binary


def _drift(binary: Path) -> None:
    """Rewrite the on-disk input so its sha256 no longer matches the session."""
    binary.write_bytes(binary.read_bytes() + b"\x00drifted")


# --------------------------------------------------------------------------
# capability gating (no tool configured)
# --------------------------------------------------------------------------


def test_upx_test_reports_capability_unavailable(tmp_path: Path) -> None:
    service = _bare_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_test(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


@pytest.mark.parametrize(
    "op",
    [
        lambda s, sid: s.unpack_upx_unpack(sid),
        lambda s, sid: s.unpack_xvlkc_unpack(sid),
        lambda s, sid: s.unpack_vmp_dump(sid, pid=4321),
        lambda s, sid: s.unpack_scylla_rebuild(sid),
    ],
)
def test_optional_unpackers_report_capability_unavailable(tmp_path: Path, op: Any) -> None:
    service = _bare_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = op(service, session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_upx_unpack_rejects_a_non_bool_open_ida(tmp_path: Path) -> None:
    service = _bare_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_unpack(session_id, open_ida="yes")  # type: ignore[arg-type]
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# input-drift gating (tool configured, on-disk input changed)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "op",
    [
        lambda s, sid: s.unpack_upx_test(sid),
        lambda s, sid: s.unpack_upx_unpack(sid),
        lambda s, sid: s.unpack_xvlkc_unpack(sid),
        lambda s, sid: s.unpack_vmp_dump(sid, pid=4321),
        lambda s, sid: s.unpack_scylla_rebuild(sid),
    ],
)
def test_ops_refuse_a_changed_input(tmp_path: Path, op: Any) -> None:
    service = _tool_service(tmp_path)
    session_id, binary = _session(service, tmp_path)
    _drift(binary)
    result = op(service, session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "input_changed"


# --------------------------------------------------------------------------
# UPX test / unpack success and comparison
# --------------------------------------------------------------------------


def test_upx_test_reports_a_clean_run(tmp_path: Path) -> None:
    def tester(upx: Path, pe: Path, *, input_sha256: str, timeout: float) -> Any:
        del upx, pe, input_sha256, timeout
        return SimpleNamespace(to_dict=lambda: {"tested": True, "ok": True})

    service = _tool_service(tmp_path, upx_tester=tester)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_test(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["input_unchanged"] is True
    assert result.data["upx"] == {"tested": True, "ok": True}


def _copy_unpacker() -> Any:
    def unpacker(
        upx: Path, pe: Path, output_path: Path, *, input_sha256: str, timeout: float
    ) -> Any:
        del upx, input_sha256, timeout
        shutil.copyfile(pe, output_path)
        return SimpleNamespace(
            to_dict=lambda: {"unpacked": True},
            output_path=output_path,
            output_sha256=file_sha256(output_path),
        )

    return unpacker


def test_upx_unpack_compares_input_and_output(tmp_path: Path) -> None:
    service = _tool_service(tmp_path, upx_unpacker=_copy_unpacker())
    # Drop DIE so the rescan branch is skipped for this baseline case.
    service.settings = dataclasses.replace(service.settings, diec=None)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_unpack(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["comparison"]["architecture_match"] is True
    assert result.data["die_rescan"] is None
    assert result.data["reanalyze"] is None
    assert result.data["input_unchanged"] is True


def test_upx_unpack_flags_an_architecture_mismatch(tmp_path: Path) -> None:
    def unpacker(
        upx: Path, pe: Path, output_path: Path, *, input_sha256: str, timeout: float
    ) -> Any:
        del upx, pe, input_sha256, timeout
        _write_pe_x86(output_path)  # x86 output vs x64 input
        return SimpleNamespace(
            to_dict=lambda: {"unpacked": True},
            output_path=output_path,
            output_sha256=file_sha256(output_path),
        )

    service = _tool_service(tmp_path, upx_unpacker=unpacker)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_unpack(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "architecture_mismatch"


def test_upx_unpack_records_a_die_rescan(tmp_path: Path) -> None:
    def scanner(diec: Path, path: Path, *, mode: Any, timeout: float) -> Any:
        del diec, path, mode, timeout
        finding = SimpleNamespace(
            category=SimpleNamespace(value="packer"),
            name="UPX",
            summary="packed",
            confidence=88,
        )
        return SimpleNamespace(
            source=SimpleNamespace(version="3.09"),
            findings=[finding],
        )

    service = _tool_service(
        tmp_path, upx_unpacker=_copy_unpacker(), die_scanner=scanner
    )
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_unpack(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["die_rescan"]["status"] == "completed"
    assert result.data["die_rescan"]["findings"][0]["name"] == "UPX"


def test_upx_unpack_records_a_die_rescan_failure(tmp_path: Path) -> None:
    def scanner(diec: Path, path: Path, *, mode: Any, timeout: float) -> Any:
        del diec, path, mode, timeout
        raise DieScanError("diec_failed", "rescan blew up")

    service = _tool_service(
        tmp_path, upx_unpacker=_copy_unpacker(), die_scanner=scanner
    )
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_unpack(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["die_rescan"]["status"] == "failed"


def test_upx_unpack_reanalyzes_when_open_ida_is_set(tmp_path: Path) -> None:
    service = _tool_service(tmp_path, upx_unpacker=_copy_unpacker())
    service.settings = dataclasses.replace(service.settings, diec=None)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_upx_unpack(session_id, open_ida=True)
    assert result.ok, result.error
    assert result.data is not None
    # A child session was created for the unpacked artifact; static open has no
    # IDA worker here, so the reanalysis records the open failure honestly.
    assert result.data["reanalyze"] is not None
    assert result.data["reanalyze"]["static_open_ok"] is False


# --------------------------------------------------------------------------
# external probe: missing / blocked / ready
# --------------------------------------------------------------------------


def test_external_probe_reports_missing_tools(tmp_path: Path) -> None:
    service = _bare_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_external_probe(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["xvlkc"]["status"] == "missing"
    assert result.data["vmp_dumper"]["status"] == "missing"
    assert result.data["scylla"]["status"] == "missing"


def test_external_probe_reports_blocked_when_not_a_file(tmp_path: Path) -> None:
    ghost = tmp_path / "ghost"
    settings = dataclasses.replace(
        _settings(tmp_path), xvlkc=ghost, vmp_dumper=ghost, scylla=ghost
    )
    service = AnalysisService(
        settings, dynamic_worker_factory=lambda s, st: FakeDynamicWorker()
    )
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_external_probe(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["xvlkc"]["status"] == "blocked"
    assert result.data["vmp_dumper"]["status"] == "blocked"
    assert result.data["scylla"]["status"] == "blocked"


def test_external_probe_surfaces_a_probe_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_path: Path) -> Any:
        raise RuntimeError("probe crashed")

    monkeypatch.setattr("headless_re_mcp.unpack.xvlkc.probe_xvlkc", boom)
    service = _tool_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_external_probe(session_id)
    assert result.ok is False
    assert result.error is not None


def test_unpack_auto_reports_not_upx_for_a_plain_binary(tmp_path: Path) -> None:
    service = _bare_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_auto(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["status"] == "not_upx"
    assert result.data["claims_universal_unpack"] is False


def test_external_probe_reports_ready_after_a_successful_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.unpack.xvlkc.probe_xvlkc", lambda p: (True, "xvlkc ok")
    )
    monkeypatch.setattr(
        "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper", lambda p: (True, "vmp ok")
    )
    monkeypatch.setattr(
        "headless_re_mcp.unpack.scylla.probe_scylla", lambda p: (False, "scylla nope")
    )
    service = _tool_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_external_probe(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["xvlkc"]["status"] == "ready"
    assert result.data["vmp_dumper"]["status"] == "ready"
    assert result.data["scylla"]["status"] == "blocked"


# --------------------------------------------------------------------------
# XVLKC / VMPDump / Scylla success, cancel and structured errors
# --------------------------------------------------------------------------


def test_xvlkc_unpack_succeeds(tmp_path: Path) -> None:
    def runner(exe: Path, pe: Path, out: Path, *, input_sha256: str, timeout: float) -> Any:
        del exe, pe, input_sha256, timeout
        out.write_bytes(b"unpacked")
        return SimpleNamespace(to_dict=lambda: {"ran": True}, output_path=out)

    service = _tool_service(tmp_path, xvlkc_runner=runner)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_xvlkc_unpack(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["claims_universal_unpack"] is False


def test_scylla_rebuild_succeeds(tmp_path: Path) -> None:
    def runner(exe: Path, pe: Path, out: Path, *, input_sha256: str, timeout: float) -> Any:
        del exe, pe, input_sha256, timeout
        out.write_bytes(b"rebuilt")
        return SimpleNamespace(to_dict=lambda: {"ran": True}, output_path=out)

    service = _tool_service(tmp_path, scylla_runner=runner)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_scylla_rebuild(session_id)
    assert result.ok, result.error


def test_vmp_dump_uses_an_explicit_pid(tmp_path: Path) -> None:
    def runner(exe: Path, pe: Path, out: Path, **kwargs: Any) -> Any:
        del exe, pe
        out.write_bytes(b"dumped")
        return SimpleNamespace(
            to_dict=lambda: {"ran": True, "pid": kwargs.get("pid")},
            output_path=out,
            dump_ok=True,
            imports_rebuilt=True,
            vm_restored=False,
        )

    service = _tool_service(tmp_path, vmp_dumper_runner=runner)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_vmp_dump(session_id, pid=9182)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pid"] == 9182
    assert result.data["dump_ok"] is True


def test_vmp_dump_falls_back_to_session_metadata_pid(tmp_path: Path) -> None:
    def runner(exe: Path, pe: Path, out: Path, **kwargs: Any) -> Any:
        del exe, pe
        out.write_bytes(b"dumped")
        return SimpleNamespace(
            to_dict=lambda: {"ran": True},
            output_path=out,
            dump_ok=True,
            imports_rebuilt=False,
            vm_restored=False,
        )

    service = _tool_service(tmp_path, vmp_dumper_runner=runner)
    session_id, _ = _session(service, tmp_path)
    service.registry.update_metadata(session_id, {"debuggee_pid": 3311})
    result = service.unpack_vmp_dump(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pid"] == 3311


def test_vmp_dump_requires_a_debuggee(tmp_path: Path) -> None:
    service = _tool_service(tmp_path)
    session_id, _ = _session(service, tmp_path)
    result = service.unpack_vmp_dump(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "debuggee_required"


@pytest.mark.parametrize(
    ("runner_key", "op", "error_type", "expected_code"),
    [
        (
            "xvlkc_runner",
            lambda s, sid: s.unpack_xvlkc_unpack(sid),
            XvlkcError,
            "xvlkc_boom",
        ),
        (
            "vmp_dumper_runner",
            lambda s, sid: s.unpack_vmp_dump(sid, pid=1),
            VmpDumperError,
            "vmp_boom",
        ),
        (
            "scylla_runner",
            lambda s, sid: s.unpack_scylla_rebuild(sid),
            ScyllaError,
            "scylla_boom",
        ),
    ],
)
def test_optional_unpackers_map_structured_errors(
    tmp_path: Path, runner_key: str, op: Any, error_type: Any, expected_code: str
) -> None:
    def runner(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise error_type(expected_code, "tool refused", details={"why": "test"})

    service = _tool_service(tmp_path, **{runner_key: runner})
    session_id, _ = _session(service, tmp_path)
    result = op(service, session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == expected_code
    assert result.error.details == {"why": "test"}


@pytest.mark.parametrize(
    ("runner_key", "op"),
    [
        ("xvlkc_runner", lambda s, sid: s.unpack_xvlkc_unpack(sid)),
        ("vmp_dumper_runner", lambda s, sid: s.unpack_vmp_dump(sid, pid=1)),
        ("scylla_runner", lambda s, sid: s.unpack_scylla_rebuild(sid)),
    ],
)
def test_optional_unpackers_report_a_caller_cancel(
    tmp_path: Path, runner_key: str, op: Any
) -> None:
    def runner(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise BoundedCancelled([])

    service = _tool_service(tmp_path, **{runner_key: runner})
    session_id, _ = _session(service, tmp_path)
    result = op(service, session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


@pytest.mark.parametrize(
    "op",
    [
        lambda s, sid: s.unpack_upx_test(sid),
        lambda s, sid: s.unpack_upx_unpack(sid),
    ],
)
def test_upx_ops_propagate_a_caller_cancel(tmp_path: Path, op: Any) -> None:
    def raiser(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise BoundedCancelled([])

    service = _tool_service(tmp_path, upx_tester=raiser, upx_unpacker=raiser)
    session_id, _ = _session(service, tmp_path)
    with pytest.raises(BoundedCancelled):
        op(service, session_id)
