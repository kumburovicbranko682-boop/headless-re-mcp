"""M4 negative IAT validation and explicit unfixed / no-universal-unpack claims."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker

JsonObject = dict[str, Any]


class _LowConfidenceImportsWorker(FakeDynamicWorker):
    """imports.read returns mostly unresolved thunks for negative validate."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        values = params or {}
        if command == "imports.read":
            self.requests.append((command, values))
            if self.failure is not None:
                raise self.failure
            iat_va = int(values["iat_va"])
            return {
                "iat_va": iat_va,
                "size": values["size"],
                "resolved_count": 0,
                "entries": [
                    {
                        "thunk_va": iat_va,
                        "value": 0x1,
                        "kind": "unresolved",
                    },
                    {
                        "thunk_va": iat_va + 8,
                        "value": 0x2,
                        "kind": "unresolved",
                    },
                    {
                        "thunk_va": iat_va + 16,
                        "value": 0,
                        "kind": "null",
                    },
                ],
            }
        return super().request(command, params, timeout=timeout)


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[section + 40 : section + 48] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section + 48, 0x200, 0x2000, 0x200, 0)
    struct.pack_into("<I", image, section + 76, 0x40000040)
    image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def _service(tmp_path: Path, dynamic: FakeDynamicWorker) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: dynamic,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )


def test_m4_low_confidence_iat_not_confirmed(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = _LowConfidenceImportsWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    validated = service.unpack_iat_validate(
        session_id,
        iat_va=worker.module_base + 0x2000,
        size=0x20,
        oep_rva=0xDEAD,
        module_base=worker.module_base,
    )
    assert validated.ok and validated.data is not None
    assert validated.data["claims_universal_unpack"] is False
    assert validated.data["confirmed"] is False
    assert float(validated.data["confidence"]) < 0.5
    assert validated.data.get("warnings")
    assert any("not confirmed" in str(item).lower() for item in validated.data["unfixed"])
    assert any("forwarded" in str(item).lower() for item in validated.data["unfixed"])


def test_m4_iat_rebuild_runs_pe_verify_and_lists_unfixed(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x400)
    assert dumped.ok and dumped.data is not None
    dump_path = Path(str(dumped.data["output_path"]))
    # Memory-layout dump: .text at RVA 0x1000 must be non-zero for rebuild_gate.
    pe = binary.read_bytes()
    mem_image = bytearray(0x3000)
    mem_image[: len(pe)] = pe
    mem_image[0x1000:0x1100] = b"\x90" * 0x100
    dump_path.write_bytes(mem_image)

    rebuilt = service.unpack_iat_rebuild(
        session_id,
        str(dump_path),
        iat_va=worker.module_base + 0x2000,
        size=0x20,
        oep_rva=0x1000,
    )
    assert rebuilt.ok and rebuilt.data is not None
    assert rebuilt.data["claims_universal_unpack"] is False
    pe_verify = rebuilt.data.get("pe_verify")
    assert isinstance(pe_verify, dict) and pe_verify.get("ok") is True
    report = rebuilt.data["report"]
    assert report["claims_universal_unpack"] is False
    assert any("checksum" in str(item).lower() for item in report["unfixed"])
    assert any("forwarded" in str(item).lower() for item in report["unfixed"])
    assert any("in-place" in str(item).lower() for item in report["changes"])
    assert not any(
        "original IAT bytes" in str(item) for item in report["unfixed"]
    )


def test_unpack_verify_refuses_a_host_pe(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    host = tmp_path / "outside.exe"
    host.write_bytes(binary.read_bytes())
    verified = service.unpack_verify(session_id, str(host), use_die=False, open_ida=False)
    assert verified.ok is False
    assert verified.error is not None
    assert verified.error.code == "invalid_params"


def _session_for_path_tests(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = service.create_session(str(binary)).data["session"]["id"]
    return service, session_id


# A ~user that resolves to nothing (RuntimeError from expanduser) and an
# embedded NUL (ValueError from resolve) are the two ways a caller-supplied
# path used to reach the handlers' ``except BaseException`` and surface as an
# internal_error incident. They must be clean client errors instead: the
# literal ~nosuchuser directory does not exist (file_not_found), and a NUL is
# a malformed request (invalid_request).
_HOSTILE_PATHS = [
    ("~nosuchuser-headless-re/dump.bin", "file_not_found"),
    ("dump\x00.bin", "invalid_request"),
]


@pytest.mark.parametrize(("bad", "code"), _HOSTILE_PATHS)
def test_unpack_strict_dump_path_methods_reject_a_hostile_path(
    tmp_path: Path, bad: str, code: str
) -> None:
    """The methods that resolve(strict=True) before any worker read.

    A tilde no user resolves lands on file_not_found (the literal ~nosuchuser
    directory is absent) and an embedded NUL on invalid_request; neither is an
    internal_error incident any more.
    """
    service, session_id = _session_for_path_tests(tmp_path)
    try:
        calls = [
            service.unpack_stub_coupling(session_id, bad),
            service.unpack_iat_rebuild(session_id, bad, iat_va=0x1000, size=0x100),
            service.unpack_pe_rebuild(session_id, bad),
            service.unpack_verify(session_id, bad, use_die=False, open_ida=False),
        ]
        for result in calls:
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == code
            assert result.error.code != "internal_error"
    finally:
        service.close_all()


@pytest.mark.parametrize("bad", ["~nosuchuser-headless-re/dump.bin", "dump\x00.bin"])
def test_unpack_iat_validate_rejects_a_hostile_dump_path(tmp_path: Path, bad: str) -> None:
    """iat_validate resolves dump_path non-strictly and has no outer except.

    Before the guard the NUL escaped resolve() as an uncaught 500 and the tilde
    escaped expanduser() the same way. Both are now the invalid_params the
    containment check gives any dump_path outside the session artifact root.
    """
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = _LowConfidenceImportsWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok
    try:
        result = service.unpack_iat_validate(
            session_id,
            iat_va=worker.module_base + 0x2000,
            size=0x20,
            module_base=worker.module_base,
            dump_path=bad,
        )
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.parametrize(("bad", "code"), _HOSTILE_PATHS)
def test_dotnet_verify_rejects_a_hostile_path(tmp_path: Path, bad: str, code: str) -> None:
    service, session_id = _session_for_path_tests(tmp_path)
    try:
        result = service.dotnet_verify(session_id, bad)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == code
    finally:
        service.close_all()
