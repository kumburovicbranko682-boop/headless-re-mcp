"""Branch and error paths across unpack.pe.rebuild.

The happy remap (with and without an IAT rebuild) is covered elsewhere; those
tests never trip the four stage guards, the dump-path validation, the memory
refusal, or the non-list imports payload. These drive each through the real
service against the fake worker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from tests.unit.test_service_unpack_iat_paths import _iat_va, _stage_blocker
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]


def test_pe_rebuild_returns_the_first_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("pe_rebuild"))

    result = service.unpack_pe_rebuild(session_id, str(dump_file), entry_point_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_pe_rebuild_rejects_a_dump_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    outsider = tmp_path / "loose.bin"
    outsider.write_bytes(b"MZ" + b"\x00" * 64)

    result = service.unpack_pe_rebuild(session_id, str(outsider), entry_point_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_pe_rebuild_returns_the_memory_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, _worker = _ready_iat_rebuild(tmp_path)
    refusal: Result[JsonObject] = Result(
        ok=False,
        error=RpcError(code="rebuild_too_large", message="would not fit"),
    )

    def read_dump(path: Path) -> tuple[bytes | None, Result[JsonObject] | None]:
        return None, refusal

    monkeypatch.setattr(service_unpack, "_read_dump_for_rebuild", read_dump)

    result = service.unpack_pe_rebuild(session_id, str(dump_file), entry_point_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "rebuild_too_large"


def test_pe_rebuild_returns_the_iat_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("pe_rebuild_iat"))

    result = service.unpack_pe_rebuild(
        session_id,
        str(dump_file),
        entry_point_rva=0x1000,
        iat_va=_iat_va(worker),
        iat_size=0x20,
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_pe_rebuild_propagates_a_failed_imports_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def read(sid: str, iat_va: int, size: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=False, error=RpcError(code="read_failed", message="no read"))

    monkeypatch.setattr(service, "imports_read", read)

    result = service.unpack_pe_rebuild(
        session_id,
        str(dump_file),
        entry_point_rva=0x1000,
        iat_va=_iat_va(worker),
        iat_size=0x20,
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "read_failed"


def test_pe_rebuild_rejects_a_non_list_entries_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def read(sid: str, iat_va: int, size: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=True, data={"iat_va": iat_va, "size": size, "entries": "nope"})

    monkeypatch.setattr(service, "imports_read", read)

    result = service.unpack_pe_rebuild(
        session_id,
        str(dump_file),
        entry_point_rva=0x1000,
        iat_va=_iat_va(worker),
        iat_size=0x20,
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_iat"


def test_pe_rebuild_returns_the_write_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("pe_rebuild_write"))

    result = service.unpack_pe_rebuild(session_id, str(dump_file), entry_point_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_pe_rebuild_aborts_when_the_advance_stage_guard_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The advance guard only runs after an import rebuild, so an iat_va/iat_size
    # pair is required to reach it. A trip here retains the artifact but refuses
    # to advance the phase.
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("pe_rebuild_advance"))

    result = service.unpack_pe_rebuild(
        session_id,
        str(dump_file),
        entry_point_rva=0x1000,
        iat_va=_iat_va(worker),
        iat_size=0x20,
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"
    assert result.data is not None
    assert result.data["aborted_before_phase_advance"] is True
    assert result.data["partial_artifacts_retained"] is True
    assert result.data["safe_rollback"] is False
