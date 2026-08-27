"""Branch and error paths across unpack.iat.scan / validate / rebuild.

The happy IAT flows (a full scan->validate->rebuild against the fake worker)
are covered elsewhere; those tests never trip the stage guards, the dump-path
validation, the non-list payload guards, the code-not-decrypted gate downgrade,
or the memory-refusal and remap-fallback branches inside ``unpack_iat_rebuild``.
These drive each of those through the real service.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]


def _blocked(stage: str) -> Result[JsonObject]:
    return Result(
        ok=False,
        error=RpcError(code="unpack_active", message=f"blocked at {stage}"),
        meta={"unpack": {"stage": stage}},
    )


def _stage_blocker(target: str):  # type: ignore[no-untyped-def]
    def guard(session_id: str, *, stage: str) -> Result[JsonObject] | None:
        return _blocked(stage) if stage == target else None

    return guard


def _iat_va(worker: object) -> int:
    return int(worker.module_base) + 0x2000  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# unpack_iat_scan
# --------------------------------------------------------------------------- #
def test_iat_scan_returns_the_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("iat_scan"))

    result = service.unpack_iat_scan(session_id, worker.module_base)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_iat_scan_tolerates_a_non_list_candidate_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)

    def scan(sid: str, base: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=True, data={"module_base": base, "module_size": 0x4000, "candidates": "x"})

    monkeypatch.setattr(service, "imports_scan", scan)

    result = service.unpack_iat_scan(session_id, worker.module_base)

    assert result.ok and result.data is not None
    assert result.data["raw_candidates"] == []
    assert result.data["candidate_count"] == 0
    assert result.data["confirmed"] is False


# --------------------------------------------------------------------------- #
# unpack_iat_validate
# --------------------------------------------------------------------------- #
def test_iat_validate_returns_the_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("iat_validate"))

    result = service.unpack_iat_validate(session_id, iat_va=_iat_va(worker), size=0x20)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_iat_validate_tolerates_a_non_list_entries_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)

    def read(sid: str, iat_va: int, size: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=True, data={"iat_va": iat_va, "size": size, "entries": "nope"})

    monkeypatch.setattr(service, "imports_read", read)

    result = service.unpack_iat_validate(session_id, iat_va=_iat_va(worker), size=0x20)

    assert result.ok and result.data is not None
    assert result.data["slot_count"] == 0


def test_iat_validate_rejects_a_dump_path_outside_the_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    outsider = tmp_path / "loose.bin"
    outsider.write_bytes(b"\x00" * 64)

    result = service.unpack_iat_validate(
        session_id, iat_va=_iat_va(worker), size=0x20, dump_path=str(outsider)
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "artifact root" in result.error.message


def test_iat_validate_rejects_a_missing_dump_path_inside_the_root(
    tmp_path: Path,
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    missing = (
        service.settings.artifact_root.expanduser().resolve() / "unpack" / session_id / "x.bin"
    )

    result = service.unpack_iat_validate(
        session_id, iat_va=_iat_va(worker), size=0x20, dump_path=str(missing)
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "does not exist" in result.error.message


def test_iat_validate_downgrades_the_gate_when_code_is_not_decrypted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A dense-looking IAT over an encrypted CODE section (near-zero nonzero
    # ratio) must be refused and the recoverability downgraded, even when the
    # raw gate would otherwise allow the rebuild.
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def coupling(path: object, **kwargs: object) -> JsonObject:
        return {
            "ok": True,
            "still_vm_stub_count": 1,
            "api_call_site_count": 3,
            "code_nonzero_ratio": 0.01,
        }

    def gate(analysis: object, **kwargs: object) -> JsonObject:
        return {"rebuild_allowed": True, "recoverability": "iat_recoverable", "reasons": []}

    monkeypatch.setattr(service_unpack, "analyze_dump_stub_coupling", coupling)
    monkeypatch.setattr(service_unpack, "gate_iat_rebuild", gate)

    result = service.unpack_iat_validate(
        session_id, iat_va=_iat_va(worker), size=0x20, dump_path=str(dump_file)
    )

    assert result.ok and result.data is not None
    rebuild_gate = result.data["rebuild_gate"]
    assert isinstance(rebuild_gate, dict)
    assert rebuild_gate["rebuild_allowed"] is False
    assert rebuild_gate["recoverability"] == "iat_insufficient"
    assert any("code_not_decrypted" in str(r) for r in rebuild_gate["reasons"])
    assert result.data["confirmed"] is False


# --------------------------------------------------------------------------- #
# unpack_iat_rebuild
# --------------------------------------------------------------------------- #
def test_iat_rebuild_returns_the_first_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("iat_rebuild"))

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_iat_rebuild_rejects_a_dump_path_outside_the_artifact_root(
    tmp_path: Path,
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    outsider = tmp_path / "loose.bin"
    outsider.write_bytes(b"MZ" + b"\x00" * 64)

    result = service.unpack_iat_rebuild(
        session_id, str(outsider), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "artifact root" in result.error.message


def test_iat_rebuild_propagates_a_failed_imports_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def read(sid: str, iat_va: int, size: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=False, error=RpcError(code="read_failed", message="no read"))

    monkeypatch.setattr(service, "imports_read", read)

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "read_failed"


def test_iat_rebuild_returns_the_write_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("iat_rebuild_write"))

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_iat_rebuild_rejects_a_non_list_entries_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def read(sid: str, iat_va: int, size: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=True, data={"iat_va": iat_va, "size": size, "entries": "nope"})

    monkeypatch.setattr(service, "imports_read", read)

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_iat"


def test_iat_rebuild_blocks_when_code_is_not_decrypted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def coupling(path: object, **kwargs: object) -> JsonObject:
        return {"ok": True, "still_vm_stub_count": 1, "code_nonzero_ratio": 0.01}

    def gate(analysis: object, **kwargs: object) -> JsonObject:
        return {"rebuild_allowed": True, "recoverability": "iat_recoverable", "reasons": []}

    monkeypatch.setattr(service_unpack, "analyze_dump_stub_coupling", coupling)
    monkeypatch.setattr(service_unpack, "gate_iat_rebuild", gate)

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "iat_rebuild_blocked"
    details = result.error.details or {}
    rebuild_gate = details.get("rebuild_gate")
    assert isinstance(rebuild_gate, dict)
    assert rebuild_gate["recoverability"] == "iat_insufficient"


def test_iat_rebuild_returns_the_memory_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    refusal: Result[JsonObject] = Result(
        ok=False,
        error=RpcError(code="rebuild_too_large", message="would not fit"),
    )

    def read_dump(path: Path) -> tuple[bytes | None, Result[JsonObject] | None]:
        return None, refusal

    monkeypatch.setattr(service_unpack, "_read_dump_for_rebuild", read_dump)

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "rebuild_too_large"


def test_iat_rebuild_falls_back_to_raw_bytes_when_remap_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the dump cannot be remapped to a file layout the rebuild keeps the
    # raw bytes (no remap_report) instead of aborting. Here the raw memory
    # image is not a valid file-layout PE, so the built-in self-check rejects
    # the result -- but only after the raw-fallback branch has executed.
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def boom(raw: bytes, **kwargs: object) -> object:
        raise PeRebuildError("cannot remap")

    monkeypatch.setattr(service_unpack, "remap_dump_to_file", boom)

    result = service.unpack_iat_rebuild(
        session_id,
        str(dump_file),
        iat_va=_iat_va(worker),
        size=0x20,
        oep_rva=0x1000,
    )

    assert not result.ok and result.error is not None
    assert result.data is not None
    assert "remap_report" not in result.data


def test_iat_rebuild_raises_on_a_negative_iat_rva(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def read(sid: str, iat_va: int, size: int, **kwargs: object) -> Result[JsonObject]:
        entries = [
            {
                "thunk_va": 0x1000 + i * 8,
                "value": 0x7FF00000 + i,
                "kind": "api",
                "module": "kernel32.dll",
                "name": f"Fn{i}",
                "ordinal": 0,
            }
            for i in range(8)
        ]
        return Result(ok=True, data={"iat_va": iat_va, "size": size, "entries": entries})

    def coupling(path: object, **kwargs: object) -> JsonObject:
        return {"ok": True, "still_vm_stub_count": 0, "code_nonzero_ratio": 0.9}

    def gate(analysis: object, **kwargs: object) -> JsonObject:
        return {"rebuild_allowed": True, "recoverability": "iat_recoverable", "reasons": []}

    def identity_remap(raw: bytes, **kwargs: object) -> tuple[bytes, None]:
        return raw, None

    monkeypatch.setattr(service, "imports_read", read)
    monkeypatch.setattr(service_unpack, "analyze_dump_stub_coupling", coupling)
    monkeypatch.setattr(service_unpack, "gate_iat_rebuild", gate)
    monkeypatch.setattr(service_unpack, "remap_dump_to_file", identity_remap)

    result = service.unpack_iat_rebuild(session_id, str(dump_file), iat_va=-0x10, size=0x20)

    assert not result.ok and result.error is not None


def test_iat_rebuild_returns_the_advance_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("iat_rebuild_advance"))

    result = service.unpack_iat_rebuild(
        session_id,
        str(dump_file),
        iat_va=_iat_va(worker),
        size=0x20,
        oep_rva=0x1000,
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"
