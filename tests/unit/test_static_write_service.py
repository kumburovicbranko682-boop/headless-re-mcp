"""Unit coverage for M8.2 static write surface (FakeStaticWorker)."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import FakeStaticWorker, _create, _write_minimal_pe


class _WriteCapableStaticWorker(FakeStaticWorker):
    def __init__(self) -> None:
        super().__init__()
        self.names: dict[int, str] = {}
        self.comments: dict[int, str] = {}
        self.patched: dict[int, bytes] = {}

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
                "static.name.set",
                "static.comment.set",
                "static.type.apply",
                "static.function.create",
                "static.function.delete",
                "static.bytes.patch",
                "static.batch",
            }
        )

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        del timeout
        values = params or {}
        if command == "name_set":
            address = int(values["address"])
            previous = self.names.get(address, "")
            self.names[address] = str(values["name"])
            return {
                "address": address,
                "name": self.names[address],
                "previous_name": previous,
                "ok": True,
            }
        if command == "comment_set":
            address = int(values["address"])
            previous = self.comments.get(address, "")
            self.comments[address] = str(values["comment"])
            return {
                "address": address,
                "comment": self.comments[address],
                "previous_comment": previous,
                "repeatable": bool(values.get("repeatable", False)),
                "ok": True,
            }
        if command == "type_apply":
            return {
                "address": int(values["address"]),
                "type": str(values["type"]),
                "previous_type": "",
                "ok": True,
            }
        if command == "function_create":
            return {
                "address": int(values["address"]),
                "created": True,
                "start": int(values["address"]),
                "end": int(values["address"]) + 16,
                "ok": True,
            }
        if command == "function_delete":
            return {"address": int(values["address"]), "deleted": True, "ok": True}
        if command == "bytes_patch":
            address = int(values["address"])
            raw = bytes.fromhex(str(values["hex"]))
            before = self.patched.get(address, b"\x90" * len(raw))
            self.patched[address] = raw
            return {
                "address": address,
                "size": len(raw),
                "before_hex": before.hex(),
                "after_hex": raw.hex(),
                "ok": True,
            }
        if command == "batch":
            results = []
            for item in values.get("commands") or []:
                assert isinstance(item, dict)
                cmd = str(item.get("command"))
                item_params = item.get("params") if isinstance(item.get("params"), dict) else {}
                results.append({"command": cmd, "ok": True, "data": {"echo": item_params}})
            return {"results": results, "count": len(results)}
        return super().request(command, params)


def _write_service(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _WriteCapableStaticWorker()
    settings = Settings(
        ida_home=tmp_path / "fake-ida",
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "fake-ida").mkdir(parents=True, exist_ok=True)
    service = AnalysisService(
        settings,
        static_worker_factory=lambda session, cfg: worker,
    )
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok
    return service, session_id


def test_static_writes_emit_patch_artifact_and_timeline(tmp_path: Path) -> None:
    service, session_id = _write_service(tmp_path)

    renamed = service.static_name_set(session_id, address=0x140001000, name="hrmcp_unit")
    assert renamed.ok and renamed.data is not None
    artifact = Path(str(renamed.data["patch_artifact"]))
    assert artifact.is_file()
    assert "timeline_event" in renamed.data

    timeline = (
        service.settings.artifact_root.expanduser().resolve()
        / "sessions"
        / session_id
        / "timeline.jsonl"
    )
    assert timeline.is_file()
    assert "static.name.set" in timeline.read_text(encoding="utf-8")

    patched = service.static_bytes_patch(
        session_id,
        address=0x140001000,
        hex="90",
    )
    assert patched.ok and patched.data is not None
    assert patched.data["after_hex"] == "90"
    assert Path(str(patched.data["patch_artifact"])).is_file()


def test_static_batch_is_bounded(tmp_path: Path) -> None:
    service, session_id = _write_service(tmp_path)
    too_many = [{"command": "names", "params": {"offset": 0, "limit": 1}}] * 33
    rejected = service.static_batch(session_id, commands=too_many)
    assert not rejected.ok
    assert rejected.error is not None
    assert rejected.error.code == "invalid_argument"

    ok = service.static_batch(
        session_id,
        commands=[{"command": "names", "params": {"offset": 0, "limit": 1}}],
    )
    assert ok.ok and ok.data is not None
    assert int(ok.data["count"]) == 1

def test_static_disassemble_spills_oversized_artifact(tmp_path: Path) -> None:
    class _HugeDisasmWorker(_WriteCapableStaticWorker):
        @property
        def capabilities(self) -> frozenset[str]:
            return frozenset({"static.functions", "static.disassemble", "static.batch"})

        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            del params, timeout
            if command == "disassemble":
                # >64KiB rendered text triggers spill path
                line = "x" * 200
                instructions = [{"text": line, "address": 0x140001000 + i} for i in range(400)]
                return {
                    "address": 0x140001000,
                    "instructions": instructions,
                    "returned": len(instructions),
                    "count": len(instructions),
                }
            return super().request(command, params)

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _HugeDisasmWorker()
    settings = Settings(
        ida_home=tmp_path / "fake-ida",
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "fake-ida").mkdir(parents=True, exist_ok=True)
    service = AnalysisService(
        settings,
        static_worker_factory=lambda session, cfg: worker,
    )
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok

    result = service.static_disassemble(session_id, address=0x140001000, count=400)
    assert result.ok and result.data is not None
    assert result.data.get("truncated") is True
    artifact = Path(str(result.data["artifact"]))
    assert artifact.is_file()
    assert "oversized" in artifact.as_posix()
    assert int(result.data["artifact_bytes"]) > 64 * 1024
    assert len(str(result.data.get("text") or "")) <= 1024
