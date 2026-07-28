"""M8.1 Batch 1: idalib static read-only Gate (zero analyzer windows)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _gate_binary() -> Path:
    configured = os.environ.get("HEADLESS_RE_IDA_GATE_BINARY")
    if configured:
        path = Path(configured)
        if path.is_file():
            return path
        pytest.skip(f"HEADLESS_RE_IDA_GATE_BINARY missing: {path}")
    for candidate in (
        _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe",
        _PROJECT_ROOT / "artifacts" / "fixtures-x86" / "headless_fixture.exe",
    ):
        if candidate.is_file():
            return candidate
    pytest.skip("no IDA gate binary: set HEADLESS_RE_IDA_GATE_BINARY")


def _session_id(data: JsonObject | None) -> str:
    assert data is not None
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.headless
def test_m8_static_batch1_idalib_gate() -> None:
    settings = Settings.load()
    if settings.ida_home is None:
        pytest.skip("IDA home is not configured")
    binary = _gate_binary()
    service = AnalysisService(settings)
    created = service.create_session(str(binary))
    assert created.ok, created
    session_id = _session_id(created.data)
    try:
        opened = service.open_static(session_id)
        assert opened.ok, opened
        assert opened.data is not None
        backend = opened.data.get("backend")
        assert isinstance(backend, dict)
        caps = set(backend.get("capabilities") or [])
        for name in (
            "static.metadata",
            "static.segments",
            "static.imports",
            "static.exports",
            "static.entrypoints",
            "static.disassemble",
            "static.xrefs_to",
            "static.xrefs_from",
            "static.callers",
            "static.callees",
            "static.basic_blocks",
            "static.cfg",
            "static.globals",
            "static.names",
            "static.types",
            "static.structs",
            "static.enums",
            "static.bytes.read",
            "static.search.bytes",
            "static.search.text",
            "static.search.immediate",
        ):
            assert name in caps, caps

        meta = service.static_metadata(session_id)
        assert meta.ok and meta.data is not None
        assert int(meta.data["image_base"]) > 0
        assert "static.metadata" in meta.data["capabilities"]

        segments = service.static_segments(session_id, limit=20)
        assert segments.ok and segments.data is not None
        assert "total" in segments.data and "items" in segments.data

        imports = service.static_imports(session_id, limit=50)
        assert imports.ok and imports.data is not None
        assert "total" in imports.data

        exports = service.static_exports(session_id, limit=50)
        assert exports.ok and exports.data is not None

        entries = service.static_entrypoints(session_id, limit=20)
        assert entries.ok and entries.data is not None
        assert int(entries.data["total"]) >= 1

        functions = service.static_functions(session_id, limit=5)
        assert functions.ok and functions.data is not None
        assert functions.data["items"]
        first = int(functions.data["items"][0]["address"])

        disasm = service.static_disassemble(session_id, address=first, count=16)
        assert disasm.ok and disasm.data is not None
        assert isinstance(disasm.data.get("instructions"), list)

        x_to = service.static_xrefs_to(session_id, address=first, limit=20)
        assert x_to.ok and x_to.data is not None
        assert x_to.data.get("address") == first

        x_from = service.static_xrefs_from(session_id, address=first, limit=20)
        assert x_from.ok and x_from.data is not None

        callers = service.static_callers(session_id, address=first, limit=20)
        assert callers.ok and callers.data is not None

        callees = service.static_callees(session_id, address=first, limit=20)
        assert callees.ok and callees.data is not None

        blocks = service.static_basic_blocks(session_id, address=first, limit=50)
        assert blocks.ok and blocks.data is not None
        assert int(blocks.data["total"]) >= 1

        cfg = service.static_cfg(session_id, address=first)
        assert cfg.ok and cfg.data is not None
        assert int(cfg.data["node_count"]) >= 1

        names = service.static_names(session_id, limit=20)
        assert names.ok and names.data is not None
        assert "total" in names.data

        globals_page = service.static_globals(session_id, limit=20)
        assert globals_page.ok and globals_page.data is not None

        types_page = service.static_types(session_id, limit=20)
        assert types_page.ok and types_page.data is not None
        structs = service.static_structs(session_id, limit=20)
        assert structs.ok and structs.data is not None
        enums = service.static_enums(session_id, limit=20)
        assert enums.ok and enums.data is not None

        raw = service.static_bytes_read(session_id, address=first, size=16)
        assert raw.ok and raw.data is not None
        assert isinstance(raw.data.get("hex"), str) and raw.data["hex"]

        # Minimal search: single NOP/ret-ish byte often present; allow zero hits.
        searched = service.static_search_bytes(session_id, pattern="C3", limit=5)
        assert searched.ok and searched.data is not None
        text_hits = service.static_search_text(session_id, text="MZ", limit=5)
        assert text_hits.ok and text_hits.data is not None
        imm = service.static_search_immediate(session_id, value=0, limit=5)
        assert imm.ok and imm.data is not None

        runtime = service._runtimes.get((session_id, BackendKind.IDA))  # noqa: SLF001
        assert runtime is not None
        assert runtime.worker.analyzer_windows == ()
    finally:
        closed = service.close_session(session_id)
        assert closed.ok, closed
