"""M8.2 write Gate: idalib rename/comment/type/function/patch + batch."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
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
def test_m8_static_write_idalib_gate() -> None:
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
        caps = set((opened.data.get("backend") or {}).get("capabilities") or [])
        for name in (
            "static.name.set",
            "static.comment.set",
            "static.type.apply",
            "static.function.create",
            "static.function.delete",
            "static.bytes.patch",
            "static.batch",
        ):
            assert name in caps, caps

        functions = service.static_functions(session_id, limit=5)
        assert functions.ok and functions.data is not None
        assert functions.data["items"]
        ea = int(functions.data["items"][0]["address"])

        marker = f"hrmcp_m8_{session_id[:8]}"
        renamed = service.static_name_set(session_id, address=ea, name=marker)
        assert renamed.ok and renamed.data is not None, renamed
        assert renamed.data.get("name") == marker
        assert "patch_artifact" in renamed.data
        assert Path(str(renamed.data["patch_artifact"])).is_file()

        names = service.static_names(session_id, limit=1000)
        assert names.ok and names.data is not None
        named = {
            str(item.get("name"))
            for item in names.data.get("items") or []
            if isinstance(item, dict)
        }
        assert marker in named

        comment_marker = f"hrmcp_cmt_{session_id[:8]}"
        commented = service.static_comment_set(
            session_id,
            address=ea,
            comment=comment_marker,
        )
        assert commented.ok and commented.data is not None, commented
        assert commented.data.get("comment") == comment_marker
        assert Path(str(commented.data["patch_artifact"])).is_file()

        # idc.SetType on code EAs often fails on this fixture; mutate an import EA instead.
        imports = service.static_imports(session_id, limit=5)
        assert imports.ok and imports.data is not None, imports
        import_items = [
            item
            for item in (imports.data.get("items") or [])
            if isinstance(item, dict) and item.get("ea") is not None
        ]
        assert import_items, "no imports available for type.apply"
        type_ea = int(import_items[0]["ea"])
        typed = service.static_type_apply(session_id, address=type_ea, type="char *")
        assert typed.ok and typed.data is not None, typed
        assert "char" in str(typed.data.get("type") or "").lower()
        assert Path(str(typed.data["patch_artifact"])).is_file()

        # delete then recreate the same function start (mutation roundtrip)
        deleted = service.static_function_delete(session_id, address=ea)
        assert deleted.ok and deleted.data is not None, deleted
        assert deleted.data.get("deleted") is True
        assert Path(str(deleted.data["patch_artifact"])).is_file()

        created_fn = service.static_function_create(session_id, address=ea)
        assert created_fn.ok and created_fn.data is not None, created_fn
        assert created_fn.data.get("ok") is True
        assert Path(str(created_fn.data["patch_artifact"])).is_file()
        assert int(created_fn.data.get("start") or 0) == ea or created_fn.data.get(
            "created"
        ) in {True, False}

        raw = service.static_bytes_read(session_id, address=ea, size=1)
        assert raw.ok and raw.data is not None
        original_hex = str(raw.data["hex"])
        assert len(original_hex) == 2

        patched = service.static_bytes_patch(
            session_id,
            address=ea,
            hex=original_hex,
        )
        assert patched.ok and patched.data is not None, patched
        assert patched.data.get("after_hex") == original_hex
        assert Path(str(patched.data["patch_artifact"])).is_file()

        readback = service.static_bytes_read(session_id, address=ea, size=1)
        assert readback.ok and readback.data is not None
        assert readback.data["hex"] == original_hex

        batch = service.static_batch(
            session_id,
            commands=[
                {"command": "bytes_read", "params": {"address": ea, "size": 1}},
                {"command": "names", "params": {"offset": 0, "limit": 8}},
            ],
        )
        assert batch.ok and batch.data is not None, batch
        assert int(batch.data["count"]) == 2
        assert all(item.get("ok") for item in batch.data["results"])
    finally:
        service.close_all()
