from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.agent import personas as personas_module
from headless_re_mcp.agent.personas import (
    DEFAULT_PERSONA_ID,
    SEAGULL_PERSONA_ID,
    PersonaStore,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app


def test_persona_store_seeds_default_and_optional_seagull(tmp_path: Path) -> None:
    seed = tmp_path / "haiou.md"
    seed.write_text("# seagull\nbe blunt\n", encoding="utf-8")
    store = PersonaStore(tmp_path / "personas", seed_paths=(seed,))
    listed = store.list_public()
    ids = {item["id"] for item in listed["personas"]}
    assert DEFAULT_PERSONA_ID in ids
    assert SEAGULL_PERSONA_ID in ids
    assert listed["current"] == SEAGULL_PERSONA_ID
    assert "be blunt" in store.current_prompt()
    store.select(DEFAULT_PERSONA_ID)
    assert store.current_id() == DEFAULT_PERSONA_ID
    imported = store.import_markdown(title="lab notes", body="# lab\nkeep hashes")
    assert imported["current"].startswith("lab-notes-")
    store.delete(imported["current"])
    assert store.current_id() in {DEFAULT_PERSONA_ID, SEAGULL_PERSONA_ID}


def test_oversized_optional_seed_is_not_copied_into_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(personas_module, "_MAX_IMPORT_BYTES", 64)
    seed = tmp_path / "oversized.md"
    seed.write_bytes(b"x" * 1024)

    store = PersonaStore(tmp_path / "personas", seed_paths=(seed,))

    assert store.current_id() == DEFAULT_PERSONA_ID
    assert not (store.root / f"{SEAGULL_PERSONA_ID}.md").exists()
    assert {item["id"] for item in store.list_public()["personas"]} == {
        DEFAULT_PERSONA_ID
    }


def test_persona_ids_cannot_escape_store_or_select_unindexed_files(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    outside = tmp_path / "outside.md"
    outside.write_text("outside prompt must stay private", encoding="utf-8")
    orphan = root / "orphan.md"
    orphan.write_text("unindexed prompt", encoding="utf-8")

    for persona_id in ("../outside", "orphan"):
        with pytest.raises(KeyError):
            store.select(persona_id)
        with pytest.raises(KeyError):
            store.delete(persona_id)
        assert "outside prompt" not in store.prompt_for(persona_id)
        assert "unindexed prompt" not in store.prompt_for(persona_id)

    assert outside.is_file()
    assert orphan.is_file()
    assert store.current_id() == DEFAULT_PERSONA_ID


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (b"x" * (256 * 1024 + 1), "persona_too_large"),
        (b"\xff", "persona_path_unreadable"),
    ],
    ids=("too-large", "invalid-utf8"),
)
def test_persona_path_import_rejects_invalid_content(
    tmp_path: Path,
    content: bytes,
    error: str,
) -> None:
    source = tmp_path / "persona.md"
    source.write_bytes(content)
    store = PersonaStore(tmp_path / "personas", seed_paths=())

    with pytest.raises(ValueError, match=error):
        store.import_path(source)


def test_persona_index_and_prompt_reads_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    monkeypatch.setattr(personas_module, "_MAX_PERSONA_INDEX_BYTES", 64)
    (root / "index.json").write_bytes(b"{" + b" " * 128 + b"}")
    assert store.list_public()["personas"] == []

    # Restore a valid catalog, then make its selected body much larger than the
    # prompt window. The loader must stop reading before it truncates text.
    store = PersonaStore(root, seed_paths=())
    monkeypatch.setattr(personas_module, "_PROMPT_MAX_CHARS", 8)
    (root / "default.md").write_bytes(b"x" * 1024)
    assert store.prompt_for(DEFAULT_PERSONA_ID) == "xxxxxxxx\n\n[persona truncated]"


def test_a_broken_current_selection_discloses_the_effective_fallback(
    tmp_path: Path,
) -> None:
    """Deleting the active persona's body must not leave the listing lying.

    current_id() already falls back to the default persona when the recorded
    selection's body file is gone, so runs quietly used the default prompt --
    while list_public still named the broken persona as current with bytes 0,
    indistinguishable from an empty one. The listing now carries
    current_effective (only when it differs) and marks the entry missing.
    """
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    imported = store.import_markdown(title="lab notes", body="# lab\nkeep hashes")
    custom_id = str(imported["current"])

    (store.root / f"{custom_id}.md").unlink()

    listed = store.list_public()
    assert listed["current"] == custom_id
    assert listed["current_effective"] == DEFAULT_PERSONA_ID
    assert store.current_id() == DEFAULT_PERSONA_ID
    broken = next(item for item in listed["personas"] if item["id"] == custom_id)
    assert broken["missing"] is True
    assert broken["bytes"] == 0


def test_an_intact_store_lists_no_missing_or_effective_fields(tmp_path: Path) -> None:
    """An empty-but-present body is not "missing", and current needs no caveat."""
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    (store.root / f"{DEFAULT_PERSONA_ID}.md").write_text("", encoding="utf-8")

    listed = store.list_public()

    assert "current_effective" not in listed
    default = next(item for item in listed["personas"] if item["id"] == DEFAULT_PERSONA_ID)
    assert default["bytes"] == 0
    assert "missing" not in default


def test_personas_are_switchable_over_http(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    seed = tmp_path / "haiou.md"
    seed.write_text("haiou-seed-body", encoding="utf-8")
    monkeypatch.setattr(
        "headless_re_mcp.agent.personas.SEAGULL_SEED_PATHS",
        (seed,),
    )
    app = create_app(AnalysisService(settings), token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    with TestClient(app) as client:
        listed = client.get("/api/agent/personas", headers=headers)
        assert listed.status_code == 200
        body = listed.json()
        assert body["ok"] is True
        switched = client.post(
            "/api/agent/personas/select",
            headers=headers,
            json={"id": DEFAULT_PERSONA_ID},
        )
        assert switched.status_code == 200
        assert switched.json()["current"] == DEFAULT_PERSONA_ID
        imported = client.post(
            "/api/agent/personas/import",
            headers=headers,
            json={"title": "custom", "content": "# custom\nno wall of tools"},
        )
        assert imported.status_code == 200
        assert imported.json()["current"].startswith("custom-")
