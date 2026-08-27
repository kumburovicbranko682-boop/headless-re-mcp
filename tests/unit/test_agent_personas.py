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


def test_import_with_surrogates_in_title_and_body_stays_whole(tmp_path: Path) -> None:
    """The web route feeds import_markdown straight from a JSON request body.

    json.loads accepts a lone \\ud800 escape, so both fields can carry an
    unpaired surrogate. A body surrogate raised in the import's own size
    check; a title surrogate was worse -- it raised inside _write_index's
    write_text after the .md file was already on disk, leaving an orphaned
    persona the index never learned about and a codec error as the
    "validation" message.
    """
    store = PersonaStore(tmp_path / "personas", seed_paths=())

    listed = store.import_markdown(title="bad \ud800 title", body="keep \ud800 hashes")

    current = listed["current"]
    assert any(item["id"] == current for item in listed["personas"])
    prompt = store.prompt_for(current)
    assert "\ud800" not in prompt
    assert "keep" in prompt and "hashes" in prompt
    titles = {item["id"]: item["title"] for item in listed["personas"]}
    assert "\ud800" not in titles[current]
    on_disk = {path.stem for path in store.root.glob("*.md")}
    indexed = {item["id"] for item in listed["personas"]}
    assert on_disk <= indexed, "no orphaned persona files"


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

        # A lone \ud800 escape passes the server's json.loads as an unpaired
        # surrogate (sent pre-encoded because the client's own encoder rightly
        # refuses it). The import used to answer 400 with a codec error and,
        # for a title-only surrogate, leave an orphaned .md behind.
        import json as json_module

        hostile = client.post(
            "/api/agent/personas/import",
            headers={**headers, "Content-Type": "application/json"},
            content=json_module.dumps(
                {"title": "bad \ud800 title", "content": "body \ud800 text"}
            ),
        )
        assert hostile.status_code == 200
        assert all(
            "\ud800" not in item["title"] for item in hostile.json()["personas"]
        )
