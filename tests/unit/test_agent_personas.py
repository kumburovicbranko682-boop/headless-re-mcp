from __future__ import annotations

import json
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


def test_a_corrupt_index_degrades_to_the_default_persona(tmp_path: Path) -> None:
    """A malformed index.json must not brick the workbench; it degrades to the
    default and repairs itself on the next construction.

    ``_read_index`` catches JSONDecodeError and returns the default catalog, so a
    half-written or hand-edited index leaves the console answering with the
    built-in default rather than raising out of every persona read. A sibling
    test already covers the *oversized* index (the truncation branch); this
    covers the *malformed* branch, which is the more likely real corruption -- a
    write interrupted by a crash or a full disk. Reconstructing over the corrupt
    file re-seeds a valid index, so the corruption is transient, not sticky.
    """
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    (root / "index.json").write_text("{not valid json", encoding="utf-8")

    # No read raises; the catalog reads empty (the index is unusable) but the
    # default prompt is still served straight from default.md.
    assert store.list_public()["personas"] == []
    assert store.current_id() == DEFAULT_PERSONA_ID
    assert "分析助手" in store.current_prompt()

    # Constructing a fresh store over the corrupt index repairs it: the default
    # is back in the catalog and the file parses as JSON again.
    healed = PersonaStore(root, seed_paths=())
    assert DEFAULT_PERSONA_ID in {item["id"] for item in healed.list_public()["personas"]}
    json.loads((root / "index.json").read_text(encoding="utf-8"))


def test_builtin_personas_cannot_be_deleted(tmp_path: Path) -> None:
    """default and seagull are the workbench's floor and must not be removable.

    Both delete guards (the id check and the meta ``builtin`` flag) exist so a
    caller cannot leave the console with no default to fall back to. Deleting
    either must raise ``persona_builtin`` and leave both present and selectable.
    """
    seed = tmp_path / "haiou.md"
    seed.write_text("seagull body", encoding="utf-8")
    store = PersonaStore(tmp_path / "personas", seed_paths=(seed,))

    for builtin in (DEFAULT_PERSONA_ID, SEAGULL_PERSONA_ID):
        with pytest.raises(ValueError, match="persona_builtin"):
            store.delete(builtin)

    ids = {item["id"] for item in store.list_public()["personas"]}
    assert {DEFAULT_PERSONA_ID, SEAGULL_PERSONA_ID} <= ids


def test_import_path_rejects_non_markdown_suffix_and_missing_file(tmp_path: Path) -> None:
    """import_path validates the target before reading it.

    A non-.md/.txt suffix is refused as ``persona_not_markdown`` and a path that
    does not exist as ``persona_path_missing`` -- both before any bytes are read,
    so a wrong drag-and-drop fails cleanly instead of surfacing as a decode or
    IO error. Sibling tests cover the too-large and invalid-utf8 content refusals.
    """
    store = PersonaStore(tmp_path / "personas", seed_paths=())

    wrong_suffix = tmp_path / "note.pdf"
    wrong_suffix.write_bytes(b"not markdown")
    with pytest.raises(ValueError, match="persona_not_markdown"):
        store.import_path(wrong_suffix)

    with pytest.raises(ValueError, match="persona_path_missing"):
        store.import_path(tmp_path / "does-not-exist.md")


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
