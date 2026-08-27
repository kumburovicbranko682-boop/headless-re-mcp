"""Guard-path coverage for the local markdown PersonaStore.

Complements ``test_agent_personas.py`` (seeding, HTTP switching, bounded
reads) with the fail-closed edges: corrupt indexes, unreadable bodies,
rejected imports, and delete/seed invariants. All hermetic under ``tmp_path``;
OSError paths are injected via monkeypatch so they hold under any uid.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent import personas as personas_module
from headless_re_mcp.agent.personas import (
    DEFAULT_PERSONA_BODY,
    DEFAULT_PERSONA_ID,
    SEAGULL_PERSONA_ID,
    PersonaStore,
)


def _write_index(root: Path, data: dict[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.json").write_text(json.dumps(data), encoding="utf-8")


def _read_raiser(
    target_name: str,
) -> Callable[[Path, int], tuple[str, bool]]:
    real = personas_module._read_bounded_text

    def fake(path: Path, max_bytes: int) -> tuple[str, bool]:
        if Path(path).name == target_name:
            raise OSError("blocked")
        return real(path, max_bytes)

    return fake


def _open_raiser(target_name: str) -> Callable[..., Any]:
    real_open = Path.open

    def fake(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == target_name:
            raise OSError("blocked")
        return real_open(self, *args, **kwargs)

    return fake


def test_read_index_recovers_from_corrupt_json(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    (root / "index.json").write_text("{ this is not json", encoding="utf-8")
    assert store.list_public()["personas"] == []


def test_body_path_rejects_traversal_ids(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    with pytest.raises(ValueError, match="persona_id_invalid"):
        store._body_path("../evil")


def test_seed_tolerates_unreadable_default_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "personas"
    PersonaStore(root, seed_paths=())  # seed default.md + index once
    monkeypatch.setattr(personas_module, "_read_bounded_text", _read_raiser("default.md"))
    store = PersonaStore(root, seed_paths=())
    assert store.current_id() == DEFAULT_PERSONA_ID


def test_seed_rewrites_stale_approval_sentence(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    root.mkdir(parents=True)
    body = "opening line\n" + personas_module._OLD_APPROVAL_SENTENCE + "\nclosing\n"
    (root / "default.md").write_text(body, encoding="utf-8")

    PersonaStore(root, seed_paths=())

    rewritten = (root / "default.md").read_text(encoding="utf-8")
    assert personas_module._OLD_APPROVAL_SENTENCE not in rewritten
    assert personas_module._NEW_APPROVAL_SENTENCE in rewritten


def test_seed_resets_non_dict_items(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    _write_index(root, {"current": DEFAULT_PERSONA_ID, "items": "broken"})
    store = PersonaStore(root, seed_paths=())
    ids = {item["id"] for item in store.list_public()["personas"]}
    assert DEFAULT_PERSONA_ID in ids


def test_seed_skips_missing_seed_paths(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=(tmp_path / "nope.md",))
    assert not (root / f"{SEAGULL_PERSONA_ID}.md").exists()
    assert store.current_id() == DEFAULT_PERSONA_ID


def test_seed_skips_unreadable_seed_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed = tmp_path / "seed.md"
    seed.write_bytes(b"seagull body")
    monkeypatch.setattr(Path, "open", _open_raiser("seed.md"))
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=(seed,))
    assert not (root / f"{SEAGULL_PERSONA_ID}.md").exists()
    assert store.current_id() == DEFAULT_PERSONA_ID


def test_seed_indexes_preexisting_seagull_body(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    root.mkdir(parents=True)
    (root / f"{SEAGULL_PERSONA_ID}.md").write_text("existing seagull", encoding="utf-8")
    _write_index(
        root,
        {
            "current": DEFAULT_PERSONA_ID,
            "items": {
                DEFAULT_PERSONA_ID: {
                    "id": DEFAULT_PERSONA_ID,
                    "title": "d",
                    "builtin": True,
                }
            },
        },
    )
    store = PersonaStore(root, seed_paths=())
    ids = {item["id"] for item in store.list_public()["personas"]}
    assert SEAGULL_PERSONA_ID in ids


def test_seed_leaves_already_indexed_seagull_untouched(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    root.mkdir(parents=True)
    (root / f"{SEAGULL_PERSONA_ID}.md").write_text("existing", encoding="utf-8")
    _write_index(
        root,
        {
            "current": DEFAULT_PERSONA_ID,
            "items": {
                DEFAULT_PERSONA_ID: {
                    "id": DEFAULT_PERSONA_ID,
                    "title": "d",
                    "builtin": True,
                },
                SEAGULL_PERSONA_ID: {
                    "id": SEAGULL_PERSONA_ID,
                    "title": "s",
                    "builtin": True,
                },
            },
        },
    )
    store = PersonaStore(root, seed_paths=())
    ids = {item["id"] for item in store.list_public()["personas"]}
    assert {DEFAULT_PERSONA_ID, SEAGULL_PERSONA_ID} <= ids


def test_seed_resets_invalid_current_pointer(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    _write_index(root, {"current": "../evil", "items": {}})
    store = PersonaStore(root, seed_paths=())
    assert store.current_id() == DEFAULT_PERSONA_ID


def test_list_public_skips_malformed_and_invalid_entries(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    index["items"]["weird"] = "not-a-dict"
    index["items"]["../bad"] = {"id": "../bad", "title": "bad"}
    (root / "index.json").write_text(json.dumps(index), encoding="utf-8")

    ids = {item["id"] for item in store.list_public()["personas"]}
    assert "weird" not in ids
    assert "../bad" not in ids
    assert DEFAULT_PERSONA_ID in ids


def test_prompt_for_falls_back_to_default_body_on_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    monkeypatch.setattr(personas_module, "_read_bounded_text", _read_raiser("default.md"))
    assert store.prompt_for(DEFAULT_PERSONA_ID) == DEFAULT_PERSONA_BODY.strip()


def test_import_markdown_rejects_empty_body(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    with pytest.raises(ValueError, match="persona_empty"):
        store.import_markdown(title="blank", body="   \n\t  ")


def test_import_markdown_rejects_oversized_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    monkeypatch.setattr(personas_module, "_MAX_IMPORT_BYTES", 8)
    with pytest.raises(ValueError, match="persona_too_large"):
        store.import_markdown(title="big", body="x" * 128)


def test_import_markdown_resets_non_dict_items(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    _write_index(root, {"current": DEFAULT_PERSONA_ID, "items": "broken"})
    result = store.import_markdown(title="lab notes", body="# lab\nkeep hashes")
    assert result["current"].startswith("lab-notes-")


def test_import_path_wraps_resolve_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())

    def boom(self: Path, *args: Any, **kwargs: Any) -> Path:
        raise OSError("unresolvable")

    monkeypatch.setattr(Path, "resolve", boom)
    with pytest.raises(ValueError, match="persona_path_unreadable"):
        store.import_path(tmp_path / "whatever.md")


def test_import_path_rejects_non_markdown_suffix(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    source = tmp_path / "payload.bin"
    source.write_text("not markdown", encoding="utf-8")
    with pytest.raises(ValueError, match="persona_not_markdown"):
        store.import_path(source)


def test_import_path_rejects_missing_file(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    with pytest.raises(ValueError, match="persona_path_missing"):
        store.import_path(tmp_path / "ghost.md")


def test_import_path_wraps_open_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    source = tmp_path / "blocked.md"
    source.write_text("readable to stat, not to open", encoding="utf-8")
    monkeypatch.setattr(Path, "open", _open_raiser("blocked.md"))
    with pytest.raises(ValueError, match="persona_path_unreadable"):
        store.import_path(source)


def test_import_path_imports_valid_markdown(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    source = tmp_path / "field-notes.md"
    source.write_text("# field\nkeep it terse", encoding="utf-8")
    result = store.import_path(source)
    assert result["current"].startswith("field-notes-")


def test_delete_refuses_builtin_ids(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    with pytest.raises(ValueError, match="persona_builtin"):
        store.delete(DEFAULT_PERSONA_ID)


def test_delete_refuses_custom_builtin_flagged_entry(tmp_path: Path) -> None:
    root = tmp_path / "personas"
    store = PersonaStore(root, seed_paths=())
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    index["items"]["vendorpack"] = {
        "id": "vendorpack",
        "title": "vendor",
        "builtin": True,
    }
    (root / "index.json").write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ValueError, match="persona_builtin"):
        store.delete("vendorpack")


def test_delete_keeps_current_when_removing_other(tmp_path: Path) -> None:
    store = PersonaStore(tmp_path / "personas", seed_paths=())
    first = store.import_markdown(title="one", body="# one\nalpha")["current"]
    second = store.import_markdown(title="two", body="# two\nbeta")["current"]
    listed = store.delete(first)
    assert listed["current"] == second
    assert first not in {item["id"] for item in listed["personas"]}
