"""Degradation and validation branches of the local persona store.

The happy path -- seed, list, select, import, delete over the store and HTTP --
is pinned in ``test_agent_personas.py``. This file covers what the store does
when its own on-disk state is corrupt or hostile: an unparseable index, a body
file that vanishes or cannot be read, an ``items`` map that is not a map, a
persona id that tries to escape the directory, and every rejection path in the
two import surfaces. Each branch is a place where a broken console-data
directory could otherwise crash the Agent tab or silently serve the wrong
prompt to an unattended run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from headless_re_mcp.agent import personas as personas_module
from headless_re_mcp.agent.personas import (
    DEFAULT_PERSONA_ID,
    SEAGULL_PERSONA_ID,
    PersonaStore,
)


def _store(tmp_path: Path) -> PersonaStore:
    return PersonaStore(tmp_path / "personas", seed_paths=())


def _write_index(root: Path, data: object) -> None:
    (root / "index.json").write_text(json.dumps(data), encoding="utf-8")


# --------------------------------------------------------------------------
# _read_index / _body_path
# --------------------------------------------------------------------------


def test_an_unparseable_index_reads_as_the_empty_default(tmp_path: Path) -> None:
    """A corrupt index.json must not crash the tab; it reads as no personas.

    The file is operator-adjacent console data that a crash or a half-write can
    leave as junk. list_public then answers the default catalog rather than
    raising into the web handler.
    """
    store = _store(tmp_path)
    (store.root / "index.json").write_text("this is not json{", encoding="utf-8")
    assert store.list_public()["personas"] == []
    assert store.current_id() == DEFAULT_PERSONA_ID


def test_a_persona_id_that_escapes_the_directory_is_refused(tmp_path: Path) -> None:
    """The id becomes a filename, so anything but the safe charset is rejected."""
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="persona_id_invalid"):
        store._body_path("../etc/passwd")


# --------------------------------------------------------------------------
# _seed degradation
# --------------------------------------------------------------------------


def test_seed_survives_a_default_body_it_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A present-but-unreadable default.md must not stop the store from opening.

    The migration step reads default.md to rewrite an old approval sentence; if
    that read fails (a permission flip, a torn file), seeding treats the body as
    empty and carries on rather than raising out of the constructor.
    """
    _store(tmp_path)  # first init writes default.md
    real = personas_module._read_bounded_text

    def flaky(path: Path, max_bytes: int) -> tuple[str, bool]:
        if path.suffix == ".md":
            raise OSError("unreadable")
        return real(path, max_bytes)

    monkeypatch.setattr(personas_module, "_read_bounded_text", flaky)
    reopened = PersonaStore(tmp_path / "personas", seed_paths=())
    assert reopened.current_id() == DEFAULT_PERSONA_ID


def test_seed_migrates_an_old_approval_sentence_in_the_default_body(
    tmp_path: Path,
) -> None:
    """A default body carrying the old, stricter approval line is rewritten.

    The autonomy policy loosened -- packing probes and debugger launch now run
    unattended -- and a default persona still telling the model to stop for
    approval would fight that policy. Seeding rewrites the one sentence in place.
    """
    root = tmp_path / "personas"
    root.mkdir(parents=True)
    stale = f"intro\n{personas_module._OLD_APPROVAL_SENTENCE}\noutro\n"
    (root / "default.md").write_text(stale, encoding="utf-8")

    PersonaStore(root, seed_paths=())

    rewritten = (root / "default.md").read_text(encoding="utf-8")
    assert personas_module._OLD_APPROVAL_SENTENCE not in rewritten
    assert "patches.apply" in rewritten


def test_seed_repairs_an_items_map_that_is_not_a_map(tmp_path: Path) -> None:
    """An index whose items is a string is reset to a dict, not indexed into."""
    root = tmp_path / "personas"
    root.mkdir(parents=True)
    _write_index(root, {"current": DEFAULT_PERSONA_ID, "items": "corrupt"})

    store = PersonaStore(root, seed_paths=())

    ids = {item["id"] for item in store.list_public()["personas"]}
    assert DEFAULT_PERSONA_ID in ids


def test_seed_skips_an_optional_seed_it_cannot_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A seed path that exists but errors on open is skipped, not fatal."""
    seed = tmp_path / "haiou.md"
    seed.write_text("be blunt", encoding="utf-8")
    real_open = Path.open

    def flaky_open(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if self == seed:
            raise OSError("locked")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", flaky_open)
    store = PersonaStore(tmp_path / "personas", seed_paths=(seed,))

    assert not (store.root / f"{SEAGULL_PERSONA_ID}.md").exists()
    assert store.current_id() == DEFAULT_PERSONA_ID


def test_seed_skips_a_missing_seed_and_takes_the_next_that_exists(tmp_path: Path) -> None:
    """The seed list is tried in order; a path that is not there is passed over."""
    missing = tmp_path / "not-there.md"
    present = tmp_path / "haiou.md"
    present.write_text("be blunt", encoding="utf-8")

    store = PersonaStore(tmp_path / "personas", seed_paths=(missing, present))

    assert (store.root / f"{SEAGULL_PERSONA_ID}.md").is_file()
    assert "be blunt" in store.current_prompt()


def test_seed_reindexes_a_seagull_body_missing_from_the_index(tmp_path: Path) -> None:
    """A seagull body on disk but absent from items is re-added on next open.

    A third open, with the entry restored, exercises the already-indexed path
    where seeding leaves the existing row untouched.
    """
    seed = tmp_path / "haiou.md"
    seed.write_text("be blunt", encoding="utf-8")
    root = tmp_path / "personas"
    PersonaStore(root, seed_paths=(seed,))
    assert (root / f"{SEAGULL_PERSONA_ID}.md").is_file()

    data = json.loads((root / "index.json").read_text(encoding="utf-8"))
    data["items"].pop(SEAGULL_PERSONA_ID, None)
    _write_index(root, data)

    reopened = PersonaStore(root, seed_paths=(seed,))
    ids = {item["id"] for item in reopened.list_public()["personas"]}
    assert SEAGULL_PERSONA_ID in ids

    again = PersonaStore(root, seed_paths=(seed,))
    assert SEAGULL_PERSONA_ID in {item["id"] for item in again.list_public()["personas"]}


def test_seed_treats_an_invalid_current_pointer_as_absent(tmp_path: Path) -> None:
    """An index pointing current at an id-shaped-wrong value falls back safely."""
    root = tmp_path / "personas"
    root.mkdir(parents=True)
    _write_index(root, {"current": "in/valid", "items": {}})

    store = PersonaStore(root, seed_paths=())

    assert store.current_id() == DEFAULT_PERSONA_ID


# --------------------------------------------------------------------------
# list_public row filtering
# --------------------------------------------------------------------------


def test_list_public_skips_non_dict_and_unsafe_rows(tmp_path: Path) -> None:
    """A corrupt items map can hold junk rows; each is skipped, not rendered.

    A meta value that is not an object, and a key that is not a safe persona id,
    are both signs of a hand-edited or torn index. Listing drops them so the tab
    shows only rows it could actually load.
    """
    store = _store(tmp_path)
    data = json.loads((store.root / "index.json").read_text(encoding="utf-8"))
    data["items"]["not-a-dict"] = "oops"
    data["items"]["../escape"] = {"id": "../escape", "title": "x"}
    _write_index(store.root, data)

    listed = store.list_public()
    ids = {item["id"] for item in listed["personas"]}
    assert "not-a-dict" not in ids
    assert "../escape" not in ids
    assert DEFAULT_PERSONA_ID in ids


# --------------------------------------------------------------------------
# prompt_for degradation
# --------------------------------------------------------------------------


def test_prompt_for_falls_back_to_the_default_body_on_a_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the selected body cannot be read, the model still gets a real prompt."""
    store = _store(tmp_path)

    def unreadable(path: Path, max_bytes: int) -> tuple[str, bool]:
        raise OSError("gone")

    monkeypatch.setattr(personas_module, "_read_bounded_text", unreadable)
    prompt = store.prompt_for(DEFAULT_PERSONA_ID)
    assert prompt == personas_module.DEFAULT_PERSONA_BODY.strip()


# --------------------------------------------------------------------------
# import_markdown validation
# --------------------------------------------------------------------------


def test_import_markdown_refuses_empty_and_oversized_bodies(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="persona_empty"):
        store.import_markdown(title="t", body="   \n  ")
    with pytest.raises(ValueError, match="persona_too_large"):
        store.import_markdown(title="t", body="x" * (personas_module._MAX_IMPORT_BYTES + 1))


def test_import_markdown_prefixes_an_id_that_would_shadow_a_builtin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slug colliding with a builtin id is namespaced so it cannot overwrite it.

    The slug is title-plus-digest, so a real collision is rare -- but if it
    happened, an import would clobber the default or seagull body. The id is
    prefixed ``custom-`` instead, keeping the builtin intact.
    """
    monkeypatch.setattr(personas_module, "_slug", lambda title, body: DEFAULT_PERSONA_ID)
    store = _store(tmp_path)

    imported = store.import_markdown(title="whatever", body="# body\ntext")

    assert imported["current"] == f"custom-{DEFAULT_PERSONA_ID}"
    assert (store.root / f"{DEFAULT_PERSONA_ID}.md").read_text(encoding="utf-8") != "# body\ntext\n"


def test_import_markdown_repairs_a_corrupt_items_map(tmp_path: Path) -> None:
    """An import into a store whose items went non-dict resets the map first."""
    store = _store(tmp_path)
    _write_index(store.root, {"current": DEFAULT_PERSONA_ID, "items": ["not", "a", "map"]})

    imported = store.import_markdown(title="lab", body="# lab\nkeep hashes")

    assert imported["current"].startswith("lab-")
    ids = {item["id"] for item in imported["personas"]}
    assert imported["current"] in ids


# --------------------------------------------------------------------------
# import_path validation and success
# --------------------------------------------------------------------------


def test_import_path_reports_an_unresolvable_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)

    def boom(self: Path) -> Path:
        raise OSError("loop")

    monkeypatch.setattr(Path, "resolve", boom)
    with pytest.raises(ValueError, match="persona_path_unreadable"):
        store.import_path(tmp_path / "whatever.md")


def test_import_path_refuses_a_non_markdown_suffix(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="persona_not_markdown"):
        store.import_path(tmp_path / "notes.bin")


def test_import_path_reports_a_missing_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="persona_path_missing"):
        store.import_path(tmp_path / "gone.md")


def test_import_path_reports_a_body_it_cannot_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "persona.md"
    source.write_text("# ok\nbody", encoding="utf-8")
    store = _store(tmp_path)
    real_open = Path.open

    def flaky_open(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if self.name == "persona.md":
            raise OSError("locked")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", flaky_open)
    with pytest.raises(ValueError, match="persona_path_unreadable"):
        store.import_path(source)


def test_import_path_imports_a_valid_markdown_file(tmp_path: Path) -> None:
    """The success path records the source and makes the import current."""
    source = tmp_path / "field-notes.md"
    source.write_text("# field notes\nkeep the hashes", encoding="utf-8")
    store = _store(tmp_path)

    imported = store.import_path(source)

    assert imported["current"].startswith("field-notes-")
    current = imported["current"]
    row = next(item for item in imported["personas"] if item["id"] == current)
    assert row["source"] == str(source.resolve())
    assert "keep the hashes" in store.prompt_for(current)


# --------------------------------------------------------------------------
# delete validation and current reassignment
# --------------------------------------------------------------------------


def test_delete_refuses_the_builtin_personas(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="persona_builtin"):
        store.delete(DEFAULT_PERSONA_ID)


def test_delete_refuses_a_custom_id_flagged_builtin_in_the_index(tmp_path: Path) -> None:
    """A row marked builtin is protected even if its id is not a reserved one."""
    store = _store(tmp_path)
    (store.root / "pinned.md").write_text("# pinned\n", encoding="utf-8")
    data = json.loads((store.root / "index.json").read_text(encoding="utf-8"))
    data["items"]["pinned"] = {"id": "pinned", "title": "pinned", "builtin": True}
    _write_index(store.root, data)

    with pytest.raises(ValueError, match="persona_builtin"):
        store.delete("pinned")


def test_deleting_a_non_current_persona_leaves_the_selection_alone(tmp_path: Path) -> None:
    """Removing a persona that is not selected must not move current.

    Import two personas; the second becomes current. Deleting the first is a
    library edit, not a selection change, so current stays on the second.
    """
    store = _store(tmp_path)
    first = store.import_markdown(title="alpha", body="# alpha\none")["current"]
    second = store.import_markdown(title="beta", body="# beta\ntwo")["current"]
    assert store.current_id() == second

    remaining = store.delete(first)

    assert remaining["current"] == second
    ids = {item["id"] for item in remaining["personas"]}
    assert first not in ids
    assert second in ids
