"""build_deps_snapshot backs /api/deps and the onboarding inventory.

It is the machine-readable form of the licensing line the README repeats: the
x64dbg headless trees may ship in the package, IDA never may. That policy lives
here as per-entry ``packable``/``never_bundle`` flags with no test pinning them,
and each entry also hardcodes a settings attribute and a HEADLESS_RE_* env var
that must stay wired to config.py. A rename or a flipped flag would either break
the console's inventory or, worse, quietly reclassify IDA as packable.
"""

from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import headless_re_mcp.config as config_module
from headless_re_mcp.config import Settings
from headless_re_mcp.web.deps import build_deps_snapshot


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return replace(base, **overrides)


def test_ida_is_never_bundled_and_x64dbg_is_packable(tmp_path: Path) -> None:
    snapshot = build_deps_snapshot(_settings(tmp_path))
    by_id = {item["id"]: item for item in snapshot["items"]}

    ida = by_id["ida_home"]
    assert ida["packable"] is False
    assert ida["never_bundle"] is True
    assert ida["required_for_core"] is True

    for dbg in ("x64dbg_headless_x64", "x64dbg_headless_x86"):
        assert by_id[dbg]["packable"] is True
        assert by_id[dbg]["never_bundle"] is False
        assert by_id[dbg]["required_for_core"] is True

    # The policy block and top-level flags must agree with the per-item flags.
    assert snapshot["claims_universal_unpack"] is False
    assert "IDA" in snapshot["policy"]["never_bundle"]
    assert {item["id"] for item in snapshot["never_bundle"]} == {"ida_home"}


def test_presence_tracks_files_and_directories_and_none(tmp_path: Path) -> None:
    present_file = tmp_path / "headless_x64" / "headless.exe"
    present_file.parent.mkdir(parents=True)
    present_file.write_text("stub", encoding="utf-8")
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()

    snapshot = build_deps_snapshot(
        _settings(tmp_path, x64dbg_headless_x64=present_file, ida_home=ida_dir)
    )
    by_id = {item["id"]: item for item in snapshot["items"]}

    assert by_id["x64dbg_headless_x64"]["present"] is True  # a real file
    assert by_id["ida_home"]["present"] is True  # a real directory
    assert by_id["x64dbg_headless_x86"]["present"] is False  # None path
    assert by_id["x64dbg_headless_x86"]["path"] is None

    # x86 headless is required and absent, so it lands in missing_core; the two
    # present required ones do not.
    missing_core_ids = {item["id"] for item in snapshot["missing_core"]}
    assert "x64dbg_headless_x86" in missing_core_ids
    assert "x64dbg_headless_x64" not in missing_core_ids
    assert "ida_home" not in missing_core_ids


def test_a_file_dependency_pointed_at_a_directory_is_not_present(tmp_path: Path) -> None:
    """A runnable binary that is really a directory must not read as present.

    x64dbg headless is required-for-core and its setting names ``headless.exe``,
    a file. If an operator mis-sets ``HEADLESS_RE_X64DBG_HEADLESS_X64`` to the
    containing folder, the snapshot used to fall back from ``is_file()`` to
    ``exists()`` and report the tool present, quietly dropping it out of
    ``missing_core`` even though nothing there can be launched. It now stays
    absent and in missing_core so onboarding tells the truth.
    """
    folder = tmp_path / "x64dbg-x64"
    folder.mkdir()

    snapshot = build_deps_snapshot(_settings(tmp_path, x64dbg_headless_x64=folder))
    by_id = {item["id"]: item for item in snapshot["items"]}

    assert by_id["x64dbg_headless_x64"]["kind"] == "file"
    assert by_id["x64dbg_headless_x64"]["present"] is False
    assert by_id["x64dbg_headless_x64"]["path"] == str(folder)
    assert "x64dbg_headless_x64" in {item["id"] for item in snapshot["missing_core"]}


def test_a_directory_root_pointed_at_a_file_is_not_present(tmp_path: Path) -> None:
    """The mirror case: an IDA home that is a file is not a usable install."""
    stray = tmp_path / "ida-not-a-dir"
    stray.write_text("stub", encoding="utf-8")

    snapshot = build_deps_snapshot(_settings(tmp_path, ida_home=stray))
    by_id = {item["id"]: item for item in snapshot["items"]}

    assert by_id["ida_home"]["kind"] == "dir"
    assert by_id["ida_home"]["present"] is False
    assert "ida_home" in {item["id"] for item in snapshot["missing_core"]}


def test_counts_are_internally_consistent(tmp_path: Path) -> None:
    snapshot = build_deps_snapshot(_settings(tmp_path))
    items = snapshot["items"]
    counts = snapshot["counts"]

    assert counts["total"] == len(items)
    assert counts["present"] == sum(1 for item in items if item["present"])
    assert counts["packable"] == sum(1 for item in items if item["packable"])
    assert counts["optional"] == sum(1 for item in items if not item["required_for_core"])
    assert counts["missing_core"] == len(snapshot["missing_core"])


def test_every_entry_stays_wired_to_settings_and_the_env_loader(tmp_path: Path) -> None:
    """id -> Settings attribute and env -> a var config.py actually reads."""
    snapshot = build_deps_snapshot(_settings(tmp_path))
    fields = set(Settings.__dataclass_fields__)
    loader_source = inspect.getsource(config_module)

    for item in snapshot["items"]:
        assert item["id"] in fields, f"deps entry names a non-existent setting: {item['id']}"
        env = item["env"]
        assert env.startswith("HEADLESS_RE_"), env
        assert f'"{env}"' in loader_source, (
            f"deps entry promises {env} but config.py never reads it"
        )
