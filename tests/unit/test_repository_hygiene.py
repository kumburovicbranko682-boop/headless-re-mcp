from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_root_and_script_entries_are_deliberately_small() -> None:
    """Pin the entry points so the root and scripts/ cannot silently accumulate.

    Exact sets rather than a size bound: the point is that adding a new public
    entry point is a decision someone has to make on purpose.
    """
    root_python = {path.name for path in ROOT.glob("*.py")}
    assert root_python == {"setup.py", "start_web.py", "openai_bridge.py"}
    release_scripts = {path.name for path in (ROOT / "scripts").iterdir() if path.is_file()}
    assert release_scripts == {
        "release.ps1",
        "sync_upstream.ps1",
        "pack_upx.ps1",
        "build_deps_bundle.ps1",
        "build_handoff_zip.ps1",
        "build_msi.ps1",
        "build_native_portable.ps1",
        "build_portable.ps1",
        "install_die_portable.ps1",
        "install_service.ps1",
        "sync_external_x64dbg.ps1",
        "verify_msi.ps1",
    }


def test_no_root_python_entry_still_references_the_retired_bootstrap() -> None:
    """first_setup.py was replaced by setup.py; nothing may still call it."""
    searched = [*ROOT.glob("*.py"), *(ROOT / "scripts").glob("*.ps1"), ROOT / "README.md"]
    offenders = [
        path.name
        for path in searched
        if path.is_file() and "first_setup" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_git_does_not_track_generated_or_temporary_files() -> None:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    tracked = [Path(item) for item in completed.stdout.decode().split("\0") if item]
    banned_parts = {
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tmp",
        "tmp",
        "temp",
        "build",
        "dist",
    }
    banned_suffixes = {
        ".pyc",
        ".pyo",
        ".log",
        ".tmp",
        ".bak",
        ".dmp",
        ".idb",
        ".i64",
        ".msi",
        ".whl",
        ".wixobj",
    }
    offenders = [
        str(path)
        for path in tracked
        if banned_parts.intersection(path.parts) or path.suffix.lower() in banned_suffixes
    ]
    assert offenders == []


def test_gitignore_covers_local_build_and_test_residue() -> None:
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for required in (
        "node_modules/",
        "__pycache__/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".tmp-*/",
        "*.tmp",
        "*.part",
        "artifacts/*",
    ):
        assert required in ignored
