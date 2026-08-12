from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_root_and_script_entries_are_deliberately_small() -> None:
    root_python = {path.name for path in ROOT.glob("*.py")}
    assert root_python == {"setup.py", "start_web.py"}
    release_scripts = {path.name for path in (ROOT / "scripts").iterdir() if path.is_file()}
    assert release_scripts == {"release.ps1", "sync_upstream.ps1", "pack_upx.ps1"}


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
        "webui/node_modules/",
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
