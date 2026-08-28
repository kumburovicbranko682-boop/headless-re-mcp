"""``_session_work_dir`` selects the directory ``_forget_session_work_dirs`` feeds
to ``shutil.rmtree`` on session close, so its traversal guard is security-critical.

The happy path (a closed session's jadx/apktool trees are reclaimed) is covered by
the apk close-session tests. What is *not* pinned is the fail-closed half: a hostile
``session_id`` must never resolve the work dir onto a shared parent and let close-time
cleanup delete a sibling session's output -- or the artifact root itself. The guard
today is a pair -- ``Path(session_id).name != session_id`` *and* a ``relative_to``
containment check -- and the pair matters: ``Path("..").name == ".."`` slips the name
check, and only the ``relative_to`` backstop then refuses it (``<root>/<kind>/..``
collapses to ``<root>``, which is not under ``<root>/<kind>``). A refactor that
"simplified" the guard down to the name check alone would silently reopen a
delete-outside-the-tree hole, so this pins the property directly.
"""

from __future__ import annotations

import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core.service import AnalysisService


# The two methods under test touch only self.settings.artifact_root (and, for
# _forget, self._session_work_dir), so a namespace stub stands in for the fully
# wired service and keeps the test fast; the type: ignore covers that stand-in.
def _work_dir(root: Path, kind: str, session_id: str) -> Path | None:
    stub = SimpleNamespace(settings=SimpleNamespace(artifact_root=root))
    return AnalysisService._session_work_dir(stub, kind, session_id)  # type: ignore[arg-type]


def _forget(root: Path, session_id: str) -> None:
    stub = SimpleNamespace(settings=SimpleNamespace(artifact_root=root))
    stub._session_work_dir = types.MethodType(AnalysisService._session_work_dir, stub)
    AnalysisService._forget_session_work_dirs(stub, session_id)  # type: ignore[arg-type]


def test_work_dir_resolves_a_valid_single_component_id(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    got = _work_dir(root, "jadx", "a" * 32)
    assert got == root.expanduser().resolve() / "jadx" / ("a" * 32)


@pytest.mark.parametrize("hostile", ["..", ".", "a/b", "../../etc", "/etc", ""])
def test_work_dir_refuses_a_non_single_component_id(tmp_path: Path, hostile: str) -> None:
    """Fail closed: anything but one ordinary path component selects no directory,
    so close-time rmtree can never escape ``<root>/<kind>/``."""
    assert _work_dir(tmp_path / "artifacts", "jadx", hostile) is None


def test_forget_with_a_dotdot_id_deletes_nothing_outside_a_session_tree(tmp_path: Path) -> None:
    """``..`` is the case that slips the name check. It must not collapse the work
    dir onto the shared parent and wipe sibling sessions or the category roots."""
    root = tmp_path / "artifacts"
    victim = root / "jadx" / ("v" * 32)
    victim.mkdir(parents=True)
    (victim / "Main.java").write_text("class Main {}", encoding="utf-8")
    (root / "apktool").mkdir(parents=True)

    _forget(root, "..")

    assert victim.is_dir()
    assert (victim / "Main.java").is_file()
    assert (root / "jadx").is_dir()
    assert (root / "apktool").is_dir()


def test_forget_reclaims_only_the_named_sessions_trees(tmp_path: Path) -> None:
    """Contrast that makes the refusal meaningful: a valid id *does* delete its own
    jadx/apktool trees, and leaves a sibling session's alone."""
    root = tmp_path / "artifacts"
    mine, other = "m" * 32, "o" * 32
    for sid in (mine, other):
        tree = root / "jadx" / sid
        tree.mkdir(parents=True)
        (tree / "X.java").write_text("x", encoding="utf-8")
        (root / "apktool" / sid).mkdir(parents=True)

    _forget(root, mine)

    assert not (root / "jadx" / mine).exists()
    assert not (root / "apktool" / mine).exists()
    assert (root / "jadx" / other).is_dir()
    assert (root / "apktool" / other).is_dir()
