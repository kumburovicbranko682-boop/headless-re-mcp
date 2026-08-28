"""The artifact-ownership guard is what stops a tool reading an arbitrary path.

unpack.*, apk.* and dotnet.* take a caller-supplied on-disk ``path`` and only
act on it when ``_session_owns_artifact_path`` says the session owns it. The
guard is fail-closed by construction -- a session id that is not a single path
component owns nothing, and containment is decided after ``resolve()`` so a
symlink cannot smuggle a path out of the tree. None of that was pinned, and it
is exactly the property a path-traversal fix must not silently lose.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.core.service import (
    _session_artifact_roots,
    _session_owns_artifact_path,
)


def test_a_path_under_the_sessions_own_tree_is_owned(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    sid = "deadbeef" * 4
    owned = root / "unpack" / sid
    owned.mkdir(parents=True)
    artifact = owned / "dumped.exe"
    artifact.write_bytes(b"MZ")

    assert _session_owns_artifact_path(root, sid, artifact) is True
    # The owned directory itself counts, not only files strictly beneath it.
    assert _session_owns_artifact_path(root, sid, owned) is True
    # Every advertised category root is genuinely owned.
    for owned_root in _session_artifact_roots(root, sid):
        assert _session_owns_artifact_path(root, sid, owned_root / "x") is True


def test_the_apk_manifest_spill_dir_is_session_owned(tmp_path: Path) -> None:
    """apk.manifest spills an oversized manifest under artifact_root/apk/<id>.

    That subtree must be advertised as session-owned like web/ and jadx/ are,
    or the ownership model would treat a legitimate capture dir as foreign the
    moment some guard starts consulting it.
    """
    root = tmp_path / "artifacts"
    sid = "cafebabe" * 4
    spill = root / "apk" / sid / "manifest-abc.xml"
    assert (root / "apk" / sid) in _session_artifact_roots(root, sid)
    assert _session_owns_artifact_path(root, sid, spill) is True


def test_another_sessions_tree_is_not_owned(tmp_path: Path) -> None:
    """A session must not reach into a sibling session's artifacts."""
    root = tmp_path / "artifacts"
    mine, theirs = "a" * 32, "b" * 32
    victim = root / "unpack" / theirs
    victim.mkdir(parents=True)
    (victim / "secret.bin").write_bytes(b"x")

    assert _session_owns_artifact_path(root, mine, victim / "secret.bin") is False


def test_a_path_outside_the_artifact_root_is_not_owned(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    (root / "unpack").mkdir(parents=True)
    outside = tmp_path / "elsewhere" / "passwd"
    outside.parent.mkdir(parents=True)
    outside.write_text("root:x:0:0", encoding="utf-8")

    assert _session_owns_artifact_path(root, "c" * 32, outside) is False
    # A category dir with no session segment is not owned either.
    assert _session_owns_artifact_path(root, "c" * 32, root / "unpack" / "loose.exe") is False


@pytest.mark.parametrize("hostile", ["../../elsewhere", "..", ".", "a/b", "/etc", ""])
def test_a_non_single_component_session_id_owns_nothing(tmp_path: Path, hostile: str) -> None:
    """Fail closed: a traversing, dot or empty id yields no owned roots at all."""
    root = tmp_path / "artifacts"
    root.mkdir()
    assert _session_artifact_roots(root, hostile) == ()
    # Even pointed at what would be a real in-root path, ownership is refused.
    assert _session_owns_artifact_path(root, hostile, root / "unpack" / "x") is False


def test_a_dotdot_session_id_cannot_claim_another_sessions_artifacts(tmp_path: Path) -> None:
    """Regression: ``..`` slipped past the single-component guard.

    ``Path("..").name == ".."`` passed ``Path(sid).name == sid``, so every owned
    root ``<cat>/..`` collapsed to the artifact root and a caller passing
    ``session_id=".."`` was judged to own every session's tree. Plant a victim
    artifact and require that a ``..`` caller does not own it.
    """
    root = tmp_path / "artifacts"
    victim = root / "unpack" / ("v" * 32)
    victim.mkdir(parents=True)
    stolen = victim / "secret.bin"
    stolen.write_bytes(b"secret")

    assert _session_owns_artifact_path(root, "..", stolen) is False
    assert _session_owns_artifact_path(root, "..", root / "detection" / "x.json") is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlink_cannot_smuggle_a_path_out_of_the_owned_tree(tmp_path: Path) -> None:
    """Containment is decided after resolve(), so a symlink out is not owned.

    A file whose *path* sits under the session tree but whose real location is
    elsewhere (via a symlinked directory) must be refused: the tools would
    otherwise read or overwrite an arbitrary target through a link planted in
    their own workspace.
    """
    root = tmp_path / "artifacts"
    sid = "d" * 32
    owned = root / "unpack" / sid
    owned.mkdir(parents=True)
    secret_dir = tmp_path / "outside"
    secret_dir.mkdir()
    (secret_dir / "passwd").write_text("root:x:0:0", encoding="utf-8")

    (owned / "escape").symlink_to(secret_dir, target_is_directory=True)
    smuggled = owned / "escape" / "passwd"

    assert smuggled.resolve() == (secret_dir / "passwd").resolve()
    assert _session_owns_artifact_path(root, sid, smuggled) is False
