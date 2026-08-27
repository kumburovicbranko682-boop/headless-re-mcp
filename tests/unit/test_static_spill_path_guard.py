"""A tampered session id must not steer a static artifact write outside the root.

``session_id`` is a server-minted uuid in normal use, but it is also restored
verbatim through ``SessionRegistry.adopt`` from the on-disk store, and every
other artifact-writing service (web/ui/proxy/apk and ``_write_die_artifact``)
refuses a segment that is not one ordinary path name before joining it. The two
static spill paths -- the oversized decompile/disassemble text and the patch
record -- were the outliers that joined it unchecked, so an id of ``..`` would
resolve above the artifact root. These pin the guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.core.service_static as service_static
from headless_re_mcp.core.limits import MAX_STATIC_INLINE_TEXT
from headless_re_mcp.core.service_static import StaticAnalysisMixin


class _Settings:
    def __init__(self, root: Path) -> None:
        self.artifact_root = root


class _Svc(StaticAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = _Settings(root)  # type: ignore[assignment]


def _oversized_text() -> str:
    return "A" * (MAX_STATIC_INLINE_TEXT + 64)


def test_patch_dir_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    svc = _Svc(tmp_path / "artifacts")
    for bad in ("..", "../evil", "a/b", "."):
        with pytest.raises(OSError, match="invalid session id"):
            svc._static_patch_dir(bad)
    # A traversal segment must not have created anything above the root.
    assert not (tmp_path / "evil").exists()
    assert not (tmp_path / "patches").exists()


def test_patch_dir_accepts_a_normal_session_id(tmp_path: Path) -> None:
    svc = _Svc(tmp_path / "artifacts")
    directory = svc._static_patch_dir("0f1e2d3c")
    root = (tmp_path / "artifacts").resolve()
    assert directory.is_dir()
    assert root in directory.resolve().parents


def test_spill_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    svc = _Svc(tmp_path / "artifacts")
    out = svc._maybe_spill_static_text(
        "../../escape",
        {"code": _oversized_text()},
        kind="decompile",
        text_key="code",
    )
    assert out["spill_failed"] == "invalid session id for artifact path"
    # The oversized text was refused a home, so nothing was written and no
    # artifact was minted for a path outside the tree.
    assert "artifact" not in out
    assert "artifact_id" not in out
    assert not (tmp_path / "escape").exists()
    assert not list((tmp_path).glob("**/decompile-*.txt"))


def test_spill_accepts_a_normal_session_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    minted: list[Path] = []

    def _fake_record_artifact(_service: object, *, path: Path, **_: object) -> dict[str, str]:
        minted.append(path)
        return {"id": "artifact-1"}

    monkeypatch.setattr(service_static, "_record_artifact", _fake_record_artifact)
    svc = _Svc(tmp_path / "artifacts")
    out = svc._maybe_spill_static_text(
        "0f1e2d3c",
        {"code": _oversized_text()},
        kind="decompile",
        text_key="code",
    )
    assert out.get("spill_failed") != "invalid session id for artifact path"
    assert out["artifact_id"] == "artifact-1"
    written = Path(out["artifact"])
    root = (tmp_path / "artifacts").resolve()
    assert written.is_file()
    assert root in written.resolve().parents
    assert minted == [written]
