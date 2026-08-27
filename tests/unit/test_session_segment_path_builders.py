"""Session-id path builders must reject a segment that is not one ordinary name.

Each of these turns ``session_id`` into a component under the artifact root.
``Path(x).name != x`` alone admitted ``..`` (and ``.``), so a ``..`` id resolved
each ``<cat>/<id>`` write to the category root rather than a per-session dir.
The guard now matches _is_safe_session_segment / session_timeline_path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_trace import TraceMixin
from headless_re_mcp.core.service_unpack import UnpackMixin

_NON_SEGMENTS = ["..", ".", "a/b", "../escape", "", "   /.."]


class _Settings:
    def __init__(self, root: Path) -> None:
        self.artifact_root = root


def _stub(cls: type, root: Path) -> object:
    obj = cls.__new__(cls)
    obj.settings = _Settings(root)  # type: ignore[attr-defined]
    return obj


@pytest.mark.parametrize("bad", _NON_SEGMENTS)
def test_unpack_session_dir_refuses_non_segment(tmp_path: Path, bad: str) -> None:
    svc = _stub(UnpackMixin, tmp_path)
    with pytest.raises(ValueError, match="invalid session id"):
        svc._unpack_session_dir(bad)  # type: ignore[attr-defined]


def test_unpack_session_dir_accepts_a_uuid(tmp_path: Path) -> None:
    svc = _stub(UnpackMixin, tmp_path)
    out = svc._unpack_session_dir("0f1e2d3c")  # type: ignore[attr-defined]
    assert (tmp_path.resolve() / "unpack") in out.parents


@pytest.mark.parametrize("bad", _NON_SEGMENTS)
def test_trace_artifact_path_refuses_non_segment(tmp_path: Path, bad: str) -> None:
    svc = _stub(TraceMixin, tmp_path)
    with pytest.raises(ValueError, match="invalid session id"):
        svc._new_trace_artifact_path(bad)  # type: ignore[attr-defined]


@pytest.mark.parametrize("bad", _NON_SEGMENTS)
def test_session_work_dir_refuses_non_segment(tmp_path: Path, bad: str) -> None:
    svc = _stub(AnalysisService, tmp_path)
    assert svc._session_work_dir("dump", bad) is None  # type: ignore[attr-defined]


def test_session_work_dir_accepts_a_uuid(tmp_path: Path) -> None:
    svc = _stub(AnalysisService, tmp_path)
    out = svc._session_work_dir("dump", "0f1e2d3c")  # type: ignore[attr-defined]
    assert out is not None
    assert (tmp_path.resolve() / "dump") in out.parents
