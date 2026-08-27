"""The apk service artifact-dir guards must fail closed on the id itself.

``_jadx_out_dir`` and ``_repack_dir`` turn a session id into a path under the
artifact root. The old ``not session_id or Path(session_id).name != session_id``
check let ``..`` through -- ``Path("..").name == ".."`` -- so ``_jadx_out_dir("..")``
resolved to ``artifact_root/jadx/..`` i.e. the artifact root itself, and jadx
would have written outside its own subtree. Callers gate a bogus id at
registry.get first, but the guard must not lean on that. These pin that dot
segments, separators and empties are refused at the guard, and that an
ordinary single-component id still lands under its category subtree.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    root = tmp_path / "artifacts"
    svc = AnalysisService(replace(Settings.load(), artifact_root=root))
    yield svc
    svc.close_all()


@pytest.mark.parametrize("hostile", ["..", ".", "a/b", "x/../y", "", "jadx/../.."])
def test_jadx_out_dir_rejects_traversal_ids(service: AnalysisService, hostile: str) -> None:
    with pytest.raises(ApkError) as caught:
        service._jadx_out_dir(hostile)
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("hostile", ["..", ".", "a/b", "x/../y", "", "apktool/../.."])
def test_repack_dir_rejects_traversal_ids(
    service: AnalysisService, tmp_path: Path, hostile: str
) -> None:
    with pytest.raises(ApkError) as caught:
        service._repack_dir(hostile)
    assert caught.value.code == "invalid_params"
    # A rejected id never got as far as mkdir on the artifact root.
    root = tmp_path / "artifacts"
    assert sorted(p.name for p in root.iterdir()) == ["meta"]


def test_valid_single_segment_ids_stay_under_their_category_subtree(
    service: AnalysisService, tmp_path: Path
) -> None:
    root = (tmp_path / "artifacts").resolve()
    jadx = service._jadx_out_dir("deadbeef")
    assert jadx == root / "jadx" / "deadbeef"

    repack = service._repack_dir("deadbeef")
    assert repack == root / "apktool" / "deadbeef"
    # _repack_dir creates its tree; it must land under apktool/, not the root.
    assert repack.is_dir()
    assert repack.parent == root / "apktool"
