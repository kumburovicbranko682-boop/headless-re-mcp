"""The ghidra service project-dir guard must fail closed on the id itself.

``_ghidra_project_dir`` turns a session id into the project path that
analyzeHeadless imports the binary into, deletes with ``-deleteProject``, and
drops ``export_<mode>.json`` beside. The single-component check alone lets
``..`` through -- ``Path("..").name == ".."`` -- so ``_ghidra_project_dir("..")``
resolved to ``artifact_root/ghidra/..`` i.e. the artifact root itself, and the
project plus its exports would land outside the ghidra subtree. Callers gate a
bogus id at registry.get first, but the guard must not lean on that ordering.
These pin that dot segments, separators and empties are refused, that the guard
matches the web/proxy/apk lines, and that an ordinary single-component id still
lands under ghidra/.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    root = tmp_path / "artifacts"
    svc = AnalysisService(replace(Settings.load(), artifact_root=root))
    yield svc
    svc.close_all()


@pytest.mark.parametrize("hostile", ["..", ".", "a/b", "x/../y", "", "ghidra/../.."])
def test_ghidra_project_dir_rejects_traversal_ids(
    service: AnalysisService, hostile: str
) -> None:
    with pytest.raises(GhidraError) as caught:
        service._ghidra_project_dir(hostile)
    assert caught.value.code == "invalid_params"


def test_ghidra_project_dir_keeps_a_valid_id_under_its_subtree(
    service: AnalysisService, tmp_path: Path
) -> None:
    root = (tmp_path / "artifacts").resolve()
    project = service._ghidra_project_dir("deadbeef")
    assert project == root / "ghidra" / "deadbeef"
    # The guard names the path but does not create it; escaping it is what matters.
    assert project.parent == root / "ghidra"
