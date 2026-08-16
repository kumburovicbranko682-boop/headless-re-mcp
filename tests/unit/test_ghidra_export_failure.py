"""A failed Ghidra export used to look like an empty successful page."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError


class TestGhidraExportDoesNotCallFailureSuccess:
    """Exit 1 plus an empty JSON page used to look like "nothing found".

    Measured: returncode=1, payload {"items":[],"count":0}, functions()
    returned count=0 -- so a caller treats a failed export as Ghidra
    finding no functions.
    """

    def _client(
        self,
        tmp_path: Path,
        *,
        payload: dict[str, Any],
        code: int,
    ) -> tuple[GhidraClient, Path, Path]:
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"MZ")
        project = tmp_path / "proj"
        client = GhidraClient()
        client.analyze = Path("/bin/true")
        client.java = Path("/bin/true")

        def fake_run(
            project_dir: Path,
            *,
            binary: Path,
            extra: list[str],
            timeout: float,
            max_heap: str,
            delete_project: bool,
        ) -> tuple[str, str, int]:
            del project_dir, binary, timeout, max_heap, delete_project
            out_path = Path(extra[5])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(payload), encoding="utf-8")
            return ("", "AnalyzeHeadless failed", code)

        client._run_headless = fake_run  # type: ignore[method-assign]
        return client, binary, project

    def test_a_failed_empty_page_is_not_success(self, tmp_path: Path) -> None:
        client, binary, project = self._client(
            tmp_path,
            payload={"mode": "functions", "items": [], "count": 0},
            code=1,
        )
        with pytest.raises(GhidraError) as info:
            client.functions(binary, project, limit=256)
        assert info.value.code == "backend_error"

    def test_a_warning_with_items_is_still_usable(self, tmp_path: Path) -> None:
        client, binary, project = self._client(
            tmp_path,
            payload={
                "mode": "functions",
                "items": [{"name": "f0", "entry": "0x1"}],
                "count": 1,
            },
            code=1,
        )
        result = client.functions(binary, project, limit=256)
        assert result["count"] == 1
        assert result["items"][0]["name"] == "f0"

    def test_a_clean_empty_binary_is_complete(self, tmp_path: Path) -> None:
        client, binary, project = self._client(
            tmp_path,
            payload={"mode": "functions", "items": [], "count": 0},
            code=0,
        )
        result = client.functions(binary, project, limit=256)
        assert result["count"] == 0
        assert result["has_more"] is False
