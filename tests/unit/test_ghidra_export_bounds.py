"""Ghidra export pages that hit the cap used to look complete."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.ghidra.client import GhidraClient


class TestGhidraExportsSayWhenTheyStopped:
    """A function page that hit the cap looks exactly like one that ended.

    Measured: limit 256, count=256, no has_more -- so a caller that only
    looks at the page thinks Ghidra found exactly that many functions.
    """

    def _client(self, tmp_path: Path, available: int) -> tuple[GhidraClient, Path, Path]:
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
            asked = int(extra[6])
            n = min(available, asked)
            payload: dict[str, Any] = {
                "mode": extra[4],
                "items": [{"name": f"f{index}", "entry": hex(index)} for index in range(n)],
                "count": n,
            }
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(payload), encoding="utf-8")
            return ("", "", 0)

        client._run_headless = fake_run  # type: ignore[method-assign]
        return client, binary, project

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        client, binary, project = self._client(tmp_path, available=400)
        result = client.functions(binary, project, limit=256)
        assert result["count"] == 256
        assert result["has_more"] is True
        assert len(result["items"]) == 256

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        client, binary, project = self._client(tmp_path, available=3)
        result = client.functions(binary, project, limit=256)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        client, binary, project = self._client(tmp_path, available=256)
        result = client.functions(binary, project, limit=256)
        assert result["count"] == 256
        assert result["has_more"] is False
