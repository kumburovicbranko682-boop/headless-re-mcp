"""ghidra.decompile used to cut the C text without saying so."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.ghidra.client import GhidraClient


class TestGhidraDecompileSaysWhenItStopped:
    """A decompilation that hit 200000 chars used to look complete.

    Measured: 250000-char C, decompiled length 200000, no truncated -- so a
    caller that only looks at decompiled thinks the function ended there.
    """

    def _client(self, tmp_path: Path, decompiled: str) -> tuple[GhidraClient, Path, Path]:
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
            payload: dict[str, Any] = {
                "mode": extra[4],
                "items": [],
                "count": 0,
                "function": "f",
                "entry": "0x1000",
                "decompiled": decompiled,
            }
            out_path.write_text(json.dumps(payload), encoding="utf-8")
            return ("", "", 0)

        client._run_headless = fake_run  # type: ignore[method-assign]
        return client, binary, project

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        # What ExportJson.py currently writes for anything longer than 200000.
        client, binary, project = self._client(tmp_path, "C" * 200_000)
        result = client.decompile(binary, project, "0x1000")
        assert len(result["decompiled"]) == 200_000
        assert result["truncated"] is True
        assert result["returned_chars"] == 200_000

    def test_a_short_function_is_complete(self, tmp_path: Path) -> None:
        client, binary, project = self._client(tmp_path, "int f() { return 0; }")
        result = client.decompile(binary, project, "0x1000")
        assert result["decompiled"] == "int f() { return 0; }"
        assert "truncated" not in result
