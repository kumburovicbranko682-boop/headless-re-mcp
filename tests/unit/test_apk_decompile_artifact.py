"""A truncated jadx class must be retrievable, not a dead-end path.

apk.decompile returns at most a buffer's worth of source inline with
truncated=true and a bare on-disk path. Every other decompiler on the surface
(static.decompile) spills the full text to an artifact so the cut-off remainder
stays reachable, and artifacts.read's contract promises exactly that ("a
decompilation too large to return inline is registered as an artifact and
answered with artifact_id"). jadx alone did not, so the rest of a large class
was lost. When truncated, the service now registers the file jadx wrote and
returns artifact_id so artifacts.read can page the whole source.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _TruncatingJadx:
    """Writes the full class to disk but returns a truncated inline source."""

    def __init__(self, full_source: bytes, *, truncated: bool) -> None:
        self._full = full_source
        self._truncated = truncated

    def decompile(
        self,
        binary: Path,
        out_dir: Path,
        class_name: str,
        *,
        timeout: float = 300.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        sources = out_dir / "sources" / "com" / "example"
        sources.mkdir(parents=True, exist_ok=True)
        java = sources / "Main.java"
        java.write_bytes(self._full)
        inline = self._full.decode("utf-8", errors="replace")
        if self._truncated:
            # Stand in for the backend cutting the source at its byte cap.
            inline = inline[:16]
        return {
            "class_name": class_name,
            "path": str(java),
            "source": inline,
            "truncated": self._truncated,
        }


def _service(
    tmp_path: Path, monkeypatch: Any, jadx: object
) -> tuple[AnalysisService, str]:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient",
        lambda *args, **kwargs: jadx,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


def test_truncated_decompile_registers_an_artifact_with_the_full_source(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """truncated=true must carry an artifact_id whose file is the whole class."""
    full = ("class Main {\n" + "  // filler\n" * 5000 + "}\n").encode("utf-8")
    service, session_id = _service(tmp_path, monkeypatch, _TruncatingJadx(full, truncated=True))
    try:
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data["truncated"] is True
        # The inline source is the cut-off preview, not the whole class.
        assert len(data["source"]) < len(full)
        artifact_id = data.get("artifact_id")
        assert isinstance(artifact_id, str) and artifact_id
        assert data.get("hint") == "full_source_in_artifact"

        # The artifact holds the entire class, so the remainder is not lost.
        read = service.artifacts_read(artifact_id, offset=0, limit=len(full) + 10)
        assert read.ok, read.error
        assert read.data is not None
        assert read.data["size"] == len(full)
        assert bytes.fromhex(read.data["data"]) == full
    finally:
        service.close_all()


def test_untruncated_decompile_registers_no_artifact(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A class that fits inline needs no artifact -- the flag stays absent."""
    full = b"class Main {}\n"
    service, session_id = _service(tmp_path, monkeypatch, _TruncatingJadx(full, truncated=False))
    try:
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data.get("truncated") in (False, None)
        assert "artifact_id" not in data
        assert "hint" not in data
    finally:
        service.close_all()


def test_decompile_docstring_promises_the_artifact() -> None:
    """The description must name artifact_id so a caller knows to page the rest."""
    doc = _tool_docstring("apk.decompile")
    assert "artifact_id" in doc
    assert "artifacts.read" in doc
