"""apk.manifest spills a cut manifest to a registered artifact."""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _ManifestSpiller:
    """Stands in for androguard: returns a cut manifest with the full spill."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def manifest(self, binary: Path, *, spill_dir: Path | None = None) -> dict[str, Any]:
        del binary
        result: dict[str, Any] = {
            "package": "com.example.app",
            "manifest_xml": "<manifest/>",
            "truncated": True,
        }
        if spill_dir is not None:
            spill_dir.mkdir(parents=True, exist_ok=True)
            out = spill_dir / "manifest-deadbeef.xml"
            out.write_text("<manifest>" + ("<x/>" * 100) + "</manifest>", encoding="utf-8")
            result["manifest_path"] = str(out)
        return result


def test_apk_manifest_registers_the_spilled_manifest(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A cut manifest is written under artifact_root/apk/<id> and registered.

    The spill path alone is a dead end -- artifacts.read only opens registered
    files and retention only reclaims what the repository knows about -- so the
    reply carries artifact_id, and the file lives in the session's owned apk
    subtree.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.ApkClient",
        lambda *args, **kwargs: _ManifestSpiller(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.apk_manifest(session_id)
        assert result.ok is True, result.error
        assert result.data is not None
        data = result.data
        assert data["truncated"] is True
        assert "manifest_path" in data
        assert "artifact_id" in data
        spilled = Path(data["manifest_path"])
        owned = settings.artifact_root.expanduser().resolve() / "apk" / session_id
        assert spilled.parent == owned
        assert spilled.is_file()
    finally:
        service.close_all()
