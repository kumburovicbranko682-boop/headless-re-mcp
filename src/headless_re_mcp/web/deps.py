"""Snapshot of external dependency presence for web console / onboarding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings, repo_root

JsonObject = dict[str, Any]


def _entry(
    *,
    id: str,
    title: str,
    title_zh: str,
    path: Path | None,
    packable: bool,
    required_for_core: bool,
    env: str,
    note_zh: str,
    note_en: str,
) -> JsonObject:
    present = bool(path and Path(path).is_file()) if path is not None else False
    # Directory roots (IDA / Ghidra) — present if path is a directory.
    if path is not None and not present:
        present = Path(path).exists()
    return {
        "id": id,
        "title": title,
        "title_zh": title_zh,
        "path": str(path) if path is not None else None,
        "present": present,
        "packable": packable,
        "never_bundle": not packable and id.startswith("ida"),
        "required_for_core": required_for_core,
        "env": env,
        "note_zh": note_zh,
        "note_en": note_en,
    }


def build_deps_snapshot(settings: Settings) -> JsonObject:
    """Read-only inventory: packable dbg vs never-bundle IDA vs optional CLIs."""
    root = repo_root()
    external = root / "external"
    items = [
        _entry(
            id="x64dbg_headless_x64",
            title="x64dbg headless (x64)",
            title_zh="x64dbg headless（x64）",
            path=settings.x64dbg_headless_x64,
            packable=True,
            required_for_core=True,
            env="HEADLESS_RE_X64DBG_HEADLESS_X64",
            note_zh="可放入 external/x64dbg-x64/ 并随包分发（整棵 Release）。",
            note_en="May ship under external/x64dbg-x64/ (full Release tree).",
        ),
        _entry(
            id="x64dbg_headless_x86",
            title="x64dbg headless (x86)",
            title_zh="x64dbg headless（x86）",
            path=settings.x64dbg_headless_x86,
            packable=True,
            required_for_core=True,
            env="HEADLESS_RE_X64DBG_HEADLESS_X86",
            note_zh="可放入 external/x64dbg-x86/ 并随包分发（整棵 Release）。",
            note_en="May ship under external/x64dbg-x86/ (full Release tree).",
        ),
        _entry(
            id="ida_home",
            title="IDA Pro / idalib",
            title_zh="IDA Pro / idalib",
            path=settings.ida_home,
            packable=False,
            required_for_core=True,
            env="HEADLESS_RE_IDA_HOME",
            note_zh="禁止打包。用户自备已授权安装，勿拷入 external/。",
            note_en="Never bundle. Point to a licensed local install only.",
        ),
        _entry(
            id="diec",
            title="Detect It Easy (diec)",
            title_zh="Detect It Easy（diec）",
            path=settings.diec,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_DIEC",
            note_zh="可选；默认不随包。可放 external/optional/ 仅本机用。",
            note_en="Optional; not in default package.",
        ),
        _entry(
            id="exeinfope",
            title="Exeinfo PE",
            title_zh="Exeinfo PE",
            path=settings.exeinfope,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_EXEINFOPE",
            note_zh="可选第二意见；Freeware，禁止进发布包。",
            note_en="Optional second opinion; do not ship in releases.",
        ),
        _entry(
            id="upx",
            title="UPX",
            title_zh="UPX",
            path=settings.upx,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_UPX",
            note_zh="可选官方 CLI；默认不捆绑。",
            note_en="Optional official CLI; not bundled by default.",
        ),
        _entry(
            id="de4dot",
            title="de4dotEx",
            title_zh="de4dotEx",
            path=settings.de4dot,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_DE4DOT",
            note_zh="可选 .NET 去混淆；默认不捆绑。",
            note_en="Optional .NET deobfuscator; not bundled by default.",
        ),
        _entry(
            id="vmp_dumper",
            title="VMPDump",
            title_zh="VMPDump",
            path=settings.vmp_dumper,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_VMP_DUMPER",
            note_zh="可选；用户自备 GPL 构建，不拷工具包闭源壳。",
            note_en="Optional user-provided GPL build; no toolkit binaries.",
        ),
        _entry(
            id="scylla",
            title="Scylla",
            title_zh="Scylla",
            path=settings.scylla,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_SCYLLA",
            note_zh="可选 IAT 修复 CLI；默认不捆绑。",
            note_en="Optional IAT repair CLI; not bundled by default.",
        ),
        _entry(
            id="ghidra_home",
            title="Ghidra",
            title_zh="Ghidra",
            path=settings.ghidra_home,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_GHIDRA_HOME",
            note_zh="可选静态后端；本机安装路径。",
            note_en="Optional static backend; local install path.",
        ),
        _entry(
            id="cdb",
            title="WinDbg cdb",
            title_zh="WinDbg cdb",
            path=settings.cdb,
            packable=False,
            required_for_core=False,
            env="HEADLESS_RE_CDB",
            note_zh="可选；来自 Windows SDK / WinDbg。",
            note_en="Optional; from Windows SDK / WinDbg.",
        ),
    ]
    packable = [i for i in items if i["packable"]]
    never = [i for i in items if i.get("never_bundle")]
    optional = [i for i in items if not i["required_for_core"]]
    missing_core = [i for i in items if i["required_for_core"] and not i["present"]]
    return {
        "ok": True,
        "external_root": str(external),
        "external_readme": str(external / "README.md"),
        "claims_universal_unpack": False,
        "policy": {
            "packable": ["x64dbg headless x86/x64 Release trees under external/"],
            "never_bundle": ["IDA", "idalib", "Hex-Rays", "licenses"],
            "optional_not_default": [
                "diec",
                "exeinfope",
                "upx",
                "de4dot",
                "vmp_dumper",
                "scylla",
                "ghidra",
                "cdb",
            ],
        },
        "counts": {
            "total": len(items),
            "present": sum(1 for i in items if i["present"]),
            "missing_core": len(missing_core),
            "packable": len(packable),
            "optional": len(optional),
        },
        "items": items,
        "missing_core": missing_core,
        "never_bundle": never,
        "sync_hint": "pwsh -File scripts/sync_external_x64dbg.ps1",
    }
