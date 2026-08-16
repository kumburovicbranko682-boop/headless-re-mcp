from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from headless_re_mcp.error_boundary import install_global_exception_hooks, record_exception

# A long decompilation used to be sliced at 1000 characters and look complete.
# Measured: a 1500-character preview came back as 1000 with no truncated.
_PREVIEW_LIMIT = 1000


def _decompiler_preview(cfunc: object | None) -> dict[str, Any]:
    if cfunc is None:
        return {"available": False, "preview": "", "truncated": False, "bytes": 0}
    text = str(cfunc)
    return {
        "available": True,
        "preview": text[:_PREVIEW_LIMIT],
        "truncated": len(text) > _PREVIEW_LIMIT,
        "bytes": len(text),
    }


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def run(binary: Path, decompile: bool) -> int:
    install_global_exception_hooks("ida-gate-worker")
    result: dict[str, Any] = {
        "ok": False,
        "binary": str(binary),
        "pid": os.getpid(),
    }
    opened = False
    try:
        import idapro

        idapro.enable_console_messages(False)
        open_result = idapro.open_database(str(binary), run_auto_analysis=True)
        if open_result:
            raise RuntimeError(f"idapro.open_database failed with code {open_result}")
        opened = True

        import ida_auto
        import ida_idaapi
        import ida_kernwin
        import ida_nalt
        import idautils

        ida_auto.auto_wait()
        functions = list(idautils.Functions())
        strings = list(idautils.Strings())
        entry = int(ida_nalt.get_imagebase())
        if functions:
            entry = int(functions[0])

        result.update(
            {
                "ok": True,
                "kernel_version": ida_kernwin.get_kernel_version(),
                "image_base": int(ida_nalt.get_imagebase()),
                "function_count": len(functions),
                "string_count": len(strings),
                "entry_function": entry,
                "badaddr": int(ida_idaapi.BADADDR),
            }
        )

        if decompile and functions:
            try:
                import ida_hexrays

                if not ida_hexrays.init_hexrays_plugin():
                    result["decompiler"] = {"available": False, "error": "init failed"}
                else:
                    cfunc = ida_hexrays.decompile(entry)
                    result["decompiler"] = _decompiler_preview(cfunc)
            except Exception as exc:
                result["decompiler"] = {"available": False, "error": str(exc)}

        _emit(result)
        return 0
    except BaseException as exc:
        incident = record_exception(exc, context="ida-gate-worker:fatal")
        result.update(
            {
                "error": (
                    f"{type(exc).__name__}: {incident['message']} "
                    f"(incident {incident['incident_id']})"
                ),
                "incident": incident,
            }
        )
        _emit(result)
        return 1
    finally:
        if opened:
            try:
                import idapro

                idapro.close_database(False)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated IDA idalib headless gate worker")
    parser.add_argument("binary", type=Path)
    parser.add_argument("--no-decompile", action="store_true")
    args = parser.parse_args()
    return run(args.binary.resolve(strict=True), not args.no_decompile)


if __name__ == "__main__":
    raise SystemExit(main())
