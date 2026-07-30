"""首次启动：CLI 问答配置（GUI 请用 python -m headless_re_mcp.native_app）。"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _ensure_src() -> Path:
    root = Path(__file__).resolve().parent
    src = root / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))
    os.chdir(root)
    return root


def main(argv: list[str] | None = None) -> int:
    _ensure_src()
    parser = argparse.ArgumentParser(description="Headless RE-MCP first setup")
    parser.add_argument("--gui", action="store_true", help="open native Tk launcher")
    parser.add_argument("--skip-pip", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--no-activate-ida", action="store_true")
    args = parser.parse_args(argv)

    if args.gui:
        from headless_re_mcp.native_app.gui import run_native_gui

        return run_native_gui()

    from headless_re_mcp.native_app.bootstrap import run_cli_setup

    return run_cli_setup(
        skip_pip=args.skip_pip,
        non_interactive=args.non_interactive,
        activate_ida=not args.no_activate_ida,
    )


if __name__ == "__main__":
    raise SystemExit(main())
