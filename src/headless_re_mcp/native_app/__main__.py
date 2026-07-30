"""python -m headless_re_mcp.native_app  -> native Win32/Tk launcher."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Headless RE-MCP native launcher (Tk dialogs, no WebView)"
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="run terminal first-setup wizard instead of GUI",
    )
    parser.add_argument("--skip-pip", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--no-activate-ida", action="store_true")
    args = parser.parse_args(argv)

    if args.cli:
        from headless_re_mcp.native_app.bootstrap import run_cli_setup

        return run_cli_setup(
            skip_pip=args.skip_pip,
            non_interactive=args.non_interactive,
            activate_ida=not args.no_activate_ida,
        )

    from headless_re_mcp.native_app.gui import run_native_gui

    return run_native_gui()


if __name__ == "__main__":
    raise SystemExit(main())
