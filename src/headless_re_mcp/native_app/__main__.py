"""python -m headless_re_mcp.native_app  -> native Win32/Tk launcher."""

from __future__ import annotations

import argparse
import json
import sys


def _gui_dependency_envelope(missing_module: str | None) -> dict[str, object]:
    """Actionable envelope for launching the GUI without the ``native`` extra.

    The native GUI lives behind the optional ``native`` extra (PySide6). A base
    install launching it is an expected user condition, not an internal error --
    letting the ModuleNotFoundError reach run_cli_safely mints an incident id for
    a predictable missing dependency and buries the one useful sentence: what to
    install. This mirrors serve-web's ``backend_unavailable`` shape.
    """
    return {
        "ok": False,
        "data": None,
        "error": {
            "code": "backend_unavailable",
            "message": (
                "The native GUI needs the optional native desktop dependencies "
                f"(missing module: {missing_module}). Install them with: "
                'pip install "headless-re-mcp[native]"'
            ),
            "details": {"missing_module": missing_module},
            "retryable": False,
        },
        "meta": None,
    }


def _main(argv: list[str] | None = None) -> int:
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

    try:
        from headless_re_mcp.native_app.gui import run_native_gui
    except ModuleNotFoundError as exc:
        print(json.dumps(_gui_dependency_envelope(exc.name), ensure_ascii=False), file=sys.stderr)
        return 2

    return run_native_gui()


def main(argv: list[str] | None = None) -> int:
    from headless_re_mcp.error_boundary import run_cli_safely

    return run_cli_safely(lambda: _main(argv), context="native-app")


if __name__ == "__main__":
    raise SystemExit(main())
