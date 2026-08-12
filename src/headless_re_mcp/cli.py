from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

from headless_re_mcp.backends.x64dbg.gate import run_command_loop_gate
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.doctor import format_report, run_doctor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headless-re-mcp",
        description="Unified headless reverse-engineering MCP",
    )
    parser.add_argument("--config", type=Path, help="Path to a JSON configuration file")
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor = subcommands.add_parser("doctor", help="Probe required and optional backends")
    doctor.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    doctor.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero code unless all required Wave 0 components are ready",
    )
    xdbg_gate = subcommands.add_parser(
        "gate-xdbg",
        help="Run the official x64dbg headless command-loop and zero-window gate",
    )
    xdbg_gate.add_argument(
        "--architecture",
        choices=("x86", "x64", "all"),
        default="all",
    )
    xdbg_gate.add_argument("--timeout", type=float, default=60.0)
    subcommands.add_parser("serve", help="Run the unified MCP server over stdio")

    serve_web = subcommands.add_parser(
        "serve-web",
        help="Run the local loopback web console (requires [web] extra)",
    )
    serve_web.add_argument("--host", default=None, help="Must be a loopback address")
    serve_web.add_argument("--port", type=int, default=None)

    config_cmd = subcommands.add_parser("config", help="Configuration helpers")
    config_subs = config_cmd.add_subparsers(dest="config_command", required=True)
    generate = config_subs.add_parser(
        "generate",
        help="Generate generic stdio MCP server JSON (no secrets)",
    )
    generate.add_argument("--python", type=Path, help="Python executable path")
    generate.add_argument(
        "--config-path",
        type=Path,
        help="Config JSON path to reference (not embedded secrets)",
    )
    generate.add_argument(
        "--skip-doctor",
        action="store_true",
        help="Do not require doctor readiness (still prints doctor when available)",
    )
    generate.add_argument(
        "--no-examples",
        action="store_true",
        help="Omit Cursor/VS Code/Claude Desktop example wrappers",
    )
    generate.add_argument(
        "--output",
        type=Path,
        help="Write JSON to this path instead of stdout",
    )
    return parser


def _run_xdbg_gates(
    settings: Settings,
    architectures: Sequence[Architecture],
    *,
    timeout: float,
) -> int:
    paths = {
        Architecture.X86: settings.x64dbg_headless_x86,
        Architecture.X64: settings.x64dbg_headless_x64,
    }
    results: list[dict[str, object]] = []
    overall = True
    for architecture in architectures:
        executable = paths[architecture]
        if executable is None:
            results.append(
                {
                    "ok": False,
                    "architecture": architecture.value,
                    "error": "headless executable is not configured",
                }
            )
            overall = False
            continue
        try:
            result = run_command_loop_gate(executable, architecture, timeout=timeout)
            results.append(result.to_dict())
            overall = overall and result.ok
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            results.append(
                {
                    "ok": False,
                    "architecture": architecture.value,
                    "executable": str(executable),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            overall = False
    print(json.dumps({"ok": overall, "results": results}, indent=2, ensure_ascii=False))
    return 0 if overall else 1


def _main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.load(args.config)

    if args.command == "doctor":
        report = run_doctor(settings)
        print(report.to_json() if args.json else format_report(report))
        return 1 if args.strict and not report.ready else 0

    if args.command == "gate-xdbg":
        architectures = (
            (Architecture.X86, Architecture.X64)
            if args.architecture == "all"
            else (Architecture(args.architecture),)
        )
        return _run_xdbg_gates(settings, architectures, timeout=args.timeout)

    if args.command == "serve":
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.mcp.server import run_stdio

        run_stdio(AnalysisService(settings))
        return 0

    if args.command == "serve-web":
        from headless_re_mcp.web.app import run_web

        return run_web(settings, host=args.host, port=args.port)

    if args.command == "config":
        if args.config_command == "generate":
            from headless_re_mcp.config_generate import generate_config_bundle

            bundle = generate_config_bundle(
                settings,
                python_path=args.python,
                config_path=args.config_path or args.config,
                run_doctor_check=not args.skip_doctor,
                include_examples=not args.no_examples,
            )
            text = json.dumps(bundle, indent=2, ensure_ascii=False) + "\n"
            if args.output is not None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(text, encoding="utf-8")
            else:
                print(text, end="")
            return 0 if bundle.get("ok") else 1
        raise AssertionError(f"unhandled config command: {args.config_command}")

    raise AssertionError(f"unhandled command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    from headless_re_mcp.error_boundary import run_cli_safely

    return run_cli_safely(lambda: _main(argv), context="cli")
