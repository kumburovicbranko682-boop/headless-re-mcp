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


def _keep_routine_logs_off_the_pipe(logger_name: str = "") -> None:
    """Send routine logs to a file, because stderr is a pipe nobody may drain.

    The SDK logs every request at INFO, and on stdio that lands on a pipe the
    client owns. A client that does not read it fills the buffer and the server
    then blocks inside write() and answers nothing further -- silently, and for
    good. Measured against a client that never read it: the server stopped
    answering at the 25th tool call, which an unattended session reaches in its
    first minute.

    Warnings and errors still go to stderr, since that is where a client
    surfaces them and they are rare enough not to accumulate. Everything below
    goes to the rotating log beside the incident and telemetry ones.
    """
    import logging

    from headless_re_mcp.logging_setup import (
        UtcFormatter,
        attach_rotating_handler,
        resolve_log_dir,
    )

    attach_rotating_handler(
        logger_name,
        (resolve_log_dir(None) / "mcp-stdio.log").resolve(),
        formatter=UtcFormatter("%(asctime)sZ %(levelname)s %(name)s %(message)s"),
    )
    loud_enough_to_interrupt = logging.StreamHandler()
    loud_enough_to_interrupt.setLevel(logging.WARNING)
    logging.getLogger(logger_name).addHandler(loud_enough_to_interrupt)


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

    supervise = subcommands.add_parser(
        "supervise",
        help="Run a server under a restarting supervisor (unattended operation)",
    )
    supervise.add_argument("--target", choices=("serve-web", "serve"), default="serve-web")
    supervise.add_argument("--host", default=None, help="Must be a loopback address")
    supervise.add_argument("--port", type=int, default=None)
    supervise.add_argument(
        "--check-interval",
        type=float,
        default=10.0,
        help="Seconds between liveness and readiness checks",
    )
    supervise.add_argument(
        "--grace-period",
        type=float,
        default=30.0,
        help="Seconds before the first readiness verdict, so startup is not a restart",
    )
    supervise.add_argument(
        "--max-restarts",
        type=int,
        default=None,
        help="Stop after this many restarts; default is unlimited until a crash loop",
    )
    supervise.add_argument(
        "--no-readiness",
        action="store_true",
        help="Restart only on exit, never on a failed /readyz probe",
    )

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


def _run_supervisor(settings: Settings, args: argparse.Namespace) -> int:
    """Keep a server process alive, restarting it on exit or lost readiness."""
    from headless_re_mcp.supervisor import Supervisor, build_child_argv

    host = args.host or settings.http_host
    port = args.port if args.port is not None else settings.http_port
    # Readiness only exists on the web target; stdio has no HTTP surface, so
    # supervising it means restarting on exit alone.
    ready_url = (
        None
        if args.no_readiness or args.target != "serve-web"
        else f"http://{host}:{port}/readyz"
    )
    supervisor = Supervisor(
        build_child_argv(
            args.target,
            host=args.host,
            port=args.port,
            config=str(args.config) if args.config else None,
        ),
        ready_url=ready_url,
        check_interval_s=max(1.0, float(args.check_interval)),
        grace_period_s=max(0.0, float(args.grace_period)),
        max_restarts=args.max_restarts,
    )
    report = supervisor.run_forever()
    clean = report.stopped_reason == "child_exited_cleanly"
    print(json.dumps({"ok": clean, **report.as_json()}, ensure_ascii=False))
    return 0 if clean else 1


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

        _keep_routine_logs_off_the_pipe()
        run_stdio(AnalysisService(settings))
        return 0

    if args.command == "serve-web":
        from headless_re_mcp.web.app import run_web

        return run_web(settings, host=args.host, port=args.port)

    if args.command == "supervise":
        return _run_supervisor(settings, args)

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
